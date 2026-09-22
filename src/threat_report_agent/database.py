from __future__ import annotations

from collections.abc import Generator
from os import getenv

from sqlalchemy import Engine, create_engine, event, inspect, insert, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Database:
    _SCHEMA_LOCK_KEY = 0x545241

    def __init__(self, url: str) -> None:
        options: dict[str, object] = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            # Local/static development runs the API and analysis callbacks in
            # separate threads.  A bounded busy timeout avoids surfacing a
            # transient writer lock as an HTTP 500, while WAL permits status
            # readers to continue during the append-heavy analysis run.
            options["connect_args"] = {"check_same_thread": False, "timeout": 30.0}
            if url in {"sqlite://", "sqlite:///:memory:"}:
                options["poolclass"] = StaticPool
        self.engine: Engine = create_engine(url, **options)
        if url.startswith("sqlite"):
            file_database = url not in {"sqlite://", "sqlite:///:memory:"}

            def configure_sqlite_connection(dbapi_connection: object, _: object) -> None:
                cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=30000")
                if file_database:
                    cursor.execute("PRAGMA journal_mode=WAL")
                cursor.close()

            event.listen(self.engine, "connect", configure_sqlite_connection)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)

    @staticmethod
    def _enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def create_schema(self) -> None:
        if self.engine.dialect.name != "postgresql":
            self._create_schema_unlocked()
            return

        with self.engine.connect() as lock_connection:
            lock_connection.execute(
                text("SELECT pg_advisory_lock(:lock_key)"),
                {"lock_key": self._SCHEMA_LOCK_KEY},
            )
            try:
                self._create_schema_unlocked()
            finally:
                lock_connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_key)"),
                    {"lock_key": self._SCHEMA_LOCK_KEY},
                )

    def _create_schema_unlocked(self) -> None:
        from threat_report_agent.models import Base

        Base.metadata.create_all(self.engine)
        columns = {item["name"] for item in inspect(self.engine).get_columns("analysis_tasks")}
        if "strategy_snapshot" not in columns:
            statement = (
                "ALTER TABLE analysis_tasks ADD COLUMN strategy_snapshot JSON NOT NULL DEFAULT '{}'"
            )
            with self.engine.begin() as connection:
                connection.execute(text(statement))
        if "submission_key" not in columns:
            with self.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE analysis_tasks ADD COLUMN submission_key VARCHAR(200)")
                )
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_task_case_submission_key "
                    "ON analysis_tasks (case_id, submission_key)"
                )
            )
        self._migrate_tool_run_columns()
        self._migrate_analysis_task_columns()
        self._migrate_artifact_columns()
        self._migrate_content_blob_columns()
        self._migrate_claim_columns()
        self._migrate_case_columns()
        self._migrate_model_call_columns()
        self._migrate_model_configuration_columns()
        self._migrate_investigation_action_columns()
        self._migrate_audit_columns()
        self._migrate_audit_seal_columns()
        # Existing PostgreSQL installations may contain a large legacy
        # Evidence ledger.  Rebuilding one page on every API/worker startup
        # creates repeated full-table scans and keeps the schema advisory lock
        # for the duration of the backfill.  New Evidence is indexed by the
        # Session hook; legacy repair remains an explicit operator action.
        if self.engine.dialect.name != "postgresql" or getenv(
            "THREAT_EVIDENCE_INDEX_BACKFILL_ON_STARTUP", "false"
        ).strip().lower() in {"1", "true", "yes"}:
            self._migrate_evidence_search_keys()
        self._migrate_interaction_session_links()
        self._migrate_threat_analysis_contexts()
        self._migrate_analysis_failures()
        self._migrate_mechanism_effectiveness_traces()
        self._install_relation_support_guard()
        self._install_audit_immutability_guards()
        self._install_model_config_audit_guard()
        self._install_evidence_delivery_trace_guard()
        self._install_analysis_turn_result_guard()
        self._install_mechanism_effectiveness_trace_guard()
        self._install_blind_run_snapshot_guard()

    def _migrate_evidence_search_keys(self) -> None:
        '''Backfill selector keys in short, restartable transactions.

        Large installations can contain hundreds of thousands of immutable
        Evidence rows.  Holding one transaction for the entire backfill blocks
        every API/Worker startup behind the schema advisory lock, so process a
        bounded keyset page and commit it before fetching the next page.
        '''
        from threat_report_agent.static.evidence_index import INDEXED_EVIDENCE_KINDS, evidence_search_keys
        from threat_report_agent.models import Evidence, EvidenceSearchKey, new_id

        page_size = 256
        # Process only currently missing rows.  This makes each startup's
        # migration bounded even when the ledger contains millions of rows;
        # the advisory schema lock serializes concurrent workers and the next
        # startup continues with the next missing page.
        with self.session_factory.begin() as session:
            rows = list(
                session.scalars(
                    select(Evidence)
                    .outerjoin(EvidenceSearchKey, EvidenceSearchKey.evidence_id == Evidence.id)
                    .where(EvidenceSearchKey.id.is_(None))
                    .where(Evidence.kind.in_(tuple(sorted(INDEXED_EVIDENCE_KINDS))))
                    .order_by(Evidence.id)
                    .limit(page_size)
                )
            )
            if not rows:
                return
            row_ids = [item.id for item in rows]
            existing = {
                (str(row.evidence_id), str(row.selector))
                for row in session.execute(
                    select(EvidenceSearchKey.evidence_id, EvidenceSearchKey.selector).where(
                        EvidenceSearchKey.evidence_id.in_(row_ids)
                    )
                )
            }
            key_rows: list[dict[str, str]] = []
            for item in rows:
                for selector in evidence_search_keys(
                    kind=item.kind, value=item.value, anchor=item.anchor
                ):
                    key = (str(item.id), selector)
                    if key in existing:
                        continue
                    key_rows.append(
                        {
                            "id": new_id(),
                            "task_id": item.task_id,
                            "artifact_id": item.artifact_id,
                            "evidence_id": item.id,
                            "selector": selector,
                            "kind": item.kind,
                        }
                    )
                    existing.add(key)
            # Keep migration writes bounded while avoiding one ORM object per
            # selector.  The outer page is intentionally small so each
            # transaction remains restartable on a large immutable ledger.
            for offset in range(0, len(key_rows), 4096):
                session.execute(insert(EvidenceSearchKey), key_rows[offset : offset + 4096])

    def repair_evidence_search_keys(self) -> dict[str, str]:
        """Repair the PostgreSQL derived Evidence selector index.

        ``evidence_search_keys`` is rebuildable state derived from immutable
        Evidence rows.  PostgreSQL can report an LZ4/index corruption while
        the source ledger remains valid; exposing repair as a small database
        operation lets the service recover without dropping evidence or data
        volumes.  SQLite has no equivalent index-rebuild requirement here and
        therefore returns an explicit skipped result.
        """
        table = "evidence_search_keys"
        if self.engine.dialect.name != "postgresql":
            return {"status": "SKIPPED", "table": table}
        with self.engine.begin() as connection:
            connection.execute(text(f"REINDEX TABLE {table}"))
        return {"status": "REPAIRED", "table": table}

    def _migrate_interaction_session_links(self) -> None:
        """Create the DSH↔backend mapping table on existing installations."""
        from threat_report_agent.models import InteractionSessionLink

        InteractionSessionLink.__table__.create(self.engine, checkfirst=True)

    def _migrate_threat_analysis_contexts(self) -> None:
        """Create the server-authoritative DSH session context projection."""
        from threat_report_agent.models import ThreatAnalysisContextRecord

        ThreatAnalysisContextRecord.__table__.create(self.engine, checkfirst=True)
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("threat_analysis_contexts")}
            if "context_revision" not in existing:
                connection.execute(
                    text("ALTER TABLE threat_analysis_contexts ADD COLUMN context_revision INTEGER NOT NULL DEFAULT 1")
                )
        if self.engine.dialect.name == "postgresql":
            with self.engine.begin() as connection:
                self._drop_not_null_if_needed(connection, "artifacts", "task_id")
                self._drop_not_null_if_needed(connection, "tool_runs", "task_id")

    def _migrate_analysis_failures(self) -> None:
        """Create the durable sanitized failure contract on existing installs."""
        from threat_report_agent.models import AnalysisFailureRecord

        AnalysisFailureRecord.__table__.create(self.engine, checkfirst=True)
        self._backfill_analysis_failures()

    def _migrate_mechanism_effectiveness_traces(self) -> None:
        """Create the append-only mechanism effectiveness trace ledger."""
        from threat_report_agent.models import MechanismEffectivenessTraceRecord

        MechanismEffectivenessTraceRecord.__table__.create(self.engine, checkfirst=True)

    def _install_mechanism_effectiveness_trace_guard(self) -> None:
        """Prevent historical mechanism traces from being rewritten."""
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS mechanism_effectiveness_traces_no_update "
                        "BEFORE UPDATE ON mechanism_effectiveness_traces BEGIN SELECT RAISE(ABORT, "
                        "'mechanism effectiveness traces are append-only'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS mechanism_effectiveness_traces_no_delete "
                        "BEFORE DELETE ON mechanism_effectiveness_traces BEGIN SELECT RAISE(ABORT, "
                        "'mechanism effectiveness traces are append-only'); END"
                    )
                )
            elif self.engine.dialect.name == "postgresql":
                if not self._postgres_trigger_exists(
                    connection,
                    "mechanism_effectiveness_traces",
                    "mechanism_effectiveness_traces_no_mutation",
                ):
                    connection.execute(
                        text(
                            "CREATE TRIGGER mechanism_effectiveness_traces_no_mutation "
                            "BEFORE UPDATE OR DELETE ON mechanism_effectiveness_traces FOR EACH ROW "
                            "EXECUTE FUNCTION prevent_audit_mutation()"
                        )
                    )

    def _backfill_analysis_failures(self) -> None:
        """Backfill failure contracts for legacy failed tasks.

        Early runtime builds persisted only an ``analysis_task.failed`` audit
        event.  Keep those historical attempts diagnosable after upgrade by
        deriving the same sanitized contract used by the live service.  The
        operation is idempotent and never touches Evidence, Claims, or Blob
        data.
        """
        from threat_report_agent.models import AnalysisFailureRecord, AnalysisTask, AuditEvent
        from threat_report_agent.runtime_contracts import classify_failure, retry_decision

        with self.session_factory.begin() as session:
            # Repair an early migration bug that could point a retry lineage
            # back to the same task or record a terminal failure as the last
            # successful stage.  These fields are diagnostic projections and
            # may be corrected without touching immutable analysis data.
            existing_rows = list(session.scalars(select(AnalysisFailureRecord)))
            for row in existing_rows:
                if row.retry_of_task_id and str(row.retry_of_task_id) == str(row.task_id):
                    row.retry_of_task_id = None
                if str(row.last_successful_stage or "").endswith(".failed"):
                    row.last_successful_stage = "UNKNOWN"
            failed_tasks = list(
                session.scalars(
                    select(AnalysisTask).where(AnalysisTask.lifecycle == "FAILED")
                )
            )
            for task in failed_tasks:
                if session.scalar(
                    select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
                ) is not None:
                    continue
                failed_event = session.scalar(
                    select(AuditEvent)
                    .where(
                        AuditEvent.task_id == task.id,
                        AuditEvent.event_type == "analysis_task.failed",
                    )
                    .order_by(AuditEvent.chain_sequence.desc(), AuditEvent.id.desc())
                )
                if failed_event is None:
                    continue
                payload = failed_event.payload if isinstance(failed_event.payload, dict) else {}
                message = str(payload.get("message") or payload.get("error_type") or "analysis failed")
                error_type = str(payload.get("error_type") or "legacy_failure")
                previous_event = session.scalar(
                    select(AuditEvent)
                    .where(
                        AuditEvent.task_id == task.id,
                        AuditEvent.chain_sequence < failed_event.chain_sequence,
                        AuditEvent.event_type.notlike("%.failed"),
                    )
                    .order_by(AuditEvent.chain_sequence.desc(), AuditEvent.id.desc())
                )
                contract = classify_failure(
                    RuntimeError(message),
                    stage=(previous_event.event_type if previous_event else "ANALYSIS"),
                    failed_component=error_type,
                    failed_activity=error_type,
                    last_successful_stage=(previous_event.event_type if previous_event else "UNKNOWN"),
                )
                previous = session.scalar(
                    select(AnalysisFailureRecord)
                    .join(AnalysisTask, AnalysisTask.id == AnalysisFailureRecord.task_id)
                    .where(
                        AnalysisTask.case_id == task.case_id,
                        AnalysisFailureRecord.task_id != task.id,
                    )
                    .order_by(AnalysisFailureRecord.created_at.desc(), AnalysisFailureRecord.id.desc())
                )
                if previous is not None and str(previous.task_id) == str(task.id):
                    previous = None
                previous_fingerprint = previous.failure_fingerprint if previous else None
                decision = retry_decision(
                    retryable=bool(contract["retryable"]),
                    previous_fingerprint=previous_fingerprint,
                    fingerprint=str(contract["failure_fingerprint"]),
                )
                session.add(
                    AnalysisFailureRecord(
                        task_id=task.id,
                        lifecycle="FAILED",
                        analysis_class="FAILED_ANALYSIS",
                        failure_code=str(contract["failure_code"]),
                        failure_stage=str(contract["failure_stage"]),
                        failed_component=str(contract["failed_component"]),
                        failed_activity=str(contract["failed_activity"]),
                        retryable=bool(contract["retryable"]),
                        retry_after_seconds=contract["retry_after_seconds"],
                        failure_fingerprint=str(contract["failure_fingerprint"]),
                        last_successful_stage=str(contract["last_successful_stage"]),
                        last_event_id=failed_event.id,
                        tool_run_id=None,
                        temporal_workflow_id=None,
                        report_available=False,
                        attempt_number=(previous.attempt_number + 1) if previous else 1,
                        retry_of_task_id=previous.task_id if previous else None,
                        retry_suppressed=bool(decision["retry_suppressed"]),
                        detail={
                            "message": message[:500],
                            "legacy_backfill": True,
                            "retry": decision,
                            "previous_failure_fingerprint": previous_fingerprint,
                        },
                    )
                )

    def _install_evidence_delivery_trace_guard(self) -> None:
        """Keep delivery traces append-only in every supported database."""
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS evidence_delivery_traces_no_update "
                        "BEFORE UPDATE ON evidence_delivery_traces BEGIN SELECT RAISE(ABORT, "
                        "'evidence delivery traces are append-only'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS evidence_delivery_traces_no_delete "
                        "BEFORE DELETE ON evidence_delivery_traces BEGIN SELECT RAISE(ABORT, "
                        "'evidence delivery traces are append-only'); END"
                    )
                )
            elif self.engine.dialect.name == "postgresql":
                if not self._postgres_trigger_exists(
                    connection, "evidence_delivery_traces", "evidence_delivery_traces_no_mutation"
                ):
                    connection.execute(
                        text(
                            "CREATE TRIGGER evidence_delivery_traces_no_mutation "
                            "BEFORE UPDATE OR DELETE ON evidence_delivery_traces FOR EACH ROW "
                            "EXECUTE FUNCTION prevent_audit_mutation()"
                        )
                    )

    def _install_analysis_turn_result_guard(self) -> None:
        """Keep post-action Turn results append-only like their parent manifests."""
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS analysis_turn_results_no_update "
                        "BEFORE UPDATE ON analysis_turn_results BEGIN SELECT RAISE(ABORT, "
                        "'analysis turn results are append-only'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS analysis_turn_results_no_delete "
                        "BEFORE DELETE ON analysis_turn_results BEGIN SELECT RAISE(ABORT, "
                        "'analysis turn results are append-only'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS analysis_turns_no_update "
                        "BEFORE UPDATE ON analysis_turns BEGIN SELECT RAISE(ABORT, "
                        "'analysis turns are immutable'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS analysis_turns_no_delete "
                        "BEFORE DELETE ON analysis_turns BEGIN SELECT RAISE(ABORT, "
                        "'analysis turns are immutable'); END"
                    )
                )
            elif self.engine.dialect.name == "postgresql":
                connection.execute(
                    text(
                        "CREATE OR REPLACE FUNCTION prevent_analysis_turn_mutation() "
                        "RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'analysis turn records are append-only'; "
                        "END; $$ LANGUAGE plpgsql"
                    )
                )
                for table in ("analysis_turns", "analysis_turn_results"):
                    if not self._postgres_trigger_exists(connection, table, f"{table}_no_mutation"):
                        connection.execute(
                            text(
                                f"CREATE TRIGGER {table}_no_mutation BEFORE UPDATE OR DELETE ON {table} "
                                "FOR EACH ROW EXECUTE FUNCTION prevent_analysis_turn_mutation()"
                            )
                        )

    def _install_blind_run_snapshot_guard(self) -> None:
        """Allow lifecycle updates while preventing blind manifest substitution."""
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS blind_runs_snapshot_immutable "
                        "BEFORE UPDATE ON blind_runs WHEN NEW.snapshot != OLD.snapshot "
                        "OR NEW.snapshot_sha256 != OLD.snapshot_sha256 BEGIN SELECT RAISE(ABORT, "
                        "'blind run snapshot is immutable'); END"
                    )
                )
            elif self.engine.dialect.name == "postgresql":
                connection.execute(
                    text(
                        "CREATE OR REPLACE FUNCTION prevent_blind_snapshot_mutation() "
                        "RETURNS trigger AS $$ BEGIN IF NEW.snapshot IS DISTINCT FROM OLD.snapshot "
                        "OR NEW.snapshot_sha256 IS DISTINCT FROM OLD.snapshot_sha256 THEN "
                        "RAISE EXCEPTION 'blind run snapshot is immutable'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql"
                    )
                )
                if not self._postgres_trigger_exists(
                    connection, "blind_runs", "blind_runs_snapshot_immutable"
                ):
                    connection.execute(
                        text(
                            "CREATE TRIGGER blind_runs_snapshot_immutable BEFORE UPDATE ON blind_runs "
                            "FOR EACH ROW EXECUTE FUNCTION prevent_blind_snapshot_mutation()"
                        )
                    )

    def _install_model_config_audit_guard(self) -> None:
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS model_configuration_audits_no_update "
                        "BEFORE UPDATE ON model_configuration_audits BEGIN SELECT RAISE(ABORT, "
                        "'model configuration audits are append-only'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS model_configuration_audits_no_delete "
                        "BEFORE DELETE ON model_configuration_audits BEGIN SELECT RAISE(ABORT, "
                        "'model configuration audits are append-only'); END"
                    )
                )
            elif self.engine.dialect.name == "postgresql":
                if not self._postgres_trigger_exists(
                    connection, "model_configuration_audits", "model_configuration_audits_no_mutation"
                ):
                    connection.execute(
                        text(
                            "CREATE TRIGGER model_configuration_audits_no_mutation "
                            "BEFORE UPDATE OR DELETE ON model_configuration_audits FOR EACH ROW "
                            "EXECUTE FUNCTION prevent_audit_mutation()"
                        )
                    )

    def _migrate_audit_seal_columns(self) -> None:
        required = {
            "payload_sha256": "VARCHAR(64)",
            "payload_storage_key": "VARCHAR(512)",
            "seal_window": "VARCHAR(32)",
            "merkle_root": "VARCHAR(64) NOT NULL DEFAULT '" + ("0" * 64) + "'",
        }
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("audit_seals")}
            for name, declaration in required.items():
                if name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE audit_seals ADD COLUMN {name} {declaration}")
                    )

    def _migrate_case_columns(self) -> None:
        required = {
            "retention_frozen_at": "TIMESTAMP",
            "retention_frozen_by": "VARCHAR(160)",
            "retention_freeze_reason": "TEXT",
        }
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("cases")}
            for name, declaration in required.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE cases ADD COLUMN {name} {declaration}"))

    def _migrate_model_call_columns(self) -> None:
        required = {
            "payload_expires_at": "TIMESTAMP",
            "payload_disposed_at": "TIMESTAMP",
            "turn_id": "VARCHAR(200)",
            "phase": "VARCHAR(160)",
            "payload_schema_version": "VARCHAR(32) NOT NULL DEFAULT 'model-payload-v1'",
            "encryption_key_id": "VARCHAR(64) NOT NULL DEFAULT 'local-model-payload-key'",
            "security_classification": "VARCHAR(64) NOT NULL DEFAULT 'RESTRICTED_MODEL_PAYLOAD'",
            "access_policy": "VARCHAR(120) NOT NULL DEFAULT 'auditor_or_system_only'",
        }
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("model_calls")}
            for name, declaration in required.items():
                if name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE model_calls ADD COLUMN {name} {declaration}")
                    )

    def _migrate_model_configuration_columns(self) -> None:
        """Add route protocol and sampling controls to existing installations."""
        required = {
            "timeout_s": "FLOAT NOT NULL DEFAULT 180.0",
            "max_tokens": "INTEGER NOT NULL DEFAULT 2048",
            "primary_stream": "BOOLEAN NOT NULL DEFAULT TRUE",
            "primary_supports_json_mode": "BOOLEAN NOT NULL DEFAULT TRUE",
            "primary_temperature": "FLOAT NOT NULL DEFAULT 0.0",
            "primary_top_p": "FLOAT NOT NULL DEFAULT 1.0",
            "primary_disable_reasoning": "BOOLEAN NOT NULL DEFAULT TRUE",
            "fallback_stream": "BOOLEAN NOT NULL DEFAULT TRUE",
            "fallback_supports_json_mode": "BOOLEAN NOT NULL DEFAULT TRUE",
            "fallback_temperature": "FLOAT NOT NULL DEFAULT 0.0",
            "fallback_top_p": "FLOAT NOT NULL DEFAULT 1.0",
            "fallback_disable_reasoning": "BOOLEAN NOT NULL DEFAULT TRUE",
        }
        with self.engine.begin() as connection:
            existing = {
                item["name"] for item in inspect(connection).get_columns("model_configurations")
            }
            for name, declaration in required.items():
                if name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE model_configurations ADD COLUMN {name} {declaration}")
                    )

    def _migrate_investigation_action_columns(self) -> None:
        """Add immutable action-target provenance to existing installations."""
        required = {
            "target_selector": "JSON NOT NULL DEFAULT '{}'",
            "expected_evidence_kinds": "JSON NOT NULL DEFAULT '[]'",
            "success_condition": "TEXT NOT NULL DEFAULT 'new_targeted_evidence'",
            "failure_interpretation": "VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN'",
            "cost_units": "INTEGER NOT NULL DEFAULT 1",
        }
        with self.engine.begin() as connection:
            existing = {
                item["name"] for item in inspect(connection).get_columns("investigation_actions")
            }
            for name, declaration in required.items():
                if name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE investigation_actions ADD COLUMN {name} {declaration}")
                    )

    def _migrate_claim_columns(self) -> None:
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("claims")}
            if "model_call_id" not in existing:
                connection.execute(text("ALTER TABLE claims ADD COLUMN model_call_id VARCHAR(36)"))

    def _migrate_artifact_columns(self) -> None:
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("artifacts")}
            if "disposed_at" not in existing:
                connection.execute(text("ALTER TABLE artifacts ADD COLUMN disposed_at TIMESTAMP"))
            # Upload-only intake permits an Artifact to exist before a Task.
            # Fresh schemas get the nullable declaration from the ORM; on an
            # existing PostgreSQL installation explicitly relax the legacy
            # NOT NULL constraint during startup migration.
            if self.engine.dialect.name == "postgresql":
                self._drop_not_null_if_needed(connection, "artifacts", "task_id")

    def _migrate_content_blob_columns(self) -> None:
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("content_blobs")}
            if "disposed_at" not in existing:
                connection.execute(
                    text("ALTER TABLE content_blobs ADD COLUMN disposed_at TIMESTAMP")
                )

    def _install_relation_support_guard(self) -> None:
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS relations_require_support "
                        "BEFORE INSERT ON relations WHEN NEW.evidence_id IS NULL "
                        "AND NEW.claim_id IS NULL BEGIN SELECT RAISE(ABORT, "
                        "'relations require evidence or claim support'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS relations_require_type_support "
                        "BEFORE INSERT ON relations WHEN "
                        "(NEW.relation_type IN ('CONTAINS','DROPS','EXTRACTED_FROM') AND NEW.evidence_id IS NULL) "
                        "OR (NEW.relation_type IN ('LOADS','DECRYPTS','EXECUTES','INJECTS') "
                        "AND NEW.claim_id IS NULL) BEGIN SELECT RAISE(ABORT, "
                        "'relation type requires its support nature'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS relations_require_support_update "
                        "BEFORE UPDATE OF evidence_id, claim_id ON relations "
                        "WHEN NEW.evidence_id IS NULL AND NEW.claim_id IS NULL BEGIN SELECT RAISE(ABORT, "
                        "'relations require evidence or claim support'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS relations_require_type_support_update "
                        "BEFORE UPDATE OF relation_type, evidence_id, claim_id ON relations "
                        "WHEN (NEW.relation_type IN ('CONTAINS','DROPS','EXTRACTED_FROM') AND NEW.evidence_id IS NULL) "
                        "OR (NEW.relation_type IN ('LOADS','DECRYPTS','EXECUTES','INJECTS') AND NEW.claim_id IS NULL) "
                        "BEGIN SELECT RAISE(ABORT, 'relation type requires its support nature'); END"
                    )
                )
            elif self.engine.dialect.name == "postgresql":
                constraints = self._postgres_constraint_names(connection, "relations")
                if "ck_relation_has_support" not in constraints:
                    connection.execute(
                        text(
                            "ALTER TABLE relations ADD CONSTRAINT ck_relation_has_support "
                            "CHECK (evidence_id IS NOT NULL OR claim_id IS NOT NULL)"
                        )
                    )
                if "ck_relation_type_support" not in constraints:
                    connection.execute(
                        text(
                            "ALTER TABLE relations ADD CONSTRAINT ck_relation_type_support CHECK ("
                            "(relation_type IN ('CONTAINS','DROPS','EXTRACTED_FROM') AND evidence_id IS NOT NULL) OR "
                            "(relation_type IN ('LOADS','DECRYPTS','EXECUTES','INJECTS') AND claim_id IS NOT NULL))"
                        )
                    )

    def _migrate_tool_run_columns(self) -> None:
        required_columns = {
            "output_sha256": "VARCHAR(64)",
            "output_storage_key": "VARCHAR(512)",
        }
        with self.engine.begin() as connection:
            inspector = inspect(connection)
            existing = {item["name"] for item in inspector.get_columns("tool_runs")}
            for name, declaration in required_columns.items():
                if name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE tool_runs ADD COLUMN {name} {declaration}")
                    )
            if self.engine.dialect.name == "postgresql":
                self._drop_not_null_if_needed(connection, "tool_runs", "artifact_id")
                self._drop_not_null_if_needed(connection, "tool_runs", "started_at")

    @staticmethod
    def _drop_not_null_if_needed(connection: object, table: str, column: str) -> None:
        """Relax a legacy column once, avoiding repeat PostgreSQL table locks."""
        columns = {item["name"]: item for item in inspect(connection).get_columns(table)}
        column_info = columns.get(column)
        if column_info is None or bool(column_info.get("nullable")):
            return
        connection.execute(text(f"ALTER TABLE {table} ALTER COLUMN {column} DROP NOT NULL"))

    @staticmethod
    def _postgres_trigger_exists(connection: object, table: str, trigger: str) -> bool:
        row = connection.execute(
            text(
                "SELECT 1 FROM pg_trigger "
                "WHERE tgname = :trigger "
                "AND tgrelid = CAST(:table AS regclass) "
                "AND NOT tgisinternal LIMIT 1"
            ),
            {"trigger": trigger, "table": table},
        ).first()
        return row is not None

    @staticmethod
    def _postgres_constraint_names(connection: object, table: str) -> set[str]:
        rows = connection.execute(
            text(
                "SELECT conname FROM pg_constraint "
                "WHERE conrelid = CAST(:table AS regclass)"
            ),
            {"table": table},
        )
        return {str(row[0]) for row in rows}

    def _migrate_analysis_task_columns(self) -> None:
        """Add Round 11 result classification and static coverage fields."""
        required = {
            "analysis_class": "VARCHAR(40)",
            "coverage": "JSON NOT NULL DEFAULT '{}'",
        }
        with self.engine.begin() as connection:
            existing = {item["name"] for item in inspect(connection).get_columns("analysis_tasks")}
            for name, declaration in required.items():
                if name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE analysis_tasks ADD COLUMN {name} {declaration}")
                    )

    def _migrate_audit_columns(self) -> None:
        required_columns = {
            "cases": {"trace_id": "VARCHAR(36) NOT NULL DEFAULT ''"},
            "analysis_tasks": {"trace_id": "VARCHAR(36) NOT NULL DEFAULT ''"},
            "audit_events": {
                "chain_version": "VARCHAR(16) NOT NULL DEFAULT '1'",
                "chain_sequence": "INTEGER NOT NULL DEFAULT 0",
                "previous_hash": "VARCHAR(64) NOT NULL DEFAULT '" + ("0" * 64) + "'",
                "event_hash": "VARCHAR(64) NOT NULL DEFAULT ''",
            },
        }
        with self.engine.begin() as connection:
            inspector = inspect(connection)
            for table, columns in required_columns.items():
                existing = {item["name"] for item in inspector.get_columns(table)}
                for name, declaration in columns.items():
                    if name not in existing:
                        connection.execute(
                            text(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
                        )
            # The workbench wait path repeatedly asks for the next event for
            # one task.  A composite index lets the database satisfy both the
            # task filter and sequence ordering without sorting the task's
            # entire audit history on every bounded wait probe.
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_audit_events_task_sequence "
                    "ON audit_events (task_id, chain_sequence)"
                )
            )

    def _install_audit_immutability_guards(self) -> None:
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                for table in ("audit_events", "audit_seals"):
                    connection.execute(
                        text(
                            f"CREATE TRIGGER IF NOT EXISTS {table}_no_update "
                            f"BEFORE UPDATE ON {table} BEGIN "
                            f"SELECT RAISE(ABORT, '{table} is append-only'); END"
                        )
                    )
                    connection.execute(
                        text(
                            f"CREATE TRIGGER IF NOT EXISTS {table}_no_delete "
                            f"BEFORE DELETE ON {table} BEGIN "
                            f"SELECT RAISE(ABORT, '{table} is append-only'); END"
                        )
                    )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS analysis_snapshots_no_update "
                        "BEFORE UPDATE ON analysis_snapshots BEGIN "
                        "SELECT RAISE(ABORT, 'analysis snapshots are immutable'); END"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS analysis_snapshots_no_delete "
                        "BEFORE DELETE ON analysis_snapshots BEGIN "
                        "SELECT RAISE(ABORT, 'analysis snapshots are immutable'); END"
                    )
                )
            elif self.engine.dialect.name == "postgresql":
                connection.execute(
                    text(
                        "CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger "
                        "AS $$ BEGIN RAISE EXCEPTION 'audit records are append-only'; END; $$ LANGUAGE plpgsql"
                    )
                )
                for table in ("audit_events", "audit_seals"):
                    if not self._postgres_trigger_exists(connection, table, f"{table}_no_mutation"):
                        connection.execute(
                            text(
                                f"CREATE TRIGGER {table}_no_mutation BEFORE UPDATE OR DELETE ON {table} "
                                "FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation()"
                            )
                        )
                connection.execute(
                    text(
                        "CREATE OR REPLACE FUNCTION prevent_analysis_snapshot_mutation() "
                        "RETURNS trigger AS $$ BEGIN "
                        "RAISE EXCEPTION 'analysis snapshots are immutable'; "
                        "END; $$ LANGUAGE plpgsql"
                    )
                )
                if not self._postgres_trigger_exists(
                    connection, "analysis_snapshots", "analysis_snapshots_no_mutation"
                ):
                    connection.execute(
                        text(
                            "CREATE TRIGGER analysis_snapshots_no_mutation "
                            "BEFORE UPDATE OR DELETE ON analysis_snapshots "
                            "FOR EACH ROW EXECUTE FUNCTION prevent_analysis_snapshot_mutation()"
                        )
                    )

    def sessions(self) -> Generator[Session, None, None]:
        with self.session_factory() as session:
            yield session
