from __future__ import annotations

from dataclasses import replace
import json
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.contracts import BackgroundContextInput
from threat_report_agent.config import ModelProviderSettings
from threat_report_agent.database import Database
from threat_report_agent.model_gateway import ModelGateway
from threat_report_agent.contracts import DynamicPlanAction
from threat_report_agent.service import AnalysisService
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    AuditSeal,
    CaseRecord,
    ContentBlob,
    Evidence,
    ModelCall,
    ToolRun,
    utcnow,
)


def _model_claim_response(evidence_id: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "claims": [
                                    {
                                        "module": "loader",
                                        "subject": "sample.py",
                                        "action": "references",
                                        "object": "VirtualAlloc",
                                        "mechanism": "static import",
                                        "condition": "static evidence only",
                                        "statement": "The script references a loader-related indicator.",
                                        "evidence_ids": [evidence_id],
                                        "confidence": "LOW",
                                        "status": "CANDIDATE",
                                    }
                                ],
                                "limitations": [],
                            }
                        )
                    }
                }
            ]
        },
    )


def test_model_enrichment_rejects_claim_without_verifier_threshold(test_settings, monkeypatch) -> None:
    settings = replace(test_settings, model_calls_enabled=True)
    service = AnalysisService(
        settings, Database(settings.database_url), LocalContentStore(settings.content_store_path)
    )
    service.database.create_schema()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        untrusted = payload["messages"][1]["content"]
        context = json.loads(
            untrusted.split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        evidence_id = context["allowed_evidence_ids"][0]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "claims": [
                                        {
                                            "module": "loader",
                                            "subject": "sample.py",
                                            "action": "references",
                                            "object": "VirtualAlloc",
                                            "mechanism": "static import",
                                            "condition": "static evidence only",
                                            "statement": "The script references a loader-related indicator.",
                                            "evidence_ids": [evidence_id],
                                            "confidence": "LOW",
                                            "status": "CANDIDATE",
                                        }
                                    ],
                                    "limitations": ["model acceptance test"],
                                }
                            )
                        }
                    }
                ]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("W4 model acceptance")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"import socket\nprint('ok')",
    )

    task = service.task_view(result.task_id)
    assert task["model_calls"]
    assert task["model_calls"][0]["status"] == "SUCCEEDED"
    assert task["model_calls"][0]["agent_run_id"]
    audit_names = [event["event_type"] for event in service.list_audit_events(result.task_id)]
    assert "agent.run.started" in audit_names
    assert "agent.context.checked" in audit_names
    assert "agent.run.completed" in audit_names
    model_claims = [item for item in task["claims"] if item["model_call_id"]]
    assert not model_claims
    report = service.get_report_revision(task["latest_report_revision_id"])
    summary = report["document"]["modules"][0]
    provenance = next(row for row in summary["rows"] if row.get("type") == "model_analysis_provenance")
    assert provenance["successful_calls"] >= 1
    assert provenance["model_claims"] == 0
    loader_rows = next(module for module in report["document"]["modules"] if module["id"] == "loader")["rows"]
    assert not any(row.get("analysis_source") == "model" for row in loader_rows)
    assert "model acceptance test" in task["limitations"]


def test_structured_model_candidate_enters_report_without_becoming_verified(test_settings) -> None:
    settings = replace(test_settings, environment="demo", model_calls_enabled=True)
    service = AnalysisService(
        settings, Database(settings.database_url), LocalContentStore(settings.content_store_path)
    )
    service.database.create_schema()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        raw = payload["messages"][1]["content"]
        context = json.loads(
            raw.split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        allowed = context["allowed_evidence_ids"]
        assert len(allowed) >= 2
        response = {
            "claims": [
                {
                    "module": "execution",
                    "subject": "sample.py",
                    "action": "may_execute",
                    "object": "a process or command",
                    "mechanism": (
                        "Input -> Transformation/Control -> Condition -> Output -> "
                        "Consumer -> Side Effect"
                    ),
                    "condition": "static evidence only",
                    "statement": (
                        "Static evidence links process input to a bounded consumer; "
                        "runtime execution is not observed."
                    ),
                    "evidence_ids": allowed[:2],
                    "confidence": "MEDIUM",
                    "status": "CANDIDATE",
                }
            ],
            "limitations": [],
        }
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(response)}}]},
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("structured model candidate")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"import socket\nimport subprocess\nsubprocess.Popen('whoami')",
    )

    task = service.task_view(result.task_id)
    model_claims = [item for item in task["claims"] if item["model_call_id"]]
    assert model_claims
    assert all(item["status"] == "CANDIDATE" for item in model_claims)
    report = service.get_report_revision(result.report_revision_id)
    # The published revision is the Chinese analyst body (`analyst_report.render_official_markdown`),
    # not the English v3 ledger that `reporting._document_to_v3_markdown` produces, so the section is
    # asserted by the heading the published renderer is contracted to emit. What the test is actually
    # protecting is unchanged: the model's candidate reaches the reader WITHOUT being promoted to a
    # verified finding, together with the mechanism chain and the unverified status that let an analyst
    # judge it. Asserting the v3 heading here only proved which renderer was wired up.
    assert "### 模型合成候选" in report["markdown"]
    assert "Input -> Transformation/Control" in report["markdown"]
    assert "未过验证器" in report["markdown"]


def test_background_context_is_first_class_evidence_but_not_claimable(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    case = service.create_case("W4 background evidence")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"print('sample')",
        background_context_input=BackgroundContextInput(
            content="Incident responder reported a suspicious loader.",
            source="ir-ticket-42",
            confidence="HIGH",
            human_confirmed=True,
        ),
    )
    task = service.task_view(result.task_id)
    background = [item for item in task["evidence"] if item["nature"] == "BACKGROUND_REPORTED"]
    assert len(background) == 1
    assert background[0]["kind"] == "background_context"
    assert background[0]["value"]["source"] == "ir-ticket-42"
    assert all(item["nature"] != "BACKGROUND_REPORTED" for item in task["evidence"] if item["kind"] != "background_context")
    assert not any(item["claim_id"] for item in task["relations"] if item.get("evidence_id") == background[0]["id"])


def test_model_context_keeps_background_visible_but_excludes_it_from_citations(test_settings) -> None:
    settings = replace(test_settings, model_calls_enabled=True)
    service = AnalysisService(
        settings, Database(settings.database_url), LocalContentStore(settings.content_store_path)
    )
    service.database.create_schema()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        user_data = json.loads(
            payload["messages"][1]["content"].split("\n", 1)[1].rsplit("\n", 1)[0]
        )
        manifest = user_data["context_manifest"]
        background_ids = {
            item["evidence_id"]
            for item in manifest
            if item["nature"] == "BACKGROUND_REPORTED"
        }
        assert background_ids
        allowed = set(user_data["allowed_evidence_ids"])
        assert not background_ids & allowed
        evidence_id = next(iter(allowed))
        return _model_claim_response(evidence_id)

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("W4 model background isolation")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"print('sample')",
        background_context_input=BackgroundContextInput(content="reported loader", source="ticket"),
    )
    task = service.task_view(result.task_id)
    # Delivery of a non-background Evidence item is not sufficient to create a
    # Claim: the independent Claim Gate can correctly reject this deliberately
    # weak one-item model draft. Isolation is proven by the successful model
    # call and by the absence of any background-supported Claim.
    assert any(item["status"] == "SUCCEEDED" for item in task["model_calls"])
    background_ids = {
        item["id"] for item in task["evidence"] if item["nature"] == "BACKGROUND_REPORTED"
    }
    assert not any(
        link["evidence_id"] in background_ids for link in task["claim_evidence"]
    )


def test_model_context_selection_is_fair_across_artifacts(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    rows = [
        SimpleNamespace(
            id=f"outer-{index}",
            artifact_id="outer",
            kind="string",
            created_at=utcnow(),
        )
        for index in range(350)
    ] + [
        SimpleNamespace(
            id=f"child-{index}",
            artifact_id="child",
            kind="function",
            created_at=utcnow(),
        )
        for index in range(25)
    ]

    selected = service._select_model_evidence(rows, limit=100)
    assert len(selected) == 100
    assert any(item.artifact_id == "child" for item in selected)
    assert any(item.kind == "function" for item in selected)


def test_investigation_execution_corpus_is_bounded_and_prioritizes_mechanisms(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(id=f"string-{index}", kind="string", created_at=utcnow())
        for index in range(20)
    ] + [
        SimpleNamespace(id=f"call-{index}", kind="function_call", created_at=utcnow())
        for index in range(3)
    ]

    selected = service._select_investigation_execution_rows(rows, limit=5)

    assert len(selected) == 5
    assert [item.kind for item in selected[:3]] == ["function_call"] * 3


def test_investigation_execution_sql_limit_keeps_high_signal_rows(test_settings) -> None:
    """The database LIMIT must not hide function/call evidence behind strings."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    database.create_schema()
    with database.session_factory.begin() as session:
        session.add(CaseRecord(id="case-sql-priority", title="SQL priority"))
        session.flush()
        session.add(
            AnalysisTask(
                id="task-sql-priority",
                case_id="case-sql-priority",
                lifecycle="RUNNING",
            )
        )
        session.flush()
        session.add(
            ContentBlob(
                sha256="a" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/sql-priority",
            )
        )
        session.flush()
        session.add(
            Artifact(
                id="artifact-sql-priority",
                task_id="task-sql-priority",
                content_sha256="a" * 64,
                logical_path="sample.exe",
                detected_type="pe",
            )
        )
        session.flush()
        session.add(
            ToolRun(
                id="run-sql-priority",
                task_id="task-sql-priority",
                artifact_id="artifact-sql-priority",
                tool_name="fixture",
                tool_version="test",
                status="SUCCEEDED",
            )
        )
        session.flush()
        session.add_all(
            [
                Evidence(
                    id=f"string-sql-{index}",
                    task_id="task-sql-priority",
                    artifact_id="artifact-sql-priority",
                    tool_run_id="run-sql-priority",
                    module="static",
                    kind="string",
                    nature="STATIC_OBSERVED",
                    value={"text": f"noise-{index}"},
                    anchor={"type": "string"},
                )
                for index in range(20)
            ]
            + [
                Evidence(
                    id=f"call-sql-{index}",
                    task_id="task-sql-priority",
                    artifact_id="artifact-sql-priority",
                    tool_run_id="run-sql-priority",
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "VirtualAlloc"},
                    anchor={"type": "function_call"},
                )
                for index in range(3)
            ]
        )
        session.flush()
        selected = service._load_investigation_execution_rows(
            session,
            task_id="task-sql-priority",
            artifact_id="artifact-sql-priority",
            action_kinds={"string", "function_call"},
            limit=5,
        )

    assert len(selected) == 5
    assert [item.kind for item in selected[:3]] == ["function_call"] * 3
    assert all(item.task_id == "task-sql-priority" for item in selected)


def test_investigation_execution_sql_limit_keeps_deep_semantic_rows(test_settings) -> None:
    """Late semantic projections must survive a small working-set cap."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    database.create_schema()
    with database.session_factory.begin() as session:
        session.add(CaseRecord(id="case-sql-deep-priority", title="SQL deep priority"))
        session.flush()
        session.add(
            AnalysisTask(
                id="task-sql-deep-priority",
                case_id="case-sql-deep-priority",
                lifecycle="RUNNING",
            )
        )
        session.flush()
        session.add(
            ContentBlob(
                sha256="b" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/sql-deep-priority",
            )
        )
        session.flush()
        session.add(
            Artifact(
                id="artifact-sql-deep-priority",
                task_id="task-sql-deep-priority",
                content_sha256="b" * 64,
                logical_path="sample.exe",
                detected_type="pe",
            )
        )
        session.flush()
        session.add(
            ToolRun(
                id="run-sql-deep-priority",
                task_id="task-sql-deep-priority",
                artifact_id="artifact-sql-deep-priority",
                tool_name="fixture",
                tool_version="test",
                status="SUCCEEDED",
            )
        )
        session.flush()
        session.add_all(
            [
                Evidence(
                    id=f"string-deep-{index}",
                    task_id="task-sql-deep-priority",
                    artifact_id="artifact-sql-deep-priority",
                    tool_run_id="run-sql-deep-priority",
                    module="static",
                    kind="string",
                    nature="STATIC_OBSERVED",
                    value={"text": f"noise-{index}"},
                    anchor={"type": "string"},
                )
                for index in range(10)
            ]
            + [
                Evidence(
                    id="semantic-summary-deep",
                    task_id="task-sql-deep-priority",
                    artifact_id="artifact-sql-deep-priority",
                    tool_run_id="run-sql-deep-priority",
                    module="investigation",
                    kind="function_semantic_summary",
                    nature="STATIC_INFERRED",
                    value={"function": "loader", "call_sequence": [{"api": "LoadLibraryW"}]},
                    anchor={"function_entry": "0x401000"},
                ),
                Evidence(
                    id="context-deep",
                    task_id="task-sql-deep-priority",
                    artifact_id="artifact-sql-deep-priority",
                    tool_run_id="run-sql-deep-priority",
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "loader", "entry": "0x401000"},
                    anchor={"function_entry": "0x401000"},
                ),
                Evidence(
                    id="pcode-deep",
                    task_id="task-sql-deep-priority",
                    artifact_id="artifact-sql-deep-priority",
                    tool_run_id="run-sql-deep-priority",
                    module="investigation",
                    kind="pcode_slice",
                    nature="STATIC_INFERRED",
                    value={"operations": ["CALL LoadLibraryW"]},
                    anchor={"function_entry": "0x401000"},
                ),
            ]
        )
        session.flush()
        selected = service._load_investigation_execution_rows(
            session,
            task_id="task-sql-deep-priority",
            artifact_id="artifact-sql-deep-priority",
            action_kinds={"string", "function_context", "function_semantic_summary", "pcode_slice"},
            limit=3,
        )

    assert [item.kind for item in selected] == [
        "function_context",
        "function_semantic_summary",
        "pcode_slice",
    ]


def test_model_context_compaction_caps_serialized_evidence_without_dropping_api_identity() -> None:
    """Planner prompts must remain provider-sized for dense Ghidra windows."""
    value = {
        "api": "GetProcAddress",
        "instructions": [
            {"address": f"0x{index:04x}", "text": "MOV RAX, " + "A" * 400}
            for index in range(96)
        ],
        "call_targets": [
            {"target_name": f"WinHttpFunction{index}", "metadata": "B" * 300}
            for index in range(96)
        ],
    }

    compact = AnalysisService._compact_model_value(value, limit=640)
    encoded = json.dumps(compact, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    assert len(encoded) <= 640
    assert "GetProcAddress" in encoded.decode("utf-8")


def test_model_planner_reorders_artifacts_and_records_policy_safe_plan(test_settings) -> None:
    settings = replace(test_settings, environment="demo", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        context = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        pe_id = next(item["artifact_id"] for item in context["artifacts"] if item["detected_type"] == "pe")
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "objective": "Prioritize executable structure",
                                    "actions": [
                                        {
                                            "tool_name": "ghidra-headless",
                                            "target_artifact_id": pe_id,
                                            "priority": 1,
                                            "reason": "Function evidence is the highest-value uncertainty.",
                                            "expected_evidence": ["function", "cfg_block"],
                                            "analysis_focus": ["imports", "entry points"],
                                            "depends_on": [],
                                        }
                                    ],
                                    "stop_conditions": ["budget exhausted"],
                                    "limitations": [],
                                }
                            )
                        }
                    }
                ]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("dynamic planner")
    root = store.put(b"MZ" + b"\x00" * 32)
    script = store.put(b"print(1)")
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={"preset": {"id": "first-phase-full-static"}},
        )
        session.add(task)
        session.flush()
        for stored, path, detected in ((root, "sample.exe", "pe"), (script, "helper.py", "script")):
            session.add(
                ContentBlob(
                    sha256=stored.sha256,
                    size=stored.size,
                    media_type="application/octet-stream",
                    storage_key=stored.storage_key,
                )
            )
            session.flush()
            session.add(
                Artifact(
                    task_id=task.id,
                    content_sha256=stored.sha256,
                    logical_path=path,
                    role="EXECUTABLE" if detected == "pe" else "SCRIPT",
                    obligation="REQUIRED",
                    detected_type=detected,
                )
            )
        session.flush()
        artifacts = list(session.query(Artifact).filter(Artifact.task_id == task.id))
        deterministic = [item.id for item in artifacts]

    actions, limitations = service.run_model_planning(task.id, artifacts, deterministic, phase="test")
    assert not limitations
    assert actions and actions[0].tool_name == "ghidra-headless"
    assert service._merge_planned_actions(deterministic, actions, artifacts)[0] == actions[0].target_artifact_id
    snapshot = service.task_view(task.id)["strategy_snapshot"]
    assert snapshot["dynamic_planning"]["status"] == "MODEL_PLAN_APPLIED"


def test_model_planner_normalizes_baseline_action_placeholder(test_settings) -> None:
    """Prompt-schema placeholders must not turn a safe tool plan into fallback."""
    settings = replace(test_settings, environment="demo", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "parse the script",
                    "actions": [{
                        "tool_name": "script-parser",
                        "action_type": "OPTIONAL_CLOSED_ACTION",
                        "target_artifact_id": "artifact-script",
                        "priority": 1,
                        "reason": "baseline parser",
                        "expected_evidence": ["script_line"],
                    }],
                    "stop_conditions": [],
                    "limitations": [],
                })}}],
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("baseline marker")
    stored = store.put(b"print('ok')")
    artifact = Artifact(
        id="artifact-script",
        task_id="",
        content_sha256=stored.sha256,
        logical_path="helper.py",
        detected_type="script",
        role="SCRIPT",
        obligation="REQUIRED",
    )
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact.task_id = task.id
        session.add(ContentBlob(sha256=stored.sha256, size=stored.size, media_type="text/plain", storage_key=stored.storage_key))
        session.flush()
        session.add(artifact)
        session.flush()

    actions, limitations = service.run_model_planning(
        task.id, [artifact], ["artifact-script"], phase="marker"
    )

    assert limitations == []
    assert len(actions) == 1
    assert actions[0].action_type is None
    assert actions[0].tool_name == "script-parser"


def test_model_planner_rejects_uncited_targeted_investigation_action(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "inspect resolver",
                    "actions": [{
                        "tool_name": "rva-xref-query",
                        "action_type": "GET_XREFS_TO",
                        "target_artifact_id": "artifact-1",
                        "priority": 1,
                        "reason": "follow API resolver",
                        "target_selector": {"target": "GetProcAddress"},
                    }],
                    "stop_conditions": [],
                    "limitations": [],
                })}}],
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("uncited action")
    with database.session_factory.begin() as session:
        session.add(ContentBlob(sha256="c" * 64, size=1, media_type="application/octet-stream", storage_key="sha256/c"))
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-1",
            task_id=task.id,
            content_sha256="c" * 64,
            logical_path="resolver.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()

    actions, limitations = service.run_model_planning(task.id, [artifact], [artifact.id], phase="test")

    assert actions == []
    assert any("rejected 1" in item for item in limitations)
    planning = service.task_view(task.id)["strategy_snapshot"]["dynamic_planning"]
    assert planning["rejected_actions"][0]["reason"] == "uncited_investigation_action"


def test_model_planner_rejects_selector_not_grounded_in_cited_evidence(test_settings) -> None:
    """A valid citation cannot authorize a different model-invented target."""
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "inspect resolver",
                    "actions": [{
                        "tool_name": "rva-xref-query",
                        "action_type": "GET_XREFS_TO",
                        "target_artifact_id": "artifact-grounded",
                        "priority": 1,
                        "reason": "attempt to substitute a new target",
                        "evidence_ids": ["getproc-evidence"],
                        "target_selector": {"target": "LoadLibraryA"},
                    }],
                    "stop_conditions": [],
                    "limitations": [],
                })}}],
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("selector grounding")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="d" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/d",
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-grounded",
            task_id=task.id,
            content_sha256="d" * 64,
            logical_path="resolver.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        tool_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="pe-parser",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(tool_run)
        session.flush()
        session.add(
            Evidence(
                id="getproc-evidence",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static",
                kind="xref",
                nature="STATIC_OBSERVED",
                value={"target_name": "GetProcAddress", "caller": "resolver"},
                anchor={"function_entry": "0x140001000"},
            )
        )
        session.flush()

    actions, _ = service.run_model_planning(
        task.id, [artifact], [artifact.id], phase="selector-grounding"
    )

    assert actions == []
    planning = service.task_view(task.id)["strategy_snapshot"]["dynamic_planning"]
    assert planning["rejected_actions"][0]["reason"] == "selector_not_anchored_in_cited_evidence"


def test_model_planner_drops_extra_parameters_from_baseline_tool_actions(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "inspect sample",
                    "actions": [{
                        "tool_name": "script-parser",
                        "target_artifact_id": "artifact-extra",
                        "priority": 1,
                        "reason": "mandatory parser",
                        "parameters": {"path": "../../outside", "execute": True},
                    }],
                    "stop_conditions": [],
                    "limitations": [],
                })}}],
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("parameter sanitization")
    stored = service.content_store.put(b"print('ok')")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        session.add(ContentBlob(sha256=stored.sha256, size=stored.size, media_type="text/plain", storage_key=stored.storage_key))
        session.flush()
        artifact = Artifact(
            id="artifact-extra",
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="helper.py",
            detected_type="script",
            role="SCRIPT",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()

    actions, _ = service.run_model_planning(task.id, [artifact], [artifact.id], phase="parameter-sanitization")
    assert actions and actions[0].parameters == {}
    assert actions[0].target_selector == {}


def test_reference_isolated_blind_planner_hides_knowledge_fact_matcher(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()
    delivered_tool_lists: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        context = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        delivered_tool_lists.append(context["allowed_tools"])
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "Request a prohibited external fact lookup",
                    "actions": [{
                        "tool_name": "knowledge-fact-matcher",
                        "target_artifact_id": "blind-artifact",
                        "priority": 1,
                        "reason": "This must not be available to a blind run",
                    }],
                    "stop_conditions": [],
                    "limitations": [],
                })}}],
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("blind planner fact isolation")
    with database.session_factory.begin() as session:
        session.add(ContentBlob(
            sha256="b" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/blind",
        ))
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "blind_run": {
                    "enabled": True,
                    "reference_isolated": True,
                    "scorecard_version": "blind-fact-isolation-v1",
                }
            },
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="blind-artifact",
            task_id=task.id,
            content_sha256="b" * 64,
            logical_path="blind.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()

    actions, limitations = service.run_model_planning(
        task.id,
        [artifact],
        [artifact.id],
        phase="blind-v2-regression",
    )

    assert len(delivered_tool_lists) == 1
    assert "knowledge-fact-matcher" not in delivered_tool_lists[0]
    assert actions == []
    assert any("rejected 1" in item for item in limitations)


def test_model_plan_is_executed_as_ordered_action_queue(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    database = service.database
    database.create_schema()
    case = service.create_case("action queue")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifacts = []
        for path, detected in (("loader.exe", "pe"), ("helper.py", "script")):
            session.add(
                ContentBlob(
                    sha256=f"{path}-sha",
                    size=1,
                    media_type="application/octet-stream",
                    storage_key=f"sha256/{path}-sha",
                )
            )
            session.flush()
            artifact = Artifact(
                task_id=task.id,
                content_sha256=f"{path}-sha",
                logical_path=path,
                role="EXECUTABLE" if detected == "pe" else "SCRIPT",
                obligation="REQUIRED",
                detected_type=detected,
            )
            session.add(artifact)
            session.flush()
            artifacts.append(artifact)
        pe_id, script_id = (item.id for item in artifacts)

    actions = [
        DynamicPlanAction(
            tool_name="ghidra-headless",
            target_artifact_id=pe_id,
            priority=1,
            reason="function evidence",
            depends_on=[f"{pe_id}:pe-parser"],
        ),
        DynamicPlanAction(
            tool_name="pe-parser",
            target_artifact_id=pe_id,
            priority=4,
            reason="structure evidence",
        ),
    ]
    queue = service._build_execution_queue([pe_id, script_id], actions, artifacts)
    shape = [(item.artifact_id, item.tool_name) for item in queue]
    # Assert the SCHEDULING CONTRACT rather than the exact list: the deterministic baseline gained the
    # PE specialist tools (see `_baseline_specialist_tools`), so pinning the full sequence made this
    # test fail on a coverage improvement instead of on a scheduling regression. What must hold:
    #   * both model-proposed actions survive the policy/compatibility gate,
    #   * the declared dependency pe-parser -> ghidra-headless is ordered,
    #   * the second artifact still gets its own parser.
    assert (pe_id, "pe-parser") in shape
    assert (pe_id, "ghidra-headless") in shape
    assert (script_id, "script-parser") in shape
    assert shape.index((pe_id, "pe-parser")) < shape.index((pe_id, "ghidra-headless")), (
        f"pe-parser must be scheduled before its dependent ghidra-headless: {shape}"
    )


def test_model_plan_can_add_methodology_specialist_after_baseline(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    case = service.create_case("methodology specialist")
    with service.database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        stored = service.content_store.put(b"MZ" + b"\x00" * 32)
        session.add(ContentBlob(sha256=stored.sha256, size=stored.size, media_type="application/octet-stream", storage_key=stored.storage_key))
        session.flush()
        artifact = Artifact(
            task_id=task.id, content_sha256=stored.sha256, logical_path="loader.exe",
            role="EXECUTABLE", obligation="REQUIRED", detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        signal_action = DynamicPlanAction(
            tool_name="signal-extractor", target_artifact_id=artifact.id,
            priority=1, reason="Extract the six methodology dimensions",
        )
        action = DynamicPlanAction(
            tool_name="knowledge-fact-matcher", target_artifact_id=artifact.id,
            priority=6, reason="Concrete signals require context-aware fact matching",
            depends_on=[f"{artifact.id}:signal-extractor"],
        )
        queue = service._build_execution_queue([artifact.id], [signal_action, action], [artifact])
        shape = [(item.artifact_id, item.tool_name) for item in queue]
        # The baseline now already contains knowledge-fact-matcher, so this test's original intent -
        # "a model can still add a methodology specialist" - is verified by the specialist being
        # present exactly once with its declared dependency ordered, not by the baseline staying small.
        assert shape.count((artifact.id, "knowledge-fact-matcher")) == 1, (
            f"the specialist must not be queued twice (baseline + model): {shape}"
        )
        assert (artifact.id, "signal-extractor") in shape
        assert (artifact.id, "ghidra-headless") in shape
        assert shape.index((artifact.id, "signal-extractor")) < shape.index(
            (artifact.id, "knowledge-fact-matcher")
        ), f"signal-extractor must precede its dependent knowledge-fact-matcher: {shape}"


def test_replanning_request_contains_completed_actions(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()
    contexts: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        context = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        contexts.append(context)
        artifact_id = context["artifacts"][0]["artifact_id"]
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "continue",
                    "actions": [{
                        "tool_name": "script-parser",
                        "target_artifact_id": artifact_id,
                        "priority": 1,
                        "reason": "new evidence",
                    }],
                    "stop_conditions": [],
                    "limitations": [],
                })}}],
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("replanning context")
    stored = store.put(b"print(1)")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        session.add(ContentBlob(
            sha256=stored.sha256,
            size=stored.size,
            media_type="text/plain",
            storage_key=stored.storage_key,
        ))
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="helper.py",
            role="SCRIPT",
            obligation="REQUIRED",
            detected_type="script",
        )
        session.add(artifact)
        session.flush()

    service.run_model_planning(task.id, [artifact], [artifact.id], phase="initial")
    service.run_model_planning(
        task.id,
        [artifact],
        [artifact.id],
        phase="replan",
        completed_actions=[
            {"action_key": f"{artifact.id}:script-parser", "tool_name": "script-parser", "status": "completed"}
        ],
    )
    assert contexts[0]["completed_actions"] == []
    assert contexts[1]["completed_actions"][0]["action_key"].endswith(":script-parser")


def test_first_runtime_planning_turn_sees_committed_static_evidence(test_settings, monkeypatch) -> None:
    """The runtime planner must not run against the pre-parser empty frontier."""
    settings = replace(test_settings, environment="demo", model_calls_enabled=True)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    observed: list[int] = []

    def planner(task_id, artifacts, deterministic_actions, *, phase, completed_actions=None):
        with database.session_factory() as session:
            observed.append(
                session.query(Evidence)
                .filter(Evidence.task_id == task_id)
                .count()
            )
        return [], []

    monkeypatch.setattr(service, "_run_model_planning", planner)
    case = service.create_case("planner evidence frontier")
    service.analyze_submission(
        case_id=case.id,
        filename="loader.py",
        content=b"import socket\nprint('static evidence')\n",
    )

    assert observed, "runtime analysis should perform a bounded planning turn"
    assert observed[0] > 0, "the first planning turn must see persisted parser Evidence"


def test_scheduler_allows_bounded_multi_turn_model_replanning_after_new_static_evidence(
    test_settings,
) -> None:
    settings = replace(test_settings, environment="demo", model_calls_enabled=True)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    planner_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal planner_calls
        payload = json.loads(request.content)
        prompt_data = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        if "allowed_investigation_actions" not in prompt_data:
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"claims": []}'}}]})
        planner_calls += 1
        artifact_id = prompt_data["artifacts"][0]["artifact_id"]
        tools = ("signal-extractor", "c2-protocol-scanner")
        actions = []
        if planner_calls <= len(tools):
            actions.append(
                {
                    "tool_name": tools[planner_calls - 1],
                    "target_artifact_id": artifact_id,
                    "priority": planner_calls,
                    "reason": "request the next bounded static observation",
                }
            )
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "recover static mechanism evidence",
                    "actions": actions,
                    "stop_conditions": [],
                    "limitations": [],
                })}}]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("bounded multi-turn planner")
    result = service.analyze_submission(
        case_id=case.id,
        filename="loader.py",
        content=b"import socket\nprint('static only')\n",
    )

    planning = service.task_view(result.task_id)["strategy_snapshot"]["dynamic_planning"]
    # The second action-bearing turn is justified by Evidence produced by the
    # first specialist action.  An empty-plan repair may make additional HTTP
    # attempts, but it cannot authorize a third action or replay an existing
    # one against the identical static frontier.
    action_turns = [item for item in planning["history"] if item["actions"]]
    assert planner_calls >= 2
    assert len(action_turns) == 2
    assert [item["actions"][0]["tool_name"] for item in action_turns] == [
        "signal-extractor",
        "c2-protocol-scanner",
    ]
    assert len({item["actions"][0]["planner_turn_id"] for item in action_turns}) == 2
    assert all(item["completed_actions"] for item in action_turns[1:])


def test_blind_v2_preserves_multiple_model_turns_without_reference_context(test_settings) -> None:
    settings = replace(test_settings, environment="demo", model_calls_enabled=True)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    planner_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal planner_calls
        payload = json.loads(request.content)
        data = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        # The blind request may contain provenance labels such as
        # ``reference_isolated``; it must not contain evaluator facts or Gold
        # mechanism conclusions.
        serialized_data = json.dumps(data, ensure_ascii=True).casefold()
        assert "loading-chain-facts" not in serialized_data
        assert "resume-critical" not in serialized_data
        assert "knowledge-fact-matcher" not in data.get("allowed_tools", [])
        planner_calls += 1
        artifact_id = data["artifacts"][0]["artifact_id"]
        action = {
            "tool_name": "signal-extractor",
            "target_artifact_id": artifact_id,
            "priority": planner_calls,
            "reason": "request another bounded static signal pass",
        }
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": json.dumps({
                    "objective": "recover evidence without external facts",
                    "actions": [action] if planner_calls <= 2 else [],
                    "stop_conditions": [],
                    "limitations": [],
                })}}]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("blind multi-turn")
    result = service.analyze_blind_submission(
        case_id=case.id,
        filename="blind.py",
        content=b"import socket\nprint('static')\n",
        scorecard_version="blind-v2-multi-turn",
    )

    task = service.task_view(result.task_id)
    planning = task["strategy_snapshot"]["dynamic_planning"]
    assert planner_calls >= 2
    assert len(planning["history"]) >= 2
    assert task["blind_runs"][0]["snapshot"]["reference_isolated"] is True


def test_decoded_child_creates_observed_drop_and_inferred_behavior_relation(test_settings) -> None:
    import base64

    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    case = service.create_case("W4 component relations")
    encoded = base64.b64encode(b"VirtualAlloc LoadLibraryA " * 8).decode()
    result = service.analyze_submission(
        case_id=case.id,
        filename="loader.py",
        content=f"import base64\npayload='{encoded}'\nVirtualAlloc\n".encode(),
    )
    task = service.task_view(result.task_id)
    assert any(item["relation_type"] == "DROPS" for item in task["relations"])
    assert any(
        item["relation_type"] in {"LOADS", "INJECTS", "DECRYPTS"}
        and item["status"] == "INFERRED"
        for item in task["relations"]
    )


def test_static_execution_claim_projects_executes_relation(test_settings) -> None:
    import base64

    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    case = service.create_case("W4 execution relation")
    encoded = base64.b64encode(b"CreateProcessA " * 16).decode()
    result = service.analyze_submission(
        case_id=case.id,
        filename="launcher.py",
        content=f"import subprocess\npayload='{encoded}'\nCreateProcessA\n".encode(),
    )
    task = service.task_view(result.task_id)
    assert any(item["module"] == "execution" for item in task["claims"])
    assert any(
        item["relation_type"] == "EXECUTES" and item["status"] == "INFERRED"
        for item in task["relations"]
    )


def test_deterministic_claims_have_valid_evidence_references(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    case = service.create_case("W4 deterministic validation")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"import socket\nCreateProcessA\n",
    )
    task = service.task_view(result.task_id)
    evidence_ids = {item["id"] for item in task["evidence"]}
    assert task["claims"]
    linked_claim_ids = {item["claim_id"] for item in task["claim_evidence"]}
    assert all(item["id"] in linked_claim_ids for item in task["claims"])
    assert all(
        item["evidence_id"] in evidence_ids for item in task["claim_evidence"]
    )


def test_enabled_but_unconfigured_models_are_audited_and_make_task_partial(test_settings) -> None:
    settings = replace(
        test_settings,
        model_calls_enabled=True,
        primary_model=ModelProviderSettings("primary", "", "", ""),
        fallback_model=ModelProviderSettings("fallback", "", "", ""),
    )
    service = AnalysisService(
        settings, Database(settings.database_url), LocalContentStore(settings.content_store_path)
    )
    service.database.create_schema()
    case = service.create_case("W4 unavailable models")

    result = service.analyze_submission(
        case_id=case.id, filename="sample.py", content=b"import socket\n"
    )
    task = service.task_view(result.task_id)

    assert task["outcome"] == "PARTIAL"
    assert [item["status"] for item in task["model_calls"]] == ["FAILED", "FAILED"]
    assert [item["error_type"] for item in task["model_calls"]] == [
        "ProviderNotConfigured",
        "ProviderNotConfigured",
    ]


def test_daily_audit_seal_is_idempotent(test_settings) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    case = service.create_case("W4 audit seal")
    result = service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")
    with database.session_factory() as session:
        from threat_report_agent.models import AuditEvent

        event = session.query(AuditEvent).filter(AuditEvent.task_id == result.task_id).first()
        assert event is not None
        day = service._as_utc(event.created_at).date()
    assert service.seal_daily_audit(utc_day=day) >= 1
    assert service.seal_daily_audit(utc_day=day) == 0
    integrity = service.audit_integrity(result.task_id)
    daily = next(
        item
        for item in integrity["seals"]
        if item["terminal_event_type"].startswith("audit.daily:")
    )
    assert daily["sequence"] < 0
    assert abs(daily["sequence"]) < 2_147_483_647
    with database.session_factory() as session:
        from threat_report_agent.models import AuditEvent

        last_on_day = (
            session.query(AuditEvent)
            .filter(AuditEvent.task_id == result.task_id)
            .order_by(AuditEvent.chain_sequence.desc())
            .first()
        )
        assert last_on_day is not None
    assert daily["terminal_event_hash"] == last_on_day.event_hash
    assert integrity["valid"] is True


def test_behavior_relation_requires_claim_and_structural_relation_requires_evidence(
    test_settings,
) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    case = service.create_case("W4 relations")
    result = service.analyze_submission(case_id=case.id, filename="a.py", content=b"print(1)")
    task = service.task_view(result.task_id)
    first = task["artifacts"][0]["id"]
    with pytest.raises(ValueError, match="requires observed Evidence"):
        service.add_component_relation(
            task_id=result.task_id,
            source_artifact_id=first,
            target_artifact_id=first,
            relation_type="CONTAINS",
        )
    with pytest.raises(ValueError, match="requires an inferred Claim"):
        service.add_component_relation(
            task_id=result.task_id,
            source_artifact_id=first,
            target_artifact_id=first,
            relation_type="LOADS",
        )


def test_case_archive_and_evidence_purge_gate_are_publicly_operable(test_settings) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    case = service.create_case("W4 purge lifecycle")
    service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")

    archived = service.archive_case(case.id, actor="reviewer")
    assert archived["status"] == "ARCHIVED"
    request = service.request_evidence_purge(
        case.id, requested_by="requester", reason="retention policy"
    )
    assert request["status"] == "PENDING_REVIEW"
    reviewed = service.review_evidence_purge(request["id"], reviewer="reviewer", approve=True)
    assert reviewed["status"] == "APPROVED"
    executed = service.execute_evidence_purge(request["id"], admin="admin")
    assert executed["status"] == "EXECUTED"
    assert executed["result"]["deleted_content_sha256"]


def test_retention_freeze_blocks_purge_until_case_is_unfrozen(test_settings) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    case = service.create_case("W4 retention freeze")
    service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")
    service.archive_case(case.id, actor="reviewer")
    service.set_retention_freeze(case.id, frozen=True, actor="admin", reason="legal hold")
    with pytest.raises(ValueError, match="retention freeze"):
        service.request_evidence_purge(case.id, requested_by="requester", reason="purge")
    service.set_retention_freeze(case.id, frozen=False, actor="admin", reason="hold released")
    request = service.request_evidence_purge(
        case.id, requested_by="requester", reason="purge after release"
    )
    assert request["status"] == "PENDING_REVIEW"


def test_expired_model_payloads_retain_shared_body_until_last_reference(test_settings) -> None:
    settings = replace(
        test_settings,
        model_calls_enabled=True,
        primary_model=ModelProviderSettings("primary", "", "", ""),
        fallback_model=ModelProviderSettings("fallback", "", "", ""),
    )
    database = Database(settings.database_url)
    database.create_schema()
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    case = service.create_case("W4 model retention")
    result = service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")
    with database.session_factory.begin() as session:
        calls = list(session.query(ModelCall).filter(ModelCall.task_id == result.task_id).order_by(ModelCall.attempt))
        assert len(calls) == 2
        assert calls[0].request_storage_key == calls[1].request_storage_key
        shared_key = calls[0].request_storage_key
        assert shared_key is not None
        now = utcnow()
        calls[0].payload_expires_at = now - timedelta(seconds=1)
        calls[1].payload_expires_at = now + timedelta(days=1)
    service.set_retention_freeze(case.id, frozen=True, actor="admin", reason="model legal hold")
    assert service.expire_model_payloads(now=now, actor="retention-worker") == 0
    service.set_retention_freeze(case.id, frozen=False, actor="admin", reason="model hold released")
    assert service.expire_model_payloads(now=now, actor="retention-worker") == 1
    assert store.read(shared_key)
    with database.session_factory() as session:
        remaining = session.get(ModelCall, calls[1].id)
        expired = session.get(ModelCall, calls[0].id)
        assert remaining is not None and remaining.request_storage_key == shared_key
        assert expired is not None and expired.request_storage_key is None
    with database.session_factory.begin() as session:
        remaining = session.get(ModelCall, calls[1].id)
        assert remaining is not None
        remaining.payload_expires_at = now - timedelta(seconds=1)
    assert service.expire_model_payloads(now=now, actor="retention-worker") == 1
    with pytest.raises(FileNotFoundError):
        store.read(shared_key)


def test_daily_audit_seal_public_scheduler_entrypoint_returns_count(test_settings) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    case = service.create_case("W4 daily seal entrypoint")
    result = service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")
    with database.session_factory() as session:
        from threat_report_agent.models import AuditEvent

        event = session.query(AuditEvent).filter(AuditEvent.task_id == result.task_id).first()
        assert event is not None
        day = service._as_utc(event.created_at).date()
    assert service.run_daily_audit_sealer(utc_day=day, actor="scheduler") >= 1


def test_analysis_package_replays_and_rejects_snapshot_tampering(test_settings) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    case = service.create_case("W4 package replay")
    result = service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")
    package = service.analysis_package(result.task_id)
    replayed = service.replay_analysis_package(package, selected_modules=["loader"])
    assert replayed["selected_modules"] == ["loader"]
    tampered = json.loads(json.dumps(package))
    tampered["analysis_snapshot"]["payload"]["task"]["lifecycle"] = "tampered"
    with pytest.raises(ValueError, match="integrity validation"):
        service.replay_analysis_package(tampered)


def test_merkle_seal_detects_payload_and_root_tampering(test_settings) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    case = service.create_case("W4 merkle tamper")
    result = service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")
    with database.session_factory() as session:
        seal = session.query(AuditSeal).filter(AuditSeal.task_id == result.task_id).first()
        assert seal is not None
        assert len(seal.merkle_root) == 64
    assert service.audit_integrity(result.task_id)["valid"] is True
