"""Read-only domain projections for the analysis pipeline. PURE TYPES ONLY.

Plan step P1.1. This module exists because of a MEASURED fact, not a preference:

    contracts.py         138 lines, 10 classes  -> NO banned import
    runtime_contracts.py 208 lines,  2 classes  -> NO banned import
    models.py            793 lines, 33 classes  -> imports sqlalchemy and sqlalchemy.orm
                          (ToolRun, Evidence, Claim, ClaimEvidence, AnalysisSnapshot, ReportRevision,
                           InvestigationActionRecord, ...)

So the projections P1.1 names already exist, but the canonical copies are ORM classes bound to the persistence
layer: today a consumer wanting `Evidence` or `Claim` must import `models.py` and therefore SQLAlchemy.

THE ROUTE, justified from the plan rather than invented:

  * section 3.2 - "一个概念只能有一个 canonical implementation。重新导出不是第二个实现"
  * P1.1's failure note - "若类型需要大量业务逻辑，先建立 protocol/adapter，不把 AnalysisService 复制到类型模块"

Both point at **Protocol adapters over the existing canonical classes**. A parallel set of pure dataclasses would
be a second canonical implementation of 33 entities, which section 3.2 forbids.

MEMBER LISTS ARE MEASURED, NOT GUESSED. `runtime_checkable` isinstance checks member PRESENCE ONLY, so a
misspelt member makes a protocol silently unsatisfiable instead of loudly wrong. Every member below was read out
of the ORM class bodies by `.scratch/probe-p11-projection-members.py`; that probe prints the same lists so a
future drift is detectable.

WHAT THIS MODULE DOES NOT CLAIM: these Protocols do not decouple anything yet. They are the seam the later steps
(P2 report/investigation, P3.4 ReportRevisionWriter) can depend on instead of importing `models.py`. Proving that
the ORM classes satisfy them is the contract test's job, not this docstring's.

This module must stay free of persistence, transport and SDK imports - `tests/test_domain_type_boundaries.py`
enforces that.
"""
from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class AnalysisSnapshotView(Protocol):
    """An immutable Analysis Snapshot: the only input a Report may read (ADR-0024).

    Members measured on `models.AnalysisSnapshot`: id, task_id, object_versions, created_at.
    The immutability is the point: a late-arriving result must not be able to change a revision rendered from
    this snapshot, which is why late results create a NEW snapshot rather than mutating this one.
    """

    id: str
    task_id: str
    object_versions: object
    created_at: datetime


@runtime_checkable
class ReportRevisionView(Protocol):
    """One published Report Revision (ADR-0025 / ADR-0036).

    Members measured on `models.ReportRevision`. `parent_revision_id` is part of the protocol because revision
    identity is load-bearing: a re-render must not silently become a new lineage. `document` and `markdown` are
    both present on purpose - `markdown` is frozen at row creation, while `document` is what a re-render reads,
    and the difference between them is exactly what the published-layer instrument compares.
    """

    id: str
    task_id: str
    snapshot_id: str
    parent_revision_id: str | None
    status: str
    author: str
    selected_modules: object
    document: object
    markdown: str
    edit_kind: str
    created_at: datetime


@runtime_checkable
class ToolRunView(Protocol):
    """One tool execution (ADR-0014): tools produce ToolRun/Evidence, the agent produces Claim.

    Members measured on `models.ToolRun`. `error` is part of the protocol deliberately: a run that did not
    succeed must be able to carry its reason to a reader, which is what the earlier limitation-propagation work
    depends on.
    """

    id: str
    task_id: str
    artifact_id: str
    tool_name: str
    tool_version: str
    status: str
    parameters: object
    environment: object
    output: object
    output_sha256: str | None
    output_storage_key: str | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


@runtime_checkable
class EvidenceView(Protocol):
    """One piece of Evidence. Not a Claim, and not model text (ADR-0014).

    Members measured on `models.Evidence`. `anchor` is part of the protocol because an evidence row without an
    anchor cannot bind file identity plus RVA/offset/function, which the glossary requires.
    """

    id: str
    task_id: str
    artifact_id: str
    tool_run_id: str | None
    module: str
    kind: str
    nature: str
    value: object
    anchor: object
    created_at: datetime


@runtime_checkable
class ClaimView(Protocol):
    """One Claim with its status vocabulary intact.

    Members measured on `models.Claim`. `status` and `confidence` are present and NOT narrowed here: this module
    must not restate, tighten or promote the CANDIDATE/verified/disputed/rejected vocabulary, which
    `CONTEXT.md` owns.
    """

    id: str
    task_id: str
    module: str
    claim_type: str
    subject: str
    action: str
    object: str
    mechanism: str
    condition: str
    statement: str
    nature: str
    status: str
    confidence: str
    attack_mapping: object
    model_call_id: str | None
    created_at: datetime


#: The projections P1.1 names, paired with the ORM class this project currently uses as the canonical
#: implementation. The contract test asserts each ORM class satisfies its protocol, so a renamed or removed
#: column fails loudly here instead of silently breaking a downstream reader.
PROJECTION_PAIRS: tuple[tuple[str, str], ...] = (
    ("AnalysisSnapshotView", "AnalysisSnapshot"),
    ("ReportRevisionView", "ReportRevision"),
    ("ToolRunView", "ToolRun"),
    ("EvidenceView", "Evidence"),
    ("ClaimView", "Claim"),
)
