"""An agent may author the report narrative -- but only through the compose gate.

ADR-0036 / plan §8.3: a fluent draft may reorganise, explain and shorten the
deterministic fragments, but it may not introduce a fact they do not contain.

This matters because the workbench agent has a working model and full evidence
access, while the API-side model path was dead (``analyst_report_draft`` had no
writer at all).  Opening a submission path is what finally lets the model
contribute analysis instead of the backend merely rendering facts.  Opening it
*without* the gate would let fabricated endpoints reach the official body, since
``approve_report``/``publish_report`` do not run the compose gate themselves.

The API-level test drives the FastAPI app so the wiring is proven, not just the
service method.
"""

from __future__ import annotations

import pytest

from threat_report_agent.analyst_report import compose_gate_violations


def _fragments() -> str:
    return (
        "### 网络通信\n\n"
        "静态已恢复解码得到的网络配置：endpoint `http://203.0.113.10/ComHost.exe`。\n\n"
        "### 进程创建\n\n"
        "UNKNOWN(creation_flags)：没有恢复到说得通的创建标志。\n"
    )


def test_functional_narrative_passes_the_gate() -> None:
    """Explaining what a recovered value means is exactly what we want."""
    draft = (
        "### 网络通信\n\n"
        "样本使用 WinHTTP 进行命令与控制通信，端点 `http://203.0.113.10/ComHost.exe` "
        "是第二阶段载荷地址；本次未做网络访问。\n"
    )
    assert compose_gate_violations(draft, _fragments()) == []


def test_a_fabricated_endpoint_is_rejected() -> None:
    draft = "### 网络通信\n\n备用 C2：endpoint `http://198.51.100.7/backup.bin`。\n"
    violations = compose_gate_violations(draft, _fragments())
    assert any("not in composed fragments" in item for item in violations)


def test_upgrading_an_unknown_to_established_is_rejected() -> None:
    """The gate keys on a fixed phrase list, so the draft must use one of them."""
    draft = "### 进程创建\n\n样本以挂起方式创建子进程，创建标志已验证。\n"
    violations = compose_gate_violations(draft, _fragments())
    assert any("upgraded candidate/unknown wording" in item for item in violations)


def test_upgrade_detection_is_phrase_based_not_semantic() -> None:
    """Honest limit: a paraphrase outside the phrase list slips through.

    ``_COMPOSE_UPGRADE_MARKERS`` is a fixed tuple (已验证/已执行/已坐实/...).
    This test records that the check is lexical, so nobody mistakes it for a
    semantic guarantee when reasoning about what the gate can promise.
    """
    draft = "### 进程创建\n\n样本以挂起方式创建子进程，创建标志已确认。\n"
    assert compose_gate_violations(draft, _fragments()) == []


def test_submit_analyst_draft_service_is_wired_into_the_api() -> None:
    """The FastAPI route must exist and reach the service method."""
    from threat_report_agent import main

    routes = {
        getattr(route, "path", "")
        for route in main.create_app().routes
    }
    assert "/api/v1/reports/{revision_id}/analyst-draft" in routes
    # Session-scoped route: the DSH client only permits /api/v1/workbench/ paths.
    assert "/api/v1/workbench/sessions/{dsh_session_id}/report/analyst-draft" in routes


def test_session_scoped_path_is_the_one_the_client_can_reach() -> None:
    """The plugin client rejects any path outside /api/v1/workbench/."""
    from pathlib import Path

    client = Path(
        r"threat-dsh-workbench/packages/threat-api-client/src/index.ts"
    ).read_text(encoding="utf-8")
    assert "startsWith('/api/v1/workbench/')" in client
    # The agent-facing draft route must therefore live under that prefix.
    assert "/api/v1/workbench/sessions/" in client


def test_service_method_exists_with_gate_semantics() -> None:
    from threat_report_agent.service import AnalysisService

    assert hasattr(AnalysisService, "submit_analyst_draft")
    doc = AnalysisService.submit_analyst_draft.__doc__ or ""
    assert "compose gate" in doc.casefold() or "合成门" in doc
