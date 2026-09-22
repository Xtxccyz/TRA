"""C10 T5 benign-sample contract: first-request official GET must not invent malware.

This is not Resume 3080 and does not claim C10/T5/B11 complete.
"""

from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import select

from threat_report_agent.analyst_report import (
    ANALYST_CONCLUSION_HEADING,
    unmatched_category_statement,
    official_revision_semantic_gains,
    primary_analyst_violations,
    t6_revision_has_substantive_gain,
)
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import Evidence, InvestigationActionRecord, InvestigationThreadRecord
from threat_report_agent.service import AnalysisService
from threat_report_agent.simulation_adapters import benign_pe32_ret


def _unbenchmarked_dll_like_pe() -> bytes:
    """Tiny PE plus loader-like names. Not Resume and not a gold fixture."""
    return benign_pe32_ret() + (
        b"LoadLibraryA\x00GetProcAddress\x00CreateThread\x00CryptDecrypt\x00"
        b"VirtualAlloc\x00QueueUserAPC\x00WinHttpOpen\x00CreateProcessW\x00"
    )


def test_benign_pe_first_request_official_get_has_zero_false_malicious_conclusions(
    test_settings,
) -> None:
    """C10 T5 benign + C5 first request: analyze_submission without '再深入'."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    database.create_schema()
    case = service.create_case("c10 benign t5")
    result = service.analyze_submission(
        case_id=case.id,
        filename="benign-ret.exe",
        content=benign_pe32_ret(),
    )
    task = service.task_view(result.task_id)
    revision = service.get_report_revision(result.report_revision_id)
    official = str(revision.get("markdown") or "")
    dump = service._leftover_official_report_dump(result.task_id)

    assert result.report_revision_id
    assert ANALYST_CONCLUSION_HEADING in official
    assert "样本执行：**否**" in official
    assert task["outcome"] in {"PARTIAL", "BOUNDED", "BOUNDED_STATIC_ANALYSIS", "UNKNOWN"}
    assert task["outcome"] != "COMPLETE"
    assert primary_analyst_violations(official) == []

    folded = official.casefold()
    assert "活 c2" not in official
    assert "beacon" not in folded
    assert "apt" not in folded
    assert "lazarus" not in folded
    assert "已感染" not in official
    assert "已运行" not in official
    assert "resume.pdf" not in folded
    assert "foxitpdfreader" not in folded
    assert "载荷已执行" not in official
    assert "远程注入" not in official
    # G4 §8.2-2 / §8.4-1：进程注入属必写闭集，未命中时必须点名缺失槽位并声明边界。
    # 该章可以出现，但不得断言注入，也不得编造目标进程或内存关系。
    sentence = next(
        line for line in official.splitlines()
        if line.startswith("未命中：进程注入与隐蔽启动。")
    )
    assert "UNKNOWN(" in sentence, sentence
    assert "不代表样本不具备该能力" in sentence, sentence
    assert "### 横向移动" not in official
    assert "FUN_" not in official
    assert "PERSISTED_INVESTIGATION" not in official

    with database.session_factory() as session:
        kinds = {
            str(kind)
            for kind in session.scalars(
                select(Evidence.kind).where(Evidence.task_id == result.task_id)
            )
        }
    assert "investigation_seed_map" in kinds or "investigation_attempt" in kinds

    assert dump.get("authoritative_revision_id") == result.report_revision_id
    assert ANALYST_CONCLUSION_HEADING in str(dump.get("content") or official)
    assert str(dump.get("content") or "") == official


def test_unbenchmarked_dll_like_pe_first_request_does_not_copy_resume_ioc(
    test_settings,
) -> None:
    """C10 T5 live anti-hallucination: unbenchmarked PE, not Resume 3080."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    database.create_schema()
    case = service.create_case("c10 unbenchmarked dll")
    result = service.analyze_submission(
        case_id=case.id,
        filename="DoubleFeatureDll.dll",
        content=_unbenchmarked_dll_like_pe(),
    )
    task = service.task_view(result.task_id)
    revision = service.get_report_revision(result.report_revision_id)
    official = str(revision.get("markdown") or "")
    dump = service._leftover_official_report_dump(result.task_id)
    folded = official.casefold()

    assert result.report_revision_id
    assert ANALYST_CONCLUSION_HEADING in official
    assert task["outcome"] != "COMPLETE"
    assert primary_analyst_violations(official) == []
    assert "resume.pdf" not in folded
    assert "foxitpdfreader" not in folded
    assert "活 c2" not in official
    assert "beacon" not in folded
    assert "apt" not in folded
    assert "lazarus" not in folded
    assert "已感染" not in official
    assert "载荷已执行" not in official
    assert "远程注入" not in official
    # G4 §8.2-2：进程注入属必写闭集，未命中时必须点名缺失槽位并声明边界。
    sentence = next(
        line for line in official.splitlines()
        if line.startswith("未命中：进程注入与隐蔽启动。")
    )
    assert "UNKNOWN(" in sentence, sentence
    assert "不代表样本不具备该能力" in sentence, sentence
    assert "### 横向移动" not in official
    assert "### 命令分发" not in official
    assert "评测基准报告" not in official
    assert "CREATE_SUSPENDED" not in official
    assert "挂起" not in official
    if "CreateProcess" in official:
        assert "UNKNOWN(creation_flags)" in official
    assert dump.get("authoritative_revision_id") == result.report_revision_id
    assert str(dump.get("content") or "") == official
    assert "十问槽位" in official
    if "winhttp" in folded:
        assert "UNKNOWN(request)" in official
        assert "活 c2" not in official

    with database.session_factory() as session:
        threads = list(
            session.scalars(
                select(InvestigationThreadRecord).where(
                    InvestigationThreadRecord.task_id == result.task_id
                )
            )
        )
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == result.task_id
                )
            )
        )
        attempts = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == result.task_id,
                    Evidence.kind == "investigation_attempt",
                )
            )
        )
    assert threads, "C5: first analyze must open investigation threads without 再深入"
    attempted_types = []
    for row in attempts:
        value = row.value if isinstance(row.value, dict) else {}
        attempted_types.extend(
            str(item) for item in (value.get("attempted_action_types") or []) if item
        )
    for action in actions:
        attempted_types.append(str(action.action_type or ""))
    assert attempted_types, (
        "C5: first analyze must record attempted_action_types or InvestigationAction action_type"
    )
    simulation_statuses = []
    with database.session_factory() as session:
        for row in session.scalars(
            select(Evidence).where(
                Evidence.task_id == result.task_id,
                Evidence.kind == "simulation_result",
            )
        ):
            value = row.value if isinstance(row.value, dict) else {}
            simulation_statuses.append(str(value.get("status") or "").upper())
            assert str(row.nature or "").upper() != "EMULATION_OBSERVED"
    assert "SUCCEEDED" not in simulation_statuses
    assert "EMULATION_OBSERVED" not in official


def test_t6_refresh_without_new_how_is_not_substantive(test_settings) -> None:
    """C10 T6: a second revision with no new HOW/relation is stamped, not a pass."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    database.create_schema()
    case = service.create_case("c10 t6 refresh")
    result = service.analyze_submission(
        case_id=case.id,
        filename="benign-ret.exe",
        content=benign_pe32_ret(),
    )
    first = service.get_report_revision(result.report_revision_id)
    first_t6 = (first.get("document") or {}).get("t6_revision_diff")
    assert isinstance(first_t6, dict)
    assert first_t6.get("parent_present") is False
    assert first_t6.get("substantive") is False
    assert "t6_revision_diff" not in str(first.get("markdown") or "")

    refreshed = service._refresh_report_after_investigation(result.task_id)
    second = service.get_report_revision(refreshed["report_revision_id"])
    second_t6 = (second.get("document") or {}).get("t6_revision_diff")
    assert second["id"] != first["id"]
    assert second.get("parent_revision_id") == first["id"]
    assert isinstance(second_t6, dict)
    assert second_t6.get("parent_present") is True
    assert second_t6.get("substantive") is False
    assert second_t6.get("word_count_delta_is_not_gain") is True
    assert second_t6.get("action_count_delta_is_not_gain") is True
    assert "t6_revision_diff" not in str(second.get("markdown") or "")
    assert "JOINED_STATIC" not in str(second.get("markdown") or "")


def test_critic_blocked_cannot_leave_task_outcome_complete() -> None:
    """C10: critic BLOCKED + COMPLETE is coerced to PARTIAL before the quality gate."""
    blocked = SimpleNamespace(outcome="COMPLETE", analysis_class="FULL_STATIC_ANALYSIS")
    blocked_document = {
        "analysis_outcome": "COMPLETE",
        "analysis_quality": {
            "readiness": "BOUNDED_WITH_LIMITATIONS",
            "critic": {"status": "BLOCKED", "overclaim_checks": []},
            "s4_orchestration": [],
        },
    }
    AnalysisService._apply_honest_analysis_outcome(blocked, blocked_document)
    assert blocked_document["analysis_outcome"] == "PARTIAL"
    assert blocked.outcome == "PARTIAL"

    ready = SimpleNamespace(outcome="COMPLETE", analysis_class="FULL_STATIC_ANALYSIS")
    ready_document = {
        "analysis_outcome": "COMPLETE",
        "analysis_quality": {
            "readiness": "READY_FOR_REPORT",
            "critic": {"status": "PASS", "overclaim_checks": []},
            "s4_orchestration": [{"status": "CLOSED"}],
        },
    }
    AnalysisService._apply_honest_analysis_outcome(ready, ready_document)
    assert ready_document["analysis_outcome"] == "COMPLETE"
    assert ready.outcome == "COMPLETE"


def test_t6_word_count_and_action_count_are_not_a_gain() -> None:
    """C10 T6: padding or more actions without new HOW/relation/bytes is not a pass."""
    before = "## 分析结论\n\n`UNKNOWN(consumer)` creation_flags=`UNKNOWN(creation_flags)`\n"
    after = before + ("额外叙述。" * 40) + "\nactions=12\n"
    assert official_revision_semantic_gains(before, after) == ()
    assert t6_revision_has_substantive_gain(before, after) is False
    payload = AnalysisService._t6_revision_diff_payload(
        before,
        after,
        {"trace": {"tool_run_ids": ["t1"], "evidence_ids": ["e1"], "relation_ids": []}},
        {"trace": {"tool_run_ids": ["t1", "t2", "t3"], "evidence_ids": ["e1", "e2"], "relation_ids": []}},
    )
    assert payload["substantive"] is False
    assert payload["word_count_delta_is_not_gain"] is True
    assert payload["action_count_delta_is_not_gain"] is True


def test_t6_new_relation_is_a_gain_without_word_count() -> None:
    """C10 T6: a new catalog relation is a gain even when GET wording is unchanged."""
    markdown = "## 分析结论\n\nconsumer=`UNKNOWN(consumer)`\n"
    payload = AnalysisService._t6_revision_diff_payload(
        markdown,
        markdown,
        {"trace": {"relation_ids": [], "tool_run_ids": ["t1"], "evidence_ids": ["e1"]}},
        {
            "trace": {
                "relation_ids": ["rel-join-1"],
                "behavior_relation_ids": ["br-1"],
                "tool_run_ids": ["t1", "t2"],
                "evidence_ids": ["e1", "e2"],
            }
        },
    )
    assert payload["parent_present"] is True
    assert payload["substantive"] is True
    assert payload["word_count_delta_is_not_gain"] is True
    assert payload["action_count_delta_is_not_gain"] is True
    assert any("relation" in str(item).casefold() for item in payload["gains"])


def test_t6_new_join_parameter_or_unknown_fill_is_a_gain() -> None:
    """C10 T6: a new JOINED_STATIC / named consumer / filled flag is a real delta."""
    before = "## 分析结论\n\nconsumer=`UNKNOWN(consumer)` creation_flags=`UNKNOWN(creation_flags)`\n"
    after = (
        "## 分析结论\n\n"
        "`JOINED_STATIC` consumer=`WinHttpOpen` creation_flags=`0x000f4240`\n"
    )
    gains = official_revision_semantic_gains(before, after)
    assert "JOINED_STATIC" in gains
    assert any("winhttpopen" in item.casefold() for item in gains)
    assert any("0x000f4240" in item.casefold() for item in gains)
    assert t6_revision_has_substantive_gain(before, after) is True


def test_t6_new_recovered_bytes_hash_is_a_gain() -> None:
    """C10 T6: a new recovered buffer hash is a byte gain, not word count."""
    before = "## 分析结论\n\nconsumer=`UNKNOWN(consumer)`\n"
    after = (
        before
        + "`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`\n"
    )
    assert t6_revision_has_substantive_gain(before, after) is True
    payload = AnalysisService._t6_revision_diff_payload(before, after)
    assert payload["substantive"] is True
    assert payload["word_count_delta_is_not_gain"] is True
