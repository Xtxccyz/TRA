"""A BOUNDED API list must not be published as a total.

MEASURED defect this pins (adversarial audit, item 3): the adapter keeps at most 256 API names per run
(`simulation_adapters.py`, `api_cap`), and **102 evidence rows over 34 tasks hold exactly 256 names with none
above** - the cap saturates in production. The chapter then rendered

    已观测 API 调用：256 次（…）

with the number reading as the sample's total, while the same rows carried `modelled_calls` 1,031 uncapped and
the true number of observed calls was >= 256 and unknown.

The chapter already applies the right pattern elsewhere for a capped list ("另有 `N` 个未展开"); this pins that
the API total now does the same, and that the notice states the cap is NOT the sample's total.

FAILS BEFORE THE FIX: no `api_truncation` key existed in the projection and the line carried no remainder.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.analyst_report import _emulation_status_section  # noqa: E402


def _row(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "simulator": "speakeasy",
        "status": "FAILED",
        "stop_reason": "EXECUTION_ERROR",
        "limitations": [],
        "observed_apis": {"MSVBVM60.__vbaStrCopy": 256},
        "shim": {},
        "api_truncation": {"kept": 256, "dropped": 7, "entry_points_dropped": 0, "api_cap": 256},
    }
    result.update(overrides)
    return {"type": "emulation_status", "overall": "FAILED", "attempted": True, "results": [result]}


def test_a_saturated_cap_is_declared_with_its_remainder() -> None:
    text = "\n".join(_emulation_status_section([_row()]))

    assert "已观测 API 调用" in text
    assert "另有 `7` 个未展开" in text, (
        "the API total is bounded but published as a total; the dropped count must be stated: "
        f"{text[-400:]}"
    )
    assert "该上限不是本样本的调用总数" in text, (
        "the reader must be told the cap is a per-run limit, not the sample's call count"
    )


def test_an_uncapped_run_carries_no_remainder() -> None:
    """NEGATIVE CONTROL: `dropped == 0` must stay silent - a notice for nothing is a false claim."""
    text = "\n".join(
        _emulation_status_section(
            [_row(api_truncation={"kept": 12, "dropped": 0, "entry_points_dropped": 0, "api_cap": 256})]
        )
    )
    assert "已观测 API 调用" in text
    assert "未展开" not in text, f"claimed a remainder that does not exist: {text[-400:]}"


def test_a_projection_without_the_key_still_renders() -> None:
    """Backward compatibility: an older projection carries no `api_truncation` and must not crash."""
    text = "\n".join(_emulation_status_section([_row(api_truncation=None)]))
    assert "已观测 API 调用" in text
    assert "未展开" not in text
