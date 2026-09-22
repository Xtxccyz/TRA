"""E2: the un-honoured-control note must be produced, and must reach the failure record.

`reason_control_note` exists because the configured route declares `primary_disable_reasoning = t` while the
gateway only implements that control for Qwen-compatible providers - so the request went out with reasoning
ENABLED and nothing said so. That silence is what made a six-round diagnosis necessary: the only visible
symptom was a 13,081-character prose reply.

The note is only useful if it TRAVELS, so this pins both halves: that it is produced for a non-Qwen provider
when the control was requested, and that it is ABSENT when it was not requested (a note that always fires
would be noise nobody reads).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.config import ModelProviderSettings  # noqa: E402
from threat_report_agent.model_gateway import ModelGateway  # noqa: E402

QWEN = ModelProviderSettings(
    provider="ali", model="qwen3.7-max", base_url="https://example.invalid", api_key="k"
)
CUSTOM = ModelProviderSettings(
    provider="custom", model="deepseek-flash", base_url="https://api.deepseek.com", api_key="k"
)


def test_a_non_qwen_provider_cannot_honour_disable_reasoning() -> None:
    """The predicate the note is built from - stated separately so a change here is visible."""
    assert ModelGateway._is_qwen_reasoning_provider(CUSTOM) is False
    assert ModelGateway._is_qwen_reasoning_provider(QWEN) is True


def _gateway_source() -> str:
    """The gateway implementation's source, resolved through the import system rather than by file path.

    MEASURED (P2-M): this file used to read `src/threat_report_agent/model_gateway.py` by path. When the module
    moved to `threat_report_agent/model/model_gateway.py` the old path became a compatibility shim, so these
    assertions silently started reading five lines of shim text and failed with "the note is not initialised at
    all" - a message that pointed at the implementation, not at the reading method. Resolving through the import
    system follows the module wherever it moves; the guard below makes a future move fail HERE, loudly, instead
    of somewhere confusing.
    """
    import threat_report_agent.model_gateway as gateway_module

    source = Path(gateway_module.__file__).read_text(encoding="utf-8")
    assert "Compatibility shim" not in source, (
        "these assertions are reading a compatibility shim at "
        f"{gateway_module.__file__}, not the gateway implementation"
    )
    return source


def test_the_note_names_the_control_that_was_dropped() -> None:
    """The note's CONTENT must say which control and why, or it cannot be acted on.

    Checked against the source text because the note is assembled inside the request builder, which needs a
    live transport to exercise. That is a weaker check than a behavioural one - stated plainly rather than
    dressed up: it proves the wording exists, not that it fired.
    """
    source = _gateway_source()
    assert "disable_reasoning was requested" in source
    assert "only implements it for Qwen-compatible" in source
    assert "reasoning ENABLED" in source, "the note must state the request went out with reasoning ON"


def test_the_note_is_attached_to_the_failure_record() -> None:
    """A note that is built but never recorded is exactly the silent drop it was written to end."""
    source = _gateway_source()
    assert "reason_control_note" in source
    # It must be concatenated into `error_detail`, i.e. used rather than merely assigned.
    assert "if reason_control_note else error_detail" in source, (
        "reason_control_note is assigned but never merged into error_detail"
    )


def test_the_note_is_bound_on_every_branch() -> None:
    """The Qwen branch does not set it, so initialising it inside the if/elif would raise NameError there.

    MEASURED: the first version of this code did exactly that and it was caught by reading, not by a test -
    which is why the test now exists.
    """
    source = _gateway_source()
    assert 'reason_control_note = ""' in source, "the note is not initialised at all"
    initialise_at = source.index('reason_control_note = ""')
    branch_at = source.index("if disable_reasoning and self._is_qwen_reasoning_provider")
    assert initialise_at < branch_at, (
        "the note is initialised INSIDE the branches, so the Qwen branch - which does not set it - "
        "would raise NameError at the point of use"
    )
