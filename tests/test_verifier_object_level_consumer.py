"""A verifier may not confirm a consumer from an API *name* in decoded text.

``verify_http_download_mechanism`` confirmed its ``request consumer`` group by
substring-matching ``winhttpsendrequest`` against evidence text.  That is the
same string co-occurrence ADR-0035 and plan 5.2/5.3 forbid, and it is why a
mechanism could keep ``status=VERIFIED`` even after the projection layer stopped
naming a consumer.  This is the deepest of the three sites: the label itself.

The decoded WinHTTP API names and the decoded endpoint stay legitimate input --
they are recovered configuration, and the ``https input`` group must keep
passing on them.  What must now require object-level evidence is the claim that
a call actually *consumes* the request.
"""

from __future__ import annotations

from threat_report_agent.investigation import (
    verify_http_download_mechanism,
    verify_shell_output_mechanism,
)

_ENTRY = "0x140031f80"
_ANCHOR = {"function_entry": _ENTRY, "rva": 0x31F80}
_URL = "http://203.0.113.10/ComHost.exe"


def _decoded(row_id: str, text: str) -> dict[str, object]:
    return {
        "id": row_id,
        "kind": "decode_result",
        "nature": "STATIC_DERIVED",
        "value": {
            "decoded_preview": text,
            "decoded_strings": [text],
            "function_entry": _ENTRY,
        },
        "anchor": dict(_ANCHOR),
    }


def _argument_trace(row_id: str, api: str) -> dict[str, object]:
    return {
        "id": row_id,
        "kind": "api_argument_trace",
        "nature": "STATIC_OBSERVED",
        "value": {
            "api": api,
            "callsite": _ENTRY,
            "function_entry": _ENTRY,
            "static_only": True,
            "arguments": [
                {"index": 1, "name": "lpszHeaders", "resolved": True, "value": "0x1400560d8"}
            ],
        },
        "anchor": dict(_ANCHOR),
    }


def _name_only_evidence() -> list[dict[str, object]]:
    return [
        _decoded("decode-send", "WinHttpSendRequest"),
        _decoded("decode-recv", "WinHttpReceiveResponse"),
        _decoded("decode-url", _URL),
    ]


def test_https_input_group_still_passes_on_decoded_configuration() -> None:
    """Do not over-correct: the decoded endpoint is legitimate evidence."""
    verification = verify_http_download_mechanism(_name_only_evidence())
    checks = {str(item["name"]): item for item in verification.checks}
    assert checks["https input"]["passed"] is True


def test_api_names_alone_do_not_confirm_the_request_consumer() -> None:
    verification = verify_http_download_mechanism(_name_only_evidence())
    assert verification.accepted is False
    assert verification.status == "UNKNOWN"
    assert any("request consumer" in item for item in verification.missing)


def test_object_level_argument_trace_confirms_the_request_consumer() -> None:
    evidence = [
        *_name_only_evidence(),
        _argument_trace("trace-send", "WinHttpSendRequest"),
    ]
    verification = verify_http_download_mechanism(evidence)
    assert verification.accepted is True, verification.missing
    assert verification.status == "VERIFIED"
    checks = {str(item["name"]): item for item in verification.checks}
    consumer_check = next(name for name in checks if "request consumer" in name)
    assert checks[consumer_check]["passed"] is True
    assert "trace-send" in checks[consumer_check]["evidence_ids"]


def test_object_level_join_pair_confirms_the_request_consumer() -> None:
    join_row = {
        "id": "join-1",
        "kind": "decode_result",
        "nature": "STATIC_DERIVED",
        "value": {
            "decoded_preview": "WinHttpSendRequest",
            "function_entry": _ENTRY,
            "join_status": "JOINED_STATIC",
            "output_buffer": {"address_space": "image", "address": 0x1400560D8, "length": 24},
            "input_buffer": {"address_space": "image", "address": 0x1400560D8, "length": 24},
        },
        "anchor": dict(_ANCHOR),
    }
    evidence = [
        _decoded("decode-recv", "WinHttpReceiveResponse"),
        _decoded("decode-url", _URL),
        join_row,
    ]
    verification = verify_http_download_mechanism(evidence)
    assert verification.accepted is True, verification.missing
    checks = {str(item["name"]): item for item in verification.checks}
    consumer_check = next(name for name in checks if "request consumer" in name)
    assert "join-1" in checks[consumer_check]["evidence_ids"]


def test_unrelated_argument_trace_does_not_confirm_the_request_consumer() -> None:
    """A trace for a different API is not a request binding."""
    evidence = [
        *_name_only_evidence(),
        _argument_trace("trace-thread", "CreateThread"),
    ]
    verification = verify_http_download_mechanism(evidence)
    assert verification.accepted is False
    assert any("request consumer" in item for item in verification.missing)


def _call_row(row_id: str, api: str) -> dict[str, object]:
    return {
        "id": row_id,
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"target_function": api, "type": "COMPUTED_CALL", "function_entry": _ENTRY},
        "anchor": dict(_ANCHOR),
    }


def test_recovered_call_target_confirms_the_request_consumer() -> None:
    """A recovered call site is real evidence; only a name in data is not."""
    evidence = [
        _decoded("decode-recv", "WinHttpReceiveResponse"),
        _decoded("decode-url", _URL),
        _call_row("call-send", "WinHttpSendRequest"),
    ]
    verification = verify_http_download_mechanism(evidence)
    assert verification.accepted is True, verification.missing
    checks = {str(item["name"]): item for item in verification.checks}
    consumer_check = next(name for name in checks if "request consumer" in name)
    assert "call-send" in checks[consumer_check]["evidence_ids"]


def test_string_row_naming_the_api_does_not_confirm_the_request_consumer() -> None:
    """A bare string naming the API is data, not a call."""
    evidence = [
        _decoded("decode-recv", "WinHttpReceiveResponse"),
        _decoded("decode-url", _URL),
        {
            "id": "string-send",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "WinHttpSendRequest", "function_entry": _ENTRY},
            "anchor": dict(_ANCHOR),
        },
    ]
    verification = verify_http_download_mechanism(evidence)
    assert verification.accepted is False
    assert any("request consumer" in item for item in verification.missing)


# --------------------------------------------------------------------------
# SHELL_OUTPUT: same class. "pipe consumer" and "shell/process input" are
# consumption claims; a name in decoded text must not confirm them.
# --------------------------------------------------------------------------


def _shell_evidence(*, call_shaped: bool) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = [
        {
            "id": "capture",
            "kind": "string" if not call_shaped else "function_call",
            "nature": "STATIC_OBSERVED",
            "value": (
                {"text": "output capture", "function_entry": _ENTRY}
                if not call_shaped
                else {"target_function": "ReadFile", "function_entry": _ENTRY}
            ),
            "anchor": dict(_ANCHOR),
        }
    ]
    specs = (("proc", "CreateProcessW"), ("pipe", "CreatePipe"), ("peek", "PeekNamedPipe"))
    for row_id, api in specs:
        if call_shaped:
            rows.append(_call_row(row_id, api))
        else:
            rows.append(
                {
                    "id": row_id,
                    "kind": "string",
                    "nature": "STATIC_OBSERVED",
                    "value": {"text": api, "function_entry": _ENTRY},
                    "anchor": dict(_ANCHOR),
                }
            )
    return rows


def test_pipe_consumer_requires_a_recovered_call_not_a_name() -> None:
    verification = verify_shell_output_mechanism(_shell_evidence(call_shaped=False))
    assert verification.accepted is False
    assert verification.status == "UNKNOWN"
    assert any("pipe consumer" in item for item in verification.missing)
    assert any("shell/process input" in item for item in verification.missing)


def test_pipe_consumer_accepts_recovered_calls() -> None:
    verification = verify_shell_output_mechanism(_shell_evidence(call_shaped=True))
    assert verification.accepted is True, verification.missing
    assert verification.status == "VERIFIED"
