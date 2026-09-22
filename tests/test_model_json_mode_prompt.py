"""JSON-mode requests must mention json, or the provider rejects every call.

DeepSeek (and several OpenAI-compatible gateways) answer HTTP 400 to
``response_format={"type": "json_object"}`` unless the prompt itself contains the
literal word ``json``:

    Prompt must contain the word 'json' in some form to use 'response_format'
    of type 'json_object'.

This product's prompts described the required schema in prose without ever using
that literal word, so **every** structured call failed at the provider, the retry
mis-read the error body as JSON, and the deterministic fallback silently produced
the whole report -- the model's participation was effectively zero.

These tests pin the precondition so that regression cannot silently reappear.
"""

from __future__ import annotations

from threat_report_agent.model_gateway import ModelGateway


def test_prompt_without_json_gets_the_instruction() -> None:
    messages = [{"role": "system", "content": "Return the schema fields only."}]
    patched = ModelGateway._ensure_json_mode_instruction(messages)
    assert len(patched) == 2
    blob = " ".join(str(item["content"]) for item in patched).casefold()
    assert "json" in blob


def test_prompt_already_mentioning_json_is_untouched() -> None:
    messages = [
        {"role": "system", "content": "Answer with a JSON object."},
        {"role": "user", "content": "plan the analysis"},
    ]
    patched = ModelGateway._ensure_json_mode_instruction(messages)
    assert patched == messages


def test_case_insensitive_detection() -> None:
    messages = [{"role": "system", "content": "Reply as Json."}]
    assert ModelGateway._ensure_json_mode_instruction(messages) == messages


def test_existing_messages_are_preserved_in_order() -> None:
    messages = [
        {"role": "system", "content": "You are an analyst."},
        {"role": "user", "content": "analyze"},
    ]
    patched = ModelGateway._ensure_json_mode_instruction(messages)
    assert patched[:2] == messages
    assert patched[2]["role"] == "user"


def test_hint_is_not_repeated_when_already_appended() -> None:
    messages: list[dict[str, object]] = [{"role": "system", "content": "no schema word"}]
    once = ModelGateway._ensure_json_mode_instruction(messages)  # type: ignore[arg-type]
    twice = ModelGateway._ensure_json_mode_instruction(once)  # type: ignore[arg-type]
    assert twice == once
