"""Persist HOW mint: recovered catalog facts become INVESTIGATED_MECHANISM claims.

This is not a second planner and not a second ClaimGate. AnalysisService still
owns InvestigationLoopDriver, Ghidra ingest, and work-ledger I/O. Persist HOW
skip (`resolve_persist_how_skip`) decides whether leftover TRACE may run;
this module decides how recovered HOW rows are projected into Claim specs and
the investigation snapshot. Ranked Ghidra symbols are emitted here so persist
HOW can join Process32 before claim mint; AnalysisService still owns the
SQLAlchemy ingest session.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Callable, Iterable, Mapping
import re

from threat_report_agent.facts.dataflow import (
    catalog_buffers_are_same_object,
    catalog_decode_output_to_process_command_relation,
    catalog_output_consumer_relation,
    is_named_decode_consumer_api,
    is_process_command_argument,
    is_process_execution_api,
)
from threat_report_agent.investigation import (
    InvestigationResult,
    InvestigationThreadState,
    MechanismPlaybookRegistry,
    Verifier,
    has_typed_process_execution_call,
    recovered_thread_parameter,
)
from threat_report_agent.facts.thread_start import recovered_thread_start_address
from threat_report_agent.models import Claim, new_id
from threat_report_agent.report.reporting import _address_lookup_keys, _thread_body_from_evidence
from threat_report_agent.semantic_predicates import normalize_api_symbol
from threat_report_agent.static.static_analysis import (
    is_process_command_candidate,
    projected_process_image_name,
)


class PersistHow:
    @classmethod
    def _is_process_creation_seed_row(cls, row: object) -> bool:
        if isinstance(row, Mapping):
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        else:
            kind = str(getattr(row, "kind", "") or "")
            raw = getattr(row, "value", None)
            value = raw if isinstance(raw, dict) else {}
        if kind == "process_creation_flags":
            return True
        if kind == "string":
            return bool(projected_process_image_name(value.get("text")))
        if kind == "api_argument_trace":
            command = value.get("command") or value.get("command_line") or value.get("image")
            flags = value.get("creation_flags") or value.get("flags")
            return bool(command) or bool(flags)
        if kind == "value_flow":
            return str(value.get("relation") or "") in {
                "command_to_process_sink",
                "decode_output_to_process_command",
            }
        if kind == "function_call":
            api = str(value.get("api") or value.get("name") or "").casefold()
            return "createprocess" in api or "shellexecute" in api or api == "winexec"
        return False

    _HTTP_TRANSPORT_API_RE = re.compile(
        r"(?i)\b("
        r"WinHttp(?:OpenRequest|SendRequest|ReceiveResponse|Connect|Open|"
        r"ReadData|AddRequestHeaders|QueryHeaders|CloseHandle|SetOption\w*)|"
        r"Internet(?:Open(?:Url)?[AW]?|Connect[AW]?|ReadFile)|"
        r"HttpSendRequest[AW]?"
        r")\b"
    )

    _HTTP_ENDPOINT_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"']{4,}")

    @classmethod
    def _decode_plaintext_texts(cls, value: Mapping[str, object]) -> list[str]:
        texts: list[str] = []
        for key in ("decoded_preview", "decoded_text", "plaintext", "text", "preview"):
            raw = value.get(key)
            if raw not in (None, ""):
                texts.append(str(raw))
        for item in value.get("decoded_strings") or ():
            if item not in (None, ""):
                texts.append(str(item))
        verification = value.get("verification")
        if isinstance(verification, Mapping):
            texts.extend(cls._decode_plaintext_texts(verification))
        return texts

    @classmethod
    def _is_rejected_http_plaintext(cls, text: object) -> bool:
        blob = str(text or "").strip().casefold()
        if not blob:
            return True
        if "export not found" in blob:
            return True
        if "cannot be run in dos mode" in blob:
            return True
        if blob.startswith("!this program"):
            return True
        return False

    @classmethod
    def _http_transport_api_names(cls, text: object) -> list[str]:
        if cls._is_rejected_http_plaintext(text):
            return []
        found: list[str] = []
        for match in cls._HTTP_TRANSPORT_API_RE.finditer(str(text or "")):
            name = match.group(1)
            if name and name not in found:
                found.append(name)
        return found

    @classmethod
    def _http_endpoints(cls, text: object) -> list[str]:
        if cls._is_rejected_http_plaintext(text):
            return []
        found: list[str] = []
        for match in cls._HTTP_ENDPOINT_RE.finditer(str(text or "")):
            endpoint = match.group(0).rstrip(").,;]")
            if endpoint and endpoint not in found:
                found.append(endpoint)
        return found

    @classmethod
    def _is_http_transport_seed_row(cls, row: object) -> bool:
        """Keep decoded WinHttp names/URLs. Reject DOS stub and missing-export strings."""
        if isinstance(row, Mapping):
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        else:
            kind = str(getattr(row, "kind", "") or "")
            raw = getattr(row, "value", None)
            value = raw if isinstance(raw, dict) else {}
        texts = cls._decode_plaintext_texts(value) if kind == "decode_result" else [
            str(value.get("text") or value.get("api") or value.get("name") or "")
        ]
        blob = " ".join(texts)
        if cls._is_rejected_http_plaintext(blob) and not cls._http_transport_api_names(blob) and not cls._http_endpoints(blob):
            return False
        if cls._http_transport_api_names(blob) or cls._http_endpoints(blob):
            return True
        if kind in {"function_call", "api_argument_trace"}:
            api = str(value.get("api") or value.get("name") or value.get("target_name") or "")
            return bool(cls._http_transport_api_names(api))
        return False

    _PPID_ENUM_API_MARKERS = (
        "process32first",
        "process32next",
        "createtoolhelp32snapshot",
    )

    @classmethod
    def _ppid_row_kind_value(cls, row: object) -> tuple[str, Mapping[str, object]]:
        if isinstance(row, Mapping):
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            return kind, value
        kind = str(getattr(row, "kind", "") or "")
        raw = getattr(row, "value", None)
        value = raw if isinstance(raw, dict) else {}
        return kind, value

    @classmethod
    def _is_process_enumeration_row(cls, row: object) -> bool:
        kind, value = cls._ppid_row_kind_value(row)
        if kind not in {"function_call", "api_argument_trace"}:
            return False
        blob = " ".join(
            str(value.get(key) or "")
            for key in ("api", "name", "text", "how", "summary", "preview")
        )
        folded = blob.casefold()
        return any(marker in folded for marker in cls._PPID_ENUM_API_MARKERS)

    @classmethod
    def _is_explorer_parent_string_row(cls, row: object) -> bool:
        kind, value = cls._ppid_row_kind_value(row)
        if kind != "string":
            return False
        return bool(re.search(r"(?i)\bexplorer\.exe\b", str(value.get("text") or "")))

    @classmethod
    def _is_parent_attribute_seed_row(cls, row: object) -> bool:
        """Keep UpdateProcThreadAttribute + parent attribute 0x00020000. Not OpenProcess alone."""
        if isinstance(row, Mapping):
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        else:
            kind = str(getattr(row, "kind", "") or "")
            raw = getattr(row, "value", None)
            value = raw if isinstance(raw, dict) else {}
        if kind == "value_flow":
            return str(value.get("relation") or "") == "parent_handle_to_attribute"
        if kind == "constant":
            return bool(cls._parent_process_attribute_token(value))
        if kind == "function_call":
            api = str(value.get("api") or value.get("name") or "").casefold()
            return "updateprocthreadattribute" in api
        if kind in {
            "api_argument_trace",
            "function_semantic_summary",
            "function_context",
        }:
            blob = " ".join(
                str(value.get(key) or "")
                for key in ("api", "name", "text", "how", "summary", "preview", "attribute")
            )
            if "updateprocthreadattribute" in blob.casefold() and cls._parent_process_attribute_token(
                value, blob
            ):
                return True
            if kind == "api_argument_trace":
                return bool(
                    cls._parent_process_attribute_token(value)
                    or (value.get("parent_selection") and value.get("attribute"))
                )
        return False

    @classmethod
    def _parent_process_attribute_token(
        cls,
        value: Mapping[str, object],
        extra_text: str = "",
    ) -> str:
        """PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is 0x00020000. Do not use 0x09080008."""
        blob = " ".join(
            (
                str(value.get("attribute") or ""),
                str(value.get("name") or ""),
                str(value.get("value") or ""),
                extra_text,
            )
        )
        folded = blob.casefold().replace(" ", "")
        if "0x09080008" in folded and "0x00020000" not in folded and "0x20000" not in folded:
            return ""
        if "proc_thread_attribute_parent_process" in blob.casefold():
            return "0x00020000"
        if re.search(r"(?i)(?:attribute\s*=\s*)?0x0*20000\b", blob):
            return "0x00020000"
        return ""

    @classmethod
    def _ppid_parent_image(cls, value: Mapping[str, object], extra_text: str = "") -> str:
        """Recover a parent image name. Handle identities are not parent identity."""
        for key in ("parent_selection", "parent_image", "parent_process", "parent"):
            raw = value.get(key)
            if isinstance(raw, Mapping):
                continue
            text = str(raw or "").strip()
            if not text or text.startswith("{") or "artifact_id" in text or "handle_id" in text:
                continue
            match = re.search(r"(?i)\bexplorer\.exe\b", text)
            if match:
                return "explorer.exe"
            if re.search(r"(?i)\.exe\b", text) and len(text) <= 80:
                return text
        blob = " ".join(
            (
                extra_text,
                str(value.get("text") or ""),
                str(value.get("summary") or ""),
                str(value.get("preview") or ""),
            )
        )
        if re.search(r"(?i)\bexplorer\.exe\b", blob):
            return "explorer.exe"
        return ""

    @classmethod
    def _gate_for_seed_playbook(cls, playbook: object, evidence: Iterable[object]):
        """Evaluate ClaimGate against the seed playbook, not an artifact-wide best match.

        Verifier.evaluate() re-ranks every row. A decode seed that also contains
        GetProcAddress imports is then scored as DYNAMIC_API_RESOLUTION and never
        sees the persist-time XOR consumer contract.
        """
        if playbook is None:
            return None
        rows = [
            dict(row) if isinstance(row, Mapping) else row
            for row in evidence
            if isinstance(row, Mapping)
        ]
        return Verifier()._evaluate_playbook(rows, playbook)

    @classmethod
    def _creation_flags_text(cls, value: Mapping[str, object]) -> str:
        raw = value.get("creation_flags")
        if raw in (None, "", []):
            raw = value.get("flags")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        if isinstance(raw, int):
            return f"0x{raw & 0xFFFFFFFF:08x}"
        if isinstance(raw, Mapping):
            inner = raw.get("value") or raw.get("flags")
            if inner not in (None, ""):
                return str(inner).strip()
        if isinstance(raw, list):
            preferred = ""
            for item in raw:
                if isinstance(item, Mapping):
                    token = str(item.get("value") or "").strip()
                    names = {
                        str(name).upper()
                        for name in (item.get("set_flags") or ())
                        if isinstance(name, str)
                    }
                    if token and "EXTENDED_STARTUPINFO_PRESENT" in names:
                        return token
                    preferred = preferred or token
                elif item not in (None, ""):
                    preferred = preferred or str(item).strip()
            return preferred
        return ""

    @classmethod
    def _process_command_text(cls, value: Mapping[str, object]) -> str:
        for key in ("command", "command_line", "image"):
            text = str(value.get(key) or "").strip()
            if text and is_process_command_candidate(text):
                return text
        image = projected_process_image_name(value.get("text"))
        return image or ""

    @classmethod
    def _typed_process_command_text(cls, value: Mapping[str, object]) -> str:
        """A command only from a field that actually holds a command.

        NOT wired into the minting path -- kept because it is the right predicate for
        any *publication* decision, and it documents the distinction precisely.

        The distinction this encodes, established by measurement on task
        ``45cbd992``: that run has **30** ``api_argument_trace`` rows for
        ``CreateProcessW`` and **every one carries ``command: null``**. The only row
        in 38,407 that yields a command at all is a bare string literal
        ``{"encoding":"utf-16le","text":"FoxitPDFReader.exe"}``, reached through
        ``_process_command_text``'s ``value["text"]`` fallback. So "mint a HOW row
        from flags + an image string" (intentional, tested behaviour) and "publish a
        *recovered process command line*" are different claims, and only the second
        one requires a typed ``command``/``command_line`` value.

        Reverting note: an earlier attempt wired this into
        ``_recovered_process_how_fields`` and broke three deliberate tests
        (``test_persist_how_claim_specs_mint_process_from_flags_and_image_string``,
        ``test_process_seed_stamp_and_emu_from_flags_and_foxit_string``,
        ``test_persist_how_prefers_recovered_flags_over_specialist_token``). The
        minting behaviour is intended; the publication wording is what needs to
        change, at the renderer, where provenance is actually decided.
        """
        for key in ("command", "command_line", "image"):
            text = str(value.get(key) or "").strip()
            if text and is_process_command_candidate(text):
                return text
        return ""

    @classmethod
    def _preferred_process_command(cls, candidates: Iterable[str]) -> str:
        """Prefer the most specific non-shell command string.

        Plan §2 #2: no sample-specific preference. The previous version preferred
        any candidate containing a particular sample's name, which is exactly the
        cross-sample residue the plan forbids; longest-wins over non-explorer
        candidates is the generic rule.
        """
        names = [item for item in candidates if str(item or "").strip()]
        if not names:
            return ""
        non_explorer = [item for item in names if "explorer.exe" not in item.casefold()]
        if non_explorer:
            return max(non_explorer, key=len)
        return names[0]

    @classmethod
    def _preferred_process_flags(cls, candidates: Iterable[str]) -> str:
        """Pick a flag word only from candidates that pass the credibility gate.

        Audit finding (this was a real defect): the previous version selected the
        first candidate whose immediate merely had bit 19 set. `0x000f4240`
        (1,000,000 ms, a WaitForSingleObject timeout) has that bit by coincidence,
        so it was written into `creation_flags=` HOW even though the verifier and
        the report footer both rejected it — violating plan §2 prohibition #3 and
        §7.2. The specialist token `0x09080008` is also no longer preferred by
        name: hardcoding it is sample-specific (plan §2 #4) and it must not be
        stamped as dwCreationFlags on its own.
        """
        from threat_report_agent.static.static_analysis import (  # deferred: avoid import cycle
            credible_windows_process_creation_flags,
            is_specialist_ppid_creation_flag,
        )

        unique = [str(item).strip() for item in candidates if str(item or "").strip()]
        unique = list(dict.fromkeys(unique))
        # The specialist PPID remainder token is not a dwCreationFlags argument on
        # its own. That rule already exists as a named predicate in static_analysis,
        # so use it rather than hardcoding the literal (plan §2 #4).
        ordered = [item for item in unique if not is_specialist_ppid_creation_flag(item)]
        ordered += [item for item in unique if is_specialist_ppid_creation_flag(item)]
        for token in ordered:
            try:
                value = int(token, 16) & 0xFFFFFFFF
            except ValueError:
                continue
            if credible_windows_process_creation_flags(value):
                return token
        return ""

    @classmethod
    def _recovered_process_how_fields(cls, evidence: Iterable[object]) -> dict[str, str]:
        commands: list[str] = []
        flag_candidates: list[str] = []
        api = "CreateProcess"
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            command = cls._process_command_text(value)
            if command:
                commands.append(command)
            token = cls._creation_flags_text(value)
            if token:
                flag_candidates.append(token)
            api_name = str(
                value.get("api") or value.get("target_name") or value.get("target_function") or ""
            ).strip()
            if "createprocess" in api_name.casefold() or "shellexecute" in api_name.casefold():
                api = api_name
        fallback = ""
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            relation = str(value.get("relation") or "").casefold()
            if relation in {
                "createprocess_failure_to_schtasks",
                "process_failure_to_scheduled_task",
            }:
                fallback = "schtasks"
                break
        return {
            "command": cls._preferred_process_command(commands),
            "flags": cls._preferred_process_flags(flag_candidates),
            "api": api,
            "fallback": fallback,
        }

    @classmethod
    def _buffer_identity_from_value(cls, value: Mapping[str, object], *keys: str) -> dict[str, object] | None:
        for key in keys:
            buffer = value.get(key)
            if isinstance(buffer, Mapping) and buffer.get("address") not in (None, ""):
                return dict(buffer)
        return None

    @classmethod
    def _with_cataloged_decode_process_joins(
        cls,
        rows: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Mint same-buffer decode→process Join rows when persist sees both identities."""
        seen: set[tuple[str, str]] = set()
        decode_items: list[tuple[str, dict[str, object], Mapping[str, object]]] = []
        process_items: list[tuple[str, dict[str, object], Mapping[str, object]]] = []
        for row in rows:
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            row_id = str(row.get("id") or "").strip()
            relation = str(value.get("relation") or "")
            if relation == "decode_output_to_process_command":
                seen.add(
                    (
                        str(value.get("source_evidence_id") or ""),
                        str(value.get("target_evidence_id") or ""),
                    )
                )
            if not row_id:
                continue
            artifact_id = row.get("artifact_id")
            if kind in {"decode_result", "encoded_blob"}:
                buffer = cls._buffer_identity_from_value(value, "output_buffer")
                if buffer is not None:
                    if artifact_id and not buffer.get("artifact_id"):
                        buffer["artifact_id"] = artifact_id
                    decode_items.append((row_id, buffer, value))
            if kind in {"api_argument_trace", "function_call"}:
                api = str(
                    value.get("api")
                    or value.get("target_name")
                    or value.get("target_function")
                    or value.get("consumer")
                    or ""
                )
                if not is_process_execution_api(api):
                    continue
                buffer = cls._buffer_identity_from_value(value, "command_buffer")
                if buffer is None:
                    index = value.get("argument_index", value.get("index"))
                    if (
                        str(value.get("source_role") or "") == "decoded_output"
                        and is_process_command_argument(api, index)
                    ):
                        buffer = cls._buffer_identity_from_value(
                            value, "source_buffer", "input_buffer"
                        )
                if buffer is not None:
                    if artifact_id and not buffer.get("artifact_id"):
                        buffer["artifact_id"] = artifact_id
                    process_items.append((row_id, buffer, value))
        extra: list[dict[str, object]] = []
        for decode_id, output_buffer, decode_value in decode_items:
            plaintext = (
                decode_value.get("decoded_text")
                or decode_value.get("plaintext")
                or decode_value.get("decoded_preview")
            )
            for process_id, command_buffer, process_value in process_items:
                key = (decode_id, process_id)
                if key in seen:
                    continue
                relation = catalog_decode_output_to_process_command_relation(
                    decode_id=decode_id,
                    process_id=process_id,
                    output_buffer=output_buffer,
                    command_buffer=command_buffer,
                    plaintext=plaintext,
                    command=(
                        process_value.get("command")
                        or process_value.get("command_line")
                        or process_value.get("image")
                    ),
                )
                if relation is None:
                    continue
                api_name = str(
                    process_value.get("api")
                    or process_value.get("target_name")
                    or process_value.get("consumer")
                    or ""
                ).rsplit("!", 1)[-1]
                if api_name:
                    relation["api"] = api_name
                    relation["consumer"] = api_name
                extra.append(
                    {
                        "id": f"join-{decode_id}-{process_id}",
                        "kind": "value_flow",
                        "nature": "STATIC_INFERRED",
                        "value": relation,
                    }
                )
                seen.add(key)
        if not extra:
            return rows
        return [*rows, *extra]

    @classmethod
    def _with_cataloged_decode_consumer_joins(
        cls,
        rows: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Mint same-buffer decode→named-API Join rows (WinHTTP, VirtualAlloc, APC)."""
        seen: set[tuple[str, str]] = set()
        decode_items: list[tuple[str, dict[str, object], Mapping[str, object]]] = []
        consumer_items: list[tuple[str, dict[str, object], Mapping[str, object]]] = []
        for row in rows:
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            row_id = str(row.get("id") or "").strip()
            relation = str(value.get("relation") or "")
            if relation in {"output_to_consumer", "decode_output_to_process_command"}:
                seen.add(
                    (
                        str(
                            value.get("source_evidence_id")
                            or value.get("producer_evidence_id")
                            or ""
                        ),
                        str(
                            value.get("target_evidence_id")
                            or value.get("consumer_evidence_id")
                            or ""
                        ),
                    )
                )
            if not row_id:
                continue
            artifact_id = row.get("artifact_id")
            if kind in {"decode_result", "encoded_blob"}:
                buffer = cls._buffer_identity_from_value(value, "output_buffer")
                if buffer is not None:
                    if artifact_id and not buffer.get("artifact_id"):
                        buffer["artifact_id"] = artifact_id
                    decode_items.append((row_id, buffer, value))
            if kind not in {"api_argument_trace", "function_call"}:
                continue
            api = str(
                value.get("api")
                or value.get("target_name")
                or value.get("target_function")
                or value.get("consumer")
                or ""
            )
            if is_process_execution_api(api) or not is_named_decode_consumer_api(api):
                continue
            buffer = cls._buffer_identity_from_value(value, "input_buffer")
            if buffer is None and str(value.get("source_role") or "") == "decoded_output":
                buffer = cls._buffer_identity_from_value(value, "source_buffer")
            if buffer is None:
                continue
            if artifact_id and not buffer.get("artifact_id"):
                buffer["artifact_id"] = artifact_id
            consumer_items.append((row_id, buffer, value))
        extra: list[dict[str, object]] = []
        for decode_id, output_buffer, _decode_value in decode_items:
            for consumer_id, consumer_buffer, consumer_value in consumer_items:
                key = (decode_id, consumer_id)
                if key in seen:
                    continue
                if not catalog_buffers_are_same_object(output_buffer, consumer_buffer):
                    continue
                api_name = str(
                    consumer_value.get("api")
                    or consumer_value.get("target_name")
                    or consumer_value.get("consumer")
                    or ""
                ).rsplit("!", 1)[-1]
                relation = catalog_output_consumer_relation(
                    producer_id=decode_id,
                    consumer_id=consumer_id,
                    output_buffer=output_buffer,
                    consumer_api=api_name,
                )
                if relation is None:
                    continue
                extra.append(
                    {
                        "id": f"join-consumer-{decode_id}-{consumer_id}",
                        "kind": "value_flow",
                        "nature": "STATIC_INFERRED",
                        "value": relation,
                    }
                )
                seen.add(key)
        if not extra:
            return rows
        return [*rows, *extra]

    @classmethod
    def _decode_process_join_label(cls, evidence: Iterable[object]) -> str:
        """Join decode output to a process command or named consumer only with a buffer relation."""
        has_plain = False
        has_command = False
        has_process_join = False
        has_consumer_join = False
        has_named_consumer_call = False
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            relation = str(value.get("relation") or "")
            if relation == "decode_output_to_process_command":
                has_process_join = True
            if relation == "output_to_consumer" and cls._usable_decode_consumer(
                value.get("api") or value.get("consumer") or value.get("consumer_api")
            ):
                has_consumer_join = True
            plain = str(value.get("decoded_text") or value.get("plaintext") or "").strip()
            if plain:
                has_plain = True
            if cls._process_command_text(value):
                has_command = True
            if kind in {"function_call", "api_argument_trace"}:
                api = str(
                    value.get("api")
                    or value.get("target_name")
                    or value.get("target_function")
                    or ""
                )
                if is_named_decode_consumer_api(api) or is_process_execution_api(api):
                    has_named_consumer_call = True
        if has_process_join or has_consumer_join:
            return "JOINED_STATIC"
        if (has_plain and has_command) or (has_plain and has_named_consumer_call):
            return "UNKNOWN(join)"
        return ""

    _JOIN_ATTEMPT_ACTIONS = (
        "GET_DECOMPILE",
        "TRACE_API_ARGUMENT",
        "TRACE_RETURN_VALUE",
        "CONTROLLED_EMULATE",
    )

    @classmethod
    def _attempted_join_actions(cls, evidence: Iterable[object]) -> str:
        """Project recorded join attempts. Do not invent GET_DECOMPILE/TRACE/EMU."""
        found: list[str] = []
        seen: set[str] = set()
        allowed = {item.casefold(): item for item in cls._JOIN_ATTEMPT_ACTIONS}
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            raw = (
                value.get("attempted_action_types")
                or value.get("attempted_actions")
                or value.get("actions_tried")
                or ()
            )
            if isinstance(raw, str):
                raw = [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]
            if not isinstance(raw, (list, tuple)):
                continue
            for item in raw:
                token = str(item or "").strip()
                canonical = allowed.get(token.casefold())
                if canonical is None or canonical in seen:
                    continue
                seen.add(canonical)
                found.append(canonical)
        return ",".join(found)

    @classmethod
    def _recovered_dynamic_api_how_fields(cls, evidence: Iterable[object]) -> dict[str, str]:
        module = ""
        api_name = ""
        consumer = ""
        resolver = ""
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            module = module or str(value.get("module_input") or value.get("module") or "").strip()
            candidate = str(
                value.get("api_name") or value.get("api_identity") or ""
            ).strip()
            if candidate.casefold() in {
                "getprocaddress",
                "loadlibrarya",
                "loadlibraryw",
                "ldrgetprocedureaddress",
            } or re.match(r"(?i)^(fun_|sub_|lab_|thunk_)", candidate):
                candidate = ""
            api_name = api_name or candidate
            consumer_candidate = str(
                value.get("consumer") or value.get("consumer_callsite") or ""
            ).strip()
            if re.match(r"(?i)^(fun_|sub_|lab_|thunk_)", consumer_candidate):
                consumer_candidate = ""
            consumer = consumer or consumer_candidate
            resolver_name = str(value.get("resolver") or "").strip()
            if resolver_name:
                resolver = resolver_name
        return {
            "module": module,
            "api_name": api_name,
            "consumer": consumer,
            "resolver": resolver,
        }

    @classmethod
    def _usable_decode_consumer(cls, raw: object) -> str:
        if isinstance(raw, Mapping):
            raw = (
                raw.get("api")
                or raw.get("function")
                or raw.get("consumer_api")
                or raw.get("consumer")
                or ""
            )
        name = str(raw or "").strip()
        if not name:
            return ""
        folded = name.casefold()
        if folded.startswith(("fun_", "dat_", "lab_", "sub_", "thunk_", "s_")):
            return ""
        if folded in {
            "lstrlena",
            "lstrlenw",
            "strlen",
            "wcslen",
            "decoded output consumer",
            "unknown(consumer)",
            "unknown",
            "not_identified",
            "not identified",
        }:
            return ""
        return name

    @classmethod
    def _recovered_decode_how_fields(cls, evidence: Iterable[object]) -> dict[str, str]:
        formula = ""
        plaintext = ""
        consumer = ""
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            formula = formula or str(value.get("formula") or value.get("algorithm") or "").strip()
            candidate_plain = str(
                value.get("decoded_text") or value.get("plaintext") or ""
            ).strip()
            folded_plain = candidate_plain.casefold()
            # Plan §2 #2: the previous version also excluded one specific sample's
            # file name here. That is cross-sample residue, so it is removed rather
            # than generalised — a recovered payload name is legitimate plaintext.
            if (
                candidate_plain
                and folded_plain not in {"sample.exe", "sample.dll", "malware.exe"}
            ):
                plaintext = plaintext or candidate_plain
            relation = str(value.get("relation") or "").strip()
            if relation == "output_to_consumer":
                consumer = consumer or cls._usable_decode_consumer(
                    value.get("api") or value.get("consumer") or value.get("consumer_api")
                )
            elif relation == "decode_output_to_process_command":
                consumer = consumer or cls._usable_decode_consumer(
                    value.get("api") or value.get("consumer") or value.get("consumer_api")
                )
                if not consumer:
                    consumer = "CreateProcessW"
        return {"formula": formula, "plaintext": plaintext, "consumer": consumer}

    @classmethod
    def _object_level_transport_apis(cls, evidence: Iterable[object]) -> list[str]:
        """Transport APIs a call actually binds -- not names that merely appear.

        Object level means either an ``api_argument_trace`` row for that API (a
        real call site with traced arguments) or a row that carries an explicit
        ``JOINED_STATIC`` marker together with an ``output_buffer`` /
        ``input_buffer`` identity pair.

        A transport API *name* sitting in decoded plaintext is recovered
        configuration and is still reported as such, but it says nothing about
        which call consumes which buffer, so it must not be promoted to the
        consumer (ADR-0035; plan 5.2/5.3 forbid calling string co-occurrence a
        Join).  The earlier preference-list selection of ``WinHttpSendRequest``
        was exactly that promotion.
        """
        bound: list[str] = []
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            candidates: list[str] = []
            if kind == "api_argument_trace":
                candidates.append(str(value.get("api") or value.get("name") or ""))
            marker_blob = " ".join(
                str(value.get(key) or "")
                for key in ("join_status", "status", "relation", "join")
            ).casefold()
            if (
                "joined_static" in marker_blob
                and value.get("output_buffer")
                and value.get("input_buffer")
            ):
                candidates.extend(cls._decode_plaintext_texts(value))
            for text in candidates:
                for name in cls._http_transport_api_names(text):
                    if name not in bound:
                        bound.append(name)
        return bound

    @classmethod
    def _recovered_http_how_fields(cls, evidence: Iterable[object]) -> dict[str, str]:
        """Project decoded WinHttp names and URLs. Do not invent IAT transport APIs.

        ``apis``/``endpoint``/``endpoints`` are recovered *configuration* and may
        come from decoded text.  ``consumer`` may not: it is only filled from
        :meth:`_object_level_transport_apis`, so an unbound name leaves the slot
        empty for the caller to render as ``UNKNOWN(consumer)``.
        """
        apis: list[str] = []
        endpoints: list[str] = []
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            texts = cls._decode_plaintext_texts(value)
            texts.append(
                str(value.get("api") or value.get("name") or value.get("target_name") or "")
            )
            for text in texts:
                for name in cls._http_transport_api_names(text):
                    if name not in apis:
                        apis.append(name)
                for endpoint in cls._http_endpoints(text):
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
        bound = cls._object_level_transport_apis(evidence)
        preferred = (
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "WinHttpOpenRequest",
            "WinHttpConnect",
            "WinHttpOpen",
        )
        consumer = next((item for item in preferred if item in bound), "")
        if not consumer:
            consumer = next(
                (
                    item
                    for item in bound
                    if "receive" in item.casefold() or "send" in item.casefold()
                ),
                bound[-1] if bound else "",
            )
        return {
            "apis": " -> ".join(apis[:8]),
            "endpoint": endpoints[0] if endpoints else "",
            "endpoints": "; ".join(endpoints[:4]),
            "consumer": consumer,
        }

    _ENVIRONMENT_PROBE_MARKERS = (
        "gettickcount64",
        "gettickcount",
        "isdebuggerpresent",
        "globalmemorystatusex",
        "virtualquery",
        "checkremotedebuggerpresent",
    )

    @classmethod
    def _environment_probe_api(cls, value: Mapping[str, object]) -> str:
        api = str(
            value.get("api")
            or value.get("name")
            or value.get("target_name")
            or value.get("target_function")
            or ""
        ).strip()
        folded = api.casefold()
        for marker in cls._ENVIRONMENT_PROBE_MARKERS:
            if marker in folded:
                return api.rsplit("!", 1)[-1] or api
        blob = " ".join(str(value.get(key) or "") for key in ("text", "how", "summary"))
        for marker in cls._ENVIRONMENT_PROBE_MARKERS:
            if marker in blob.casefold():
                return marker
        return ""

    @classmethod
    def _is_environment_probe_row(cls, row: Mapping[str, object]) -> bool:
        kind = str(row.get("kind") or "")
        if kind in {"import_symbol", "string"}:
            return False
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if kind in {"function_call", "api_argument_trace", "constant"}:
            return bool(cls._environment_probe_api(value) or value.get("threshold") or value.get("comparison"))
        if kind == "cfg_block":
            return bool(
                value.get("return_branch")
                or value.get("gated_behavior")
                or value.get("exit")
            )
        return False

    @classmethod
    def _recovered_environment_how_fields(cls, evidence: Iterable[object]) -> dict[str, str]:
        """Project probe API + threshold. Import listings are not anti-analysis."""
        api = ""
        threshold = ""
        branch = ""
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            api = api or cls._environment_probe_api(value)
            token = str(
                value.get("threshold") or value.get("comparison") or value.get("constant") or ""
            ).strip()
            if token and "unknown" not in token.casefold():
                if str(value.get("name") or "").casefold() in {"creation_flags", "flags"}:
                    continue
                threshold = threshold or token
            branch = branch or str(
                value.get("return_branch") or value.get("gated_behavior") or value.get("exit") or ""
            ).strip()
        return {
            "api": api,
            "threshold": threshold,
            "branch": branch,
        }

    @classmethod
    def _recovered_ppid_how_fields(cls, evidence: Iterable[object]) -> dict[str, str]:
        """Project recovered PPID chain facts. Do not invent 0x09080008."""
        apis: list[str] = []
        parent = ""
        flags = ""
        attribute = ""
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            api = str(value.get("api") or value.get("name") or "").strip()
            if api:
                apis.append(api)
            blob = " ".join(
                str(value.get(key) or "")
                for key in ("text", "how", "summary", "preview", "attribute")
            )
            for token in re.findall(
                r"(?i)OpenProcess|UpdateProcThreadAttribute|InitializeProcThreadAttributeList|CreateProcessW|CreateProcessA",
                blob,
            ):
                if token not in apis:
                    apis.append(token)
            attribute = attribute or cls._parent_process_attribute_token(value, blob)
            parent = parent or cls._ppid_parent_image(value, blob)
            flags = flags or str(
                value.get("creation_flags") or value.get("flags") or ""
            ).strip()
            if flags.replace(" ", "").casefold() == "0x09080008":
                flags = ""
            relation = str(value.get("relation") or "")
            if relation == "parent_handle_to_attribute" and not parent:
                parent = cls._ppid_parent_image(value, blob)
        unique_apis = list(dict.fromkeys(apis))
        return {
            "api": next((item for item in unique_apis if "createprocess" in item.casefold()), "") or (
                unique_apis[-1] if unique_apis else ""
            ),
            "parent": parent,
            "flags": flags,
            "attribute": attribute,
            # ``_parent_process_attribute_token`` returns the *immediate* because
            # that is what an analyst can grep an image for.  The symbolic name is
            # the form a detection rule is written against, and the report chapter
            # could not name it: the row that carries the recovered chain keeps
            # only ``attribute=0x00020000``, while the name lives in a separate
            # process-creation row.  Attaching it here keeps the fact and its
            # evidence on one row instead of making the renderer join across rows.
            "attribute_name": (
                "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" if attribute == "0x00020000" else ""
            ),
            "path": " -> ".join(unique_apis[:6]),
        }

    @classmethod
    def _investigated_mechanism_claim_fields(
        cls,
        playbook: object,
        evidence: Iterable[object],
        artifact_path: str,
    ) -> dict[str, object]:
        """Project persist-time HOW into a claim. Do not keyword-hijack PPID."""
        playbook_id = str(getattr(playbook, "id", "") or "")
        mechanism_type = str(getattr(playbook, "mechanism_type", "") or "").upper()
        path = str(artifact_path or "artifact")
        if playbook_id == "ppid-process-chain" or mechanism_type == "PPID_SPOOFING":
            how = cls._recovered_ppid_how_fields(evidence)
            recovered_path = how["path"]
            attribute = how["attribute"] or "UNKNOWN(attribute)"
            parent = how["parent"] or "UNKNOWN(parent identity)"
            if how.get("attribute_name") and attribute == "0x00020000":
                # Carry the symbolic form with the immediate in the same field, so
                # one recovered row publishes both the greppable value and the
                # name a detection rule targets.
                attribute = f"0x00020000 {how['attribute_name']}"
            mechanism = recovered_path or "UpdateProcThreadAttribute"
            mechanism += f"; attribute={attribute}; parent={parent}"
            return {
                "action": "may_spoof_parent_process",
                "object": parent,
                "mechanism": mechanism,
                "statement": (
                    f"{path} statically recovers a parent-process attribute chain "
                    f"`{mechanism}`; runtime parent identity is unverified."
                ),
                "attack_mapping": {
                    "technique_id": "T1134.004",
                    "name": "Parent PID Spoofing",
                    "status": "candidate",
                },
            }
        if playbook_id == "process-execution" or mechanism_type == "PROCESS_EXECUTION":
            how = cls._recovered_process_how_fields(evidence)
            command = how["command"] or "UNKNOWN(command)"
            flags = how["flags"] or "UNKNOWN(creation_flags)"
            fallback = how["fallback"] or "UNKNOWN(fallback)"
            return {
                "action": "may_create_process",
                "object": command,
                "mechanism": (
                    f"{how['api']} command={command}; creation_flags={flags}; "
                    f"fallback={fallback}"
                ),
                "statement": (
                    f"{path} statically recovers a child-process construction: "
                    f"command `{command}` with creation_flags `{flags}`; "
                    "runtime execution is unverified."
                ),
                "attack_mapping": {
                    "technique_id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "status": "candidate",
                },
            }
        if playbook_id == "dynamic-api-resolution" or mechanism_type == "DYNAMIC_API_RESOLUTION":
            how = cls._recovered_dynamic_api_how_fields(evidence)
            module = how["module"]
            api_name = how["api_name"] or "recovered API"
            consumer = how["consumer"] or "resolved pointer consumer"
            identity = f"{module}!{api_name}" if module else api_name
            mechanism_parts: list[str] = []
            if how["resolver"]:
                mechanism_parts.append(how["resolver"])
            if module:
                mechanism_parts.append(f"module={module}")
            mechanism_parts.append(f"api={api_name}")
            mechanism_parts.append(f"consumer={consumer}")
            return {
                "action": "may_resolve_api_dynamically",
                "object": identity,
                "mechanism": " ".join(mechanism_parts),
                "statement": (
                    f"{path} statically recovers a dynamic API resolution: "
                    f"`{identity}` consumed by `{consumer}`; "
                    "runtime loading is unverified."
                ),
                "attack_mapping": {},
            }
        if playbook_id == "xor-config-recovery" or mechanism_type == "DECODE_CONFIG":
            how = cls._recovered_decode_how_fields(evidence)
            formula = how["formula"] or "recovered decode formula"
            consumer = how["consumer"] or "UNKNOWN(consumer)"
            plaintext = how["plaintext"]
            mechanism_parts = [formula]
            if plaintext:
                mechanism_parts.append(f"plaintext=`{plaintext}`")
            mechanism_parts.append(f"consumer={consumer}")
            statement = (
                f"{path} statically recovers a decode path using `{formula}` "
                f"consumed by `{consumer}`"
            )
            if plaintext:
                statement += f"; plaintext begins `{plaintext[:48]}`"
            statement += "; runtime use of the plaintext is unverified."
            return {
                "action": "may_decode_configuration",
                "object": plaintext or "decoded configuration buffer",
                "mechanism": " ".join(mechanism_parts),
                "statement": statement,
                "attack_mapping": {},
            }
        if playbook_id == "http-download" or mechanism_type == "HTTP_DOWNLOAD":
            how = cls._recovered_http_how_fields(evidence)
            endpoint = how["endpoint"] or "UNKNOWN(endpoint)"
            apis = how["apis"] or "UNKNOWN(transport API)"
            consumer = how["consumer"] or "UNKNOWN(response consumer)"
            # ``request=recovered`` used to be decided by transport API *names*
            # appearing in decoded text, which is the same string co-occurrence
            # ADR-0035 forbids for a consumer.  A request body/verb may only be
            # called recovered when a call actually binds it at argument level.
            bound_blob = " ".join(cls._object_level_transport_apis(evidence)).casefold()
            request = (
                "recovered"
                if (
                    "winhttpopenrequest" in bound_blob
                    or "winhttpsendrequest" in bound_blob
                    or "httpsendrequest" in bound_blob
                    or "internetopenurl" in bound_blob
                )
                else "UNKNOWN(request)"
            )
            return {
                "action": "may_download_over_http",
                "object": endpoint,
                "mechanism": (
                    f"{apis}; endpoint={endpoint}; request={request}; consumer={consumer}"
                ),
                "statement": (
                    f"{path} statically recovers decoded HTTP transport APIs "
                    f"`{apis}` and endpoint `{endpoint}`; "
                    "runtime network access was not performed."
                ),
                "attack_mapping": {
                    "technique_id": "T1071",
                    "name": "Application Layer Protocol",
                    "status": "candidate",
                },
            }
        if playbook_id == "v3-environment-guard" or mechanism_type == "ENVIRONMENT_GUARD":
            how = cls._recovered_environment_how_fields(evidence)
            api = how["api"] or "UNKNOWN(probe)"
            threshold = how["threshold"] or "UNKNOWN(threshold)"
            branch = how["branch"] or "UNKNOWN(exit)"
            return {
                "action": "may_probe_environment",
                "object": api,
                "mechanism": f"{api}; threshold={threshold}; exit={branch}",
                "statement": (
                    f"{path} statically recovers an environment probe `{api}` "
                    f"with threshold `{threshold}`; "
                    "a probe API is not a proven anti-analysis gate."
                ),
                "attack_mapping": {},
            }
        return {
            "action": "exhibits_static_mechanism",
            "object": "ordered static behavior indicators",
            "mechanism": (
                "multiple independent static observations correlated by investigation actions"
            ),
            "statement": (
                f"{path} has an evidence-backed static mechanism hypothesis; "
                "runtime execution remains unverified."
            ),
            "attack_mapping": {},
        }

    @classmethod
    def _how_recovery_evidence(
        cls,
        playbook_id: str,
        evidence: Iterable[object],
    ) -> list[dict[str, object]]:
        """Typed persist HOW only. Same-seed IAT/PPID traces are not GetProcAddress exports."""
        mapped = [
            item
            for item in (cls._investigation_row_mapping(row) for row in evidence)
            if item is not None
        ]
        if playbook_id not in cls._PERSIST_HOW_PLAYBOOKS:
            return mapped
        return cls._persist_how_rows_for_playbook(playbook_id, mapped)

    @classmethod
    def _catalog_candidate_mechanism_fields(
        cls,
        playbook: object,
        evidence: Iterable[object],
        artifact_path: str,
    ) -> dict[str, object]:
        """Fill snapshot HOW fields when ClaimGate accepted without a specialist."""
        playbook_id = str(getattr(playbook, "id", "") or "")
        how_evidence = cls._how_recovery_evidence(playbook_id, evidence)
        evidence_ids = [
            str(row.get("id"))
            for row in how_evidence
            if str(row.get("id") or "").strip()
        ][:12]
        if playbook_id == "process-execution":
            how = cls._recovered_process_how_fields(how_evidence)
            command = how["command"] or "UNKNOWN(command)"
            claim = cls._investigated_mechanism_claim_fields(
                playbook, how_evidence, artifact_path
            )
            return {
                "target": artifact_path,
                "mechanism_type": "PROCESS_EXECUTION",
                "inputs": [command],
                "transformation_or_control": [str(claim["mechanism"])],
                "conditions": [
                    "static argument recovery; runtime execution is not observed"
                ],
                "outputs": ["process object / handle"],
                "consumers": [command],
                "side_effects": ["may start a child process if executed"],
                "evidence_ids": evidence_ids,
            }
        if playbook_id == "dynamic-api-resolution":
            how = cls._recovered_dynamic_api_how_fields(how_evidence)
            module = how["module"]
            api_name = how["api_name"] or "recovered API"
            consumer = how["consumer"] or "resolved pointer consumer"
            inputs = [item for item in (module, api_name) if item] or [api_name]
            claim = cls._investigated_mechanism_claim_fields(
                playbook, how_evidence, artifact_path
            )
            return {
                "target": artifact_path,
                "mechanism_type": "DYNAMIC_API_RESOLUTION",
                "inputs": inputs,
                "transformation_or_control": [str(claim["mechanism"])],
                "conditions": [
                    "static resolver/module/entry ordering is recovered; runtime loading is not observed"
                ],
                "outputs": ["resolved function address"],
                "consumers": [consumer],
                "side_effects": ["may load a secondary module and prepare a resolved entry point"],
                "evidence_ids": evidence_ids,
            }
        if playbook_id == "xor-config-recovery":
            how = cls._recovered_decode_how_fields(how_evidence)
            formula = how["formula"] or "recovered decode formula"
            consumer = how["consumer"] or "UNKNOWN(consumer)"
            return {
                "target": artifact_path,
                "mechanism_type": "DECODE_CONFIG",
                "inputs": [how["plaintext"] or "encoded buffer"],
                "transformation_or_control": [formula],
                "conditions": ["bounded static decode; runtime use is not observed"],
                "outputs": [how["plaintext"] or "decoded buffer"],
                "consumers": [consumer],
                "side_effects": ["may materialize decoded configuration for a later consumer"],
                "evidence_ids": evidence_ids,
            }
        if playbook_id == "http-download":
            how = cls._recovered_http_how_fields(how_evidence)
            endpoint = how["endpoint"] or "UNKNOWN(endpoint)"
            apis = how["apis"] or "UNKNOWN(transport API)"
            consumer = how["consumer"] or "UNKNOWN(response consumer)"
            claim = cls._investigated_mechanism_claim_fields(
                playbook, how_evidence, artifact_path
            )
            return {
                "target": artifact_path,
                "mechanism_type": "HTTP_DOWNLOAD",
                "inputs": [endpoint] if how["endpoint"] else ["UNKNOWN(endpoint)"],
                "transformation_or_control": [str(claim["mechanism"])],
                "conditions": [
                    "decoded transport API names and endpoints; runtime network access was not performed"
                ],
                "outputs": ["UNKNOWN(response bytes)"],
                "consumers": [consumer],
                "side_effects": ["may receive response bytes; network access was not performed"],
                "evidence_ids": evidence_ids,
            }
        if playbook_id == "v3-environment-guard":
            how = cls._recovered_environment_how_fields(how_evidence)
            api = how["api"] or "UNKNOWN(probe)"
            threshold = how["threshold"] or "UNKNOWN(threshold)"
            claim = cls._investigated_mechanism_claim_fields(
                playbook, how_evidence, artifact_path
            )
            return {
                "target": artifact_path,
                "mechanism_type": "ENVIRONMENT_GUARD",
                "inputs": [api],
                "transformation_or_control": [str(claim["mechanism"])],
                "conditions": [
                    "static probe recovery; a probe API is not a proven anti-analysis gate"
                ],
                "outputs": [threshold],
                "consumers": [how["branch"] or "UNKNOWN(exit)"],
                "side_effects": ["may skip or exit if a comparison later gates control flow"],
                "evidence_ids": evidence_ids,
            }
        if playbook_id == "ppid-process-chain":
            how = cls._recovered_ppid_how_fields(how_evidence)
            parent = how["parent"] or "UNKNOWN(parent)"
            claim = cls._investigated_mechanism_claim_fields(
                playbook, how_evidence, artifact_path
            )
            return {
                "target": artifact_path,
                "mechanism_type": "PPID_SPOOFING",
                "inputs": [parent],
                "transformation_or_control": [str(claim["mechanism"])],
                "conditions": [
                    "parent-process attribute recovered statically; runtime spoof and parent identity are unverified"
                ],
                "outputs": [parent],
                "consumers": [how["api"] or "CreateProcess"],
                "side_effects": ["may select an alternate parent if executed"],
                "unknowns": (
                    ["parent identity not recovered"]
                    if not how["parent"]
                    else []
                ),
                "missing_fields": (
                    ["parent identity"] if not how["parent"] else []
                ),
                "evidence_ids": evidence_ids,
            }
        if playbook_id == "unique-os-thread":
            starts: list[str] = []
            apis: list[str] = []
            parameters: list[str] = []
            for row in evidence:
                if not isinstance(row, Mapping):
                    continue
                value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
                start = recovered_thread_start_address(value)
                if not start:
                    continue
                starts.append(start)
                apis.append(str(value.get("api") or "CreateThread"))
                parameters.append(recovered_thread_parameter(value) or "UNKNOWN(parameter)")
            if not starts:
                return {"target": artifact_path, "evidence_ids": evidence_ids}
            api = apis[0]
            start = starts[0]
            parameter = parameters[0]
            evidence_by_id = {
                str(item.get("id") or ""): item
                for item in evidence
                if isinstance(item, Mapping) and str(item.get("id") or "").strip()
            }
            loop, exit_cond, shared = _thread_body_from_evidence(evidence_by_id, start)
            transform_parts = [
                f"{api} lpStartAddress={start}",
                f"lpParameter={parameter}",
                f"loop={loop or 'UNKNOWN(loop)'}",
                f"exit={exit_cond or 'UNKNOWN(exit)'}",
            ]
            if shared and not str(shared).startswith("UNKNOWN"):
                transform_parts.append(f"shared_state={shared}")
            return {
                "target": artifact_path,
                "mechanism_type": "THREAD_CALLBACK",
                "inputs": [parameter],
                "transformation_or_control": ["; ".join(transform_parts)],
                "conditions": [
                    "static thread-start recovery; runtime start is not observed"
                ],
                "outputs": [start],
                "consumers": [start],
                "side_effects": ["may start a same-process OS thread if executed"],
                "evidence_ids": evidence_ids,
            }
        return {
            "target": artifact_path,
            "evidence_ids": evidence_ids,
        }

    _PERSIST_HOW_PLAYBOOKS = (
        "process-execution",
        "dynamic-api-resolution",
        "xor-config-recovery",
        "http-download",
        "ppid-process-chain",
        "v3-environment-guard",
    )

    _PERSIST_HOW_CLAIM_MODULES = {
        "process-execution": "execution",
        "dynamic-api-resolution": "loader",
        "xor-config-recovery": "decryption",
        "http-download": "c2_network",
        "ppid-process-chain": "identity",
        "v3-environment-guard": "anti_analysis",
        "unique-os-thread": "execution",
        "communication-loop": "c2_network",
        "defender-modification": "anti_analysis",
        "file-operations": "execution",
        "relation-timing": "execution",
    }

    _NAMED_API_CLAIM_SKIP = frozenset(
        {
            "getprocaddress",
            "loadlibrarya",
            "loadlibraryw",
            "loadlibraryexa",
            "loadlibraryexw",
            "ldrgetprocedureaddress",
            "getmodulehandlea",
            "getmodulehandlew",
        }
    )

    _HOW_PLAYBOOK_IDS = frozenset(
        (
            *_PERSIST_HOW_PLAYBOOKS,
            "http-download",
            "ppid-process-chain",
            "unique-os-thread",
        )
    )

    @classmethod
    def _investigation_row_mapping(cls, row: object) -> dict[str, object] | None:
        if isinstance(row, Mapping):
            mapped = dict(row)
            if str(mapped.get("id") or "").strip() and str(mapped.get("kind") or "").strip():
                return mapped
            return None
        row_id = str(getattr(row, "id", "") or "").strip()
        kind = str(getattr(row, "kind", "") or "").strip()
        if not row_id or not kind:
            return None
        return {
            "id": row_id,
            "kind": kind,
            "nature": str(getattr(row, "nature", "") or ""),
            "value": getattr(row, "value", {}) or {},
            "anchor": getattr(row, "anchor", {}) or {},
        }

    @classmethod
    def _persist_how_rows_for_playbook(
        cls,
        playbook_id: str,
        rows: Iterable[Mapping[str, object]],
    ) -> list[dict[str, object]]:
        selected: list[dict[str, object]] = []
        for row in rows:
            kind = str(row.get("kind") or "")
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            relation = str(value.get("relation") or "")
            if playbook_id == "process-execution":
                api_name = str(
                    value.get("api") or value.get("target_name") or value.get("target_function") or ""
                ).casefold()
                if kind == "api_argument_trace" and (
                    "createprocess" in api_name
                    or value.get("command")
                    or value.get("command_line")
                    or value.get("creation_flags")
                    or value.get("flags")
                ):
                    selected.append(dict(row))
                elif kind == "process_creation_flags":
                    selected.append(dict(row))
                elif kind == "string" and projected_process_image_name(value.get("text")):
                    selected.append(dict(row))
                elif kind == "value_flow" and relation in {
                    "command_to_process_sink",
                    "decode_output_to_process_command",
                }:
                    selected.append(dict(row))
                elif kind == "function_call" and "createprocess" in api_name:
                    selected.append(dict(row))
            elif playbook_id == "dynamic-api-resolution":
                if kind == "resolved_api" and (
                    value.get("module_input") or value.get("api_name") or value.get("api_identity")
                ):
                    selected.append(dict(row))
                elif kind == "value_flow" and relation == "resolved_pointer_to_call":
                    selected.append(dict(row))
            elif playbook_id == "xor-config-recovery":
                if kind in {"decode_result", "encoded_blob", "data_reference"}:
                    selected.append(dict(row))
                elif kind == "value_flow" and relation in {
                    "output_to_consumer",
                    "decode_output_to_process_command",
                }:
                    selected.append(dict(row))
            elif playbook_id == "http-download":
                if cls._is_http_transport_seed_row(row):
                    selected.append(dict(row))
            elif playbook_id == "ppid-process-chain":
                if cls._is_parent_attribute_seed_row(row):
                    selected.append(dict(row))
                elif cls._is_process_enumeration_row(row) or cls._is_explorer_parent_string_row(row):
                    selected.append(dict(row))
            elif playbook_id == "v3-environment-guard":
                if cls._is_environment_probe_row(row):
                    selected.append(dict(row))
        if playbook_id == "ppid-process-chain":
            has_enum = any(cls._is_process_enumeration_row(item) for item in selected)
            if not has_enum:
                selected = [
                    item
                    for item in selected
                    if not cls._is_explorer_parent_string_row(item)
                ]
        if playbook_id == "process-execution" and selected:
            how = cls._recovered_process_how_fields(selected)
            if not has_typed_process_execution_call(selected) and not (
                how.get("command") or how.get("flags")
            ):
                return []
        return selected

    @classmethod
    def _persist_partial_how_ready(
        cls,
        playbook_id: str,
        evidence: Iterable[object],
    ) -> bool:
        """True when persist recovered enough HOW to mint CANDIDATE without TRACE.

        Kunglao DISPATCH_VERIFIER: a named API plus consumer is a claim, not a
        reason to spend leftover TRACE hoping LoadLibrary appears. TRACE after
        Ghidra persist cannot invent module_input or a transport API.
        """
        rows = [
            mapped
            for mapped in (cls._investigation_row_mapping(item) for item in evidence)
            if mapped is not None
        ]
        selected = cls._persist_how_rows_for_playbook(playbook_id, rows)
        if playbook_id == "process-execution":
            how = cls._recovered_process_how_fields(selected)
            return bool(how.get("command") or how.get("flags"))
        if playbook_id == "dynamic-api-resolution":
            how = cls._recovered_dynamic_api_how_fields(selected)
            return bool(how.get("api_name") and (how.get("consumer") or how.get("module")))
        if playbook_id == "xor-config-recovery":
            how = cls._recovered_decode_how_fields(selected)
            return bool(how.get("formula") or how.get("plaintext"))
        if playbook_id == "http-download":
            how = cls._recovered_http_how_fields(selected)
            return bool(how.get("apis"))
        if playbook_id == "ppid-process-chain":
            how = cls._recovered_ppid_how_fields(selected)
            if not how.get("attribute"):
                return False
            blob = " ".join(
                str(item.get("kind") or "") + " " + str(item.get("value") or "")
                for item in selected
                if isinstance(item, Mapping)
            ).casefold()
            return (
                "updateprocthreadattribute" in blob
                or "parent_handle_to_attribute" in blob
                or "proc_thread_attribute_parent_process" in blob
            )
        if playbook_id == "v3-environment-guard":
            how = cls._recovered_environment_how_fields(selected)
            return bool(how.get("api"))
        return False

    @classmethod
    def _persist_how_claim_specs(
        cls,
        *,
        artifact_path: str,
        evidence: Iterable[object],
    ) -> list[tuple[object, dict[str, object], tuple[str, ...]]]:
        """Kunglao DISPATCH_VERIFIER: persist recovered facts as claims now.

        The static worker already wrote HOW rows. Waiting for investigation
        TRACE / leftover-64 to mint INVESTIGATED_MECHANISM left one-round
        reports empty when budget died on sibling threads. Do not introduce a
        second claim-register engine; reuse ClaimGate on the seed playbook.
        """
        rows = [
            mapped
            for mapped in (cls._investigation_row_mapping(item) for item in evidence)
            if mapped is not None
        ]
        if not rows:
            return []
        rows = cls._with_cataloged_decode_process_joins(rows)
        rows = cls._with_cataloged_decode_consumer_joins(rows)
        registry = MechanismPlaybookRegistry()
        specs: list[tuple[object, dict[str, object], tuple[str, ...]]] = []
        for playbook_id in cls._PERSIST_HOW_PLAYBOOKS:
            playbook = registry.by_id(playbook_id)
            if playbook is None:
                continue
            selected = cls._persist_how_rows_for_playbook(playbook_id, rows)
            if not selected:
                continue
            for group in cls._persist_how_row_groups(playbook_id, selected):
                entry = registry.behavior_entry(playbook_id)
                catalog_ready = False
                evaluate = getattr(getattr(entry, "contract", None), "evaluate", None)
                if callable(evaluate):
                    catalog_ready = bool(getattr(evaluate(group), "accepted", False))
                seed_gate = cls._gate_for_seed_playbook(playbook, group)
                # Kunglao DISPATCH_VERIFIER: recovered command / named API+consumer
                # / decode formula is enough to mint CANDIDATE. Specialist or
                # catalog failure must not hide those facts or send leftover TRACE
                # to invent module_input.
                if not catalog_ready and (seed_gate is None or not seed_gate.accepted):
                    if not cls._persist_partial_how_ready(playbook_id, group):
                        continue
                fields = cls._investigated_mechanism_claim_fields(
                    playbook,
                    group,
                    artifact_path,
                )
                evidence_ids = tuple(
                    str(item.get("id"))
                    for item in group
                    if str(item.get("id") or "").strip()
                )[:16]
                if not evidence_ids:
                    continue
                specs.append((playbook, fields, evidence_ids))
        specs.extend(cls._persist_unique_thread_claim_specs(artifact_path, rows))
        specs.extend(cls._persist_communication_loop_claim_specs(artifact_path, rows))
        specs.extend(cls._persist_defender_claim_specs(artifact_path, rows))
        specs.extend(cls._persist_file_drop_claim_specs(artifact_path, rows))
        specs.extend(cls._persist_relation_timing_claim_specs(artifact_path, rows))
        join = cls._decode_process_join_label(rows)
        attempted = cls._attempted_join_actions(rows)
        if join:
            join_token = join
            if join.startswith("UNKNOWN") and attempted:
                join_token = f"{join} attempted={attempted}"
            for _playbook, fields, _ids in specs:
                playbook_id = str(getattr(_playbook, "id", "") or "")
                if playbook_id not in {"process-execution", "xor-config-recovery"}:
                    continue
                mechanism = str(fields.get("mechanism") or "")
                if join_token not in mechanism:
                    fields["mechanism"] = f"{mechanism}; {join_token}".strip("; ")
                statement = str(fields.get("statement") or "")
                if join not in statement:
                    fields["statement"] = f"{statement} join `{join_token}`.".strip()
        return specs

    @classmethod
    def _persist_unique_thread_claim_specs(
        cls,
        artifact_path: str,
        rows: Iterable[Mapping[str, object]],
    ) -> list[tuple[object, dict[str, object], tuple[str, ...]]]:
        """Kunglao DISPATCH_VERIFIER: recovered lpStartAddress is a claim now.

        Unique OS-thread seeds have no typed playbook, so TRACE burned the
        leftover 64 on GET_CALLEES and the one-round report listed
        UNKNOWN(start_routine) even after persist stamped CreateThread
        arguments. Do not invent a start address.
        """
        playbook = SimpleNamespace(id="unique-os-thread", mechanism_type="THREAD_CALLBACK")
        specs: list[tuple[object, dict[str, object], tuple[str, ...]]] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            if str(row.get("kind") or "") != "api_argument_trace":
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            start = recovered_thread_start_address(value)
            if not start:
                continue
            api = str(value.get("api") or "CreateThread")
            key = (normalize_api_symbol(api), start.casefold())
            if key in seen:
                continue
            seen.add(key)
            parameter = recovered_thread_parameter(value) or "UNKNOWN(parameter)"
            evidence_id = str(row.get("id") or "").strip()
            if not evidence_id:
                continue
            evidence_by_id = {
                str(item.get("id") or ""): item
                for item in rows
                if str(item.get("id") or "").strip()
            }
            loop, exit_cond, shared = _thread_body_from_evidence(evidence_by_id, start)
            mechanism_parts = [
                f"{api} lpStartAddress={start}",
                f"lpParameter={parameter}",
                f"loop={loop or 'UNKNOWN(loop)'}",
                f"exit={exit_cond or 'UNKNOWN(exit)'}",
            ]
            if shared and not str(shared).startswith("UNKNOWN"):
                mechanism_parts.append(f"shared_state={shared}")
            start_keys = set(_address_lookup_keys(start))
            body_ids: list[str] = []
            for item in rows:
                kind = str(item.get("kind") or "")
                if kind not in {
                    "function_context",
                    "function",
                    "function_semantic_summary",
                    "decompile_slice",
                    "cfg_block",
                    "function_instruction_window",
                }:
                    continue
                item_id = str(item.get("id") or "").strip()
                if not item_id or item_id == evidence_id:
                    continue
                payload = item.get("value") if isinstance(item.get("value"), Mapping) else {}
                anchor = item.get("anchor") if isinstance(item.get("anchor"), Mapping) else {}
                entry = str(
                    payload.get("name")
                    or payload.get("entry")
                    or payload.get("function_entry")
                    or payload.get("function")
                    or anchor.get("function_entry")
                    or ""
                )
                if start_keys & set(_address_lookup_keys(entry)):
                    body_ids.append(item_id)
            specs.append(
                (
                    playbook,
                    {
                        "action": "may_start_os_thread",
                        "object": start,
                        "mechanism": "; ".join(mechanism_parts),
                        "statement": (
                            f"{artifact_path} statically recovers a same-process "
                            f"OS thread: `{api}` start `{start}` parameter "
                            f"`{parameter}`"
                            + (
                                f"; loop `{loop}`"
                                if not str(loop).startswith("UNKNOWN")
                                else ""
                            )
                            + "; runtime start is unverified."
                        ),
                        "attack_mapping": {},
                    },
                    tuple(dict.fromkeys((evidence_id, *body_ids)))[:16],
                )
            )
            if len(specs) >= 4:
                break
        return specs

    @classmethod
    def _persist_communication_loop_claim_specs(
        cls,
        artifact_path: str,
        rows: Iterable[Mapping[str, object]],
    ) -> list[tuple[object, dict[str, object], tuple[str, ...]]]:
        """C4: Sleep/delay is a loop HOW. Missing back-edge stays UNKNOWN(loop)."""
        playbook = SimpleNamespace(id="communication-loop", mechanism_type="COMMUNICATION_LOOP")
        back_edge = ""
        mapped = list(rows)
        for row in mapped:
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            token = str(value.get("back_edge") or "").strip()
            if token and "unknown" not in token.casefold():
                back_edge = token
                break
        loop = back_edge or "UNKNOWN(loop)"
        specs: list[tuple[object, dict[str, object], tuple[str, ...]]] = []
        for row in mapped:
            kind = str(row.get("kind") or "")
            if kind not in {"function_call", "api_argument_trace"}:
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            api = str(value.get("api") or value.get("name") or value.get("target_name") or "")
            folded = api.rsplit("!", 1)[-1].casefold()
            if folded not in {"sleep", "sleepex"}:
                continue
            evidence_id = str(row.get("id") or "").strip()
            if not evidence_id:
                continue
            delay = str(
                value.get("dwMilliseconds") or value.get("timeout") or value.get("delay") or ""
            ).strip() or "UNKNOWN(delay)"
            specs.append(
                (
                    playbook,
                    {
                        "action": "may_delay_or_poll",
                        "object": api.rsplit("!", 1)[-1] or "Sleep",
                        "mechanism": (
                            f"{api.rsplit('!', 1)[-1]} delay={delay} back_edge={loop}"
                        ),
                        "statement": (
                            f"{artifact_path} statically recovers a delay call `{api}`; "
                            "a sleep listing is not C2 tasking or command dispatch."
                        ),
                        "attack_mapping": {},
                    },
                    (evidence_id,),
                )
            )
            break
        return specs

    @classmethod
    def _persist_defender_claim_specs(
        cls,
        artifact_path: str,
        rows: Iterable[Mapping[str, object]],
    ) -> list[tuple[object, dict[str, object], tuple[str, ...]]]:
        """C4: Defender registry writes keep UNKNOWN(value) until a DWORD is recovered."""
        playbook = SimpleNamespace(
            id="defender-modification", mechanism_type="DEFENDER_MODIFICATION"
        )
        specs: list[tuple[object, dict[str, object], tuple[str, ...]]] = []
        for row in rows:
            kind = str(row.get("kind") or "")
            if kind not in {"function_call", "api_argument_trace"}:
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            api = str(value.get("api") or value.get("name") or "")
            blob = " ".join(
                str(value.get(key) or "")
                for key in ("api", "key", "path", "subkey", "text", "name")
            )
            if "regsetvalue" not in api.casefold() and "regsetvalue" not in blob.casefold():
                continue
            if not any(
                token in blob.casefold()
                for token in ("defender", "mpreffer", "spynet", "disableantispyware")
            ):
                continue
            evidence_id = str(row.get("id") or "").strip()
            if not evidence_id:
                continue
            dword = str(
                value.get("data") or value.get("dword") or value.get("value_data") or ""
            ).strip()
            if not re.fullmatch(r"(?i)(?:0x)?[0-9a-f]+", dword):
                dword = "UNKNOWN(value)"
            specs.append(
                (
                    playbook,
                    {
                        "action": "may_modify_defender",
                        "object": str(value.get("key") or value.get("path") or "Windows Defender"),
                        "mechanism": (
                            f"{api.rsplit('!', 1)[-1] or 'RegSetValueExW'} "
                            f"key=`{value.get('key') or value.get('path') or ''}` "
                            f"value={dword}"
                        ),
                        "statement": (
                            f"{artifact_path} statically recovers a Defender-related registry write; "
                            "a key name is not a disabled security product."
                        ),
                        "attack_mapping": {},
                    },
                    (evidence_id,),
                )
            )
            break
        return specs

    @classmethod
    def _persist_file_drop_claim_specs(
        cls,
        artifact_path: str,
        rows: Iterable[Mapping[str, object]],
    ) -> list[tuple[object, dict[str, object], tuple[str, ...]]]:
        """C4: .tmp/MZ file writes keep UNKNOWN(size) until 0x1000 is recovered."""
        playbook = SimpleNamespace(id="file-operations", mechanism_type="FILE_OPERATIONS")
        specs: list[tuple[object, dict[str, object], tuple[str, ...]]] = []
        for row in rows:
            kind = str(row.get("kind") or "")
            if kind not in {"function_call", "api_argument_trace"}:
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            api = str(value.get("api") or value.get("name") or "")
            folded = api.rsplit("!", 1)[-1].casefold()
            if folded not in {
                "createfilew",
                "createfilea",
                "writefile",
                "writefilew",
            } and "createfile" not in folded and "writefile" not in folded:
                continue
            path = str(value.get("path") or value.get("file_path") or "").strip()
            magic = str(value.get("magic") or "").strip()
            tmp_or_mz = ".tmp" in path.casefold() or magic.upper() == "MZ"
            if not tmp_or_mz:
                continue
            evidence_id = str(row.get("id") or "").strip()
            if not evidence_id:
                continue
            size = str(
                value.get("size") or value.get("length") or value.get("threshold") or ""
            ).strip()
            size_token = size if size.casefold() in {"0x1000", "4096"} else "UNKNOWN(size)"
            specs.append(
                (
                    playbook,
                    {
                        "action": "may_write_file",
                        "object": path or magic or "file write",
                        "mechanism": (
                            f"{api.rsplit('!', 1)[-1]} path=`{path}` "
                            f"{'MZ ' if magic.upper() == 'MZ' else ''}"
                            f"size={size_token}"
                        ),
                        "statement": (
                            f"{artifact_path} statically recovers a file-create/write call; "
                            "a .tmp name or MZ magic is not a dropped payload on disk."
                        ),
                        "attack_mapping": {},
                    },
                    (evidence_id,),
                )
            )
            break
        return specs

    _TIMING_RELATIONS = (
        "output_to_consumer",
        "decode_output_to_process_command",
        "command_to_process_sink",
        "resolved_pointer_to_call",
        "parent_handle_to_attribute",
        "probe_to_branch",
        "response_to_consumer",
        "buffer_to_file_sink",
        "parent_to_child",
        "routine_to_thread",
        "network_path_to_loop",
    )

    @classmethod
    def _persist_relation_timing_claim_specs(
        cls,
        artifact_path: str,
        rows: Iterable[Mapping[str, object]],
    ) -> list[tuple[object, dict[str, object], tuple[str, ...]]]:
        """C4: project an ordered Relation chain. Do not invent Phase 1–8 shells."""
        allowed = {name: True for name in cls._TIMING_RELATIONS}
        chain: list[str] = []
        evidence_ids: list[str] = []
        seen: set[str] = set()
        for row in rows:
            if str(row.get("kind") or "") != "value_flow":
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            relation = str(value.get("relation") or "").strip()
            if relation not in allowed or relation in seen:
                continue
            seen.add(relation)
            chain.append(relation)
            row_id = str(row.get("id") or "").strip()
            if row_id:
                evidence_ids.append(row_id)
        if len(chain) < 2:
            return []
        playbook = SimpleNamespace(id="relation-timing", mechanism_type="ENTRY_TIMELINE")
        ordered = " -> ".join(chain)
        return [
            (
                playbook,
                {
                    "action": "may_order_static_stages",
                    "object": ordered,
                    "mechanism": f"relation_chain={ordered}",
                    "statement": (
                        f"{artifact_path} statically recovers ordered catalog Relations "
                        f"`{ordered}`; this is not an invented runtime phase shell."
                    ),
                    "attack_mapping": {},
                },
                tuple(evidence_ids)[:16],
            )
        ]

    @classmethod
    def _persist_how_row_groups(
        cls,
        playbook_id: str,
        selected: list[dict[str, object]],
    ) -> list[list[dict[str, object]]]:
        """One persist claim per recovered named API. Process/decode stay one group."""
        if playbook_id != "dynamic-api-resolution":
            return [selected]
        flows = [row for row in selected if str(row.get("kind") or "") == "value_flow"]
        groups: list[list[dict[str, object]]] = []
        seen: set[str] = set()
        for row in selected:
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            api_name = str(
                value.get("api_name") or value.get("api_identity") or ""
            ).strip()
            if not api_name or api_name.casefold() in cls._NAMED_API_CLAIM_SKIP:
                continue
            if re.match(r"(?i)^(fun_|sub_|lab_|thunk_)", api_name):
                continue
            key = api_name.casefold()
            if key in seen:
                continue
            seen.add(key)
            groups.append([row, *flows])
            if len(groups) >= 4:
                break
        return groups

    @classmethod
    def _stage_persist_how_claims(
        cls,
        pending_claims: list[tuple[object, object, object, object]],
        how_specs: Iterable[tuple[object, dict[str, object], tuple[str, ...]]],
        *,
        task_id: str,
        subject: str,
    ) -> None:
        """Mint one CANDIDATE per recovered HOW object. Typed module, not all execution."""
        seen_how_claims = {
            (str(item[0].action), str(item[0].object))
            for item in pending_claims
            if str(getattr(item[0], "claim_type", "") or "") == "INVESTIGATED_MECHANISM"
        }
        for playbook, fields, evidence_ids in how_specs:
            action = str(fields["action"])
            object_name = str(fields["object"])[:500]
            claim_key = (action, object_name)
            if claim_key in seen_how_claims or not evidence_ids:
                continue
            seen_how_claims.add(claim_key)
            playbook_id = str(getattr(playbook, "id", "") or "")
            claim_module = cls._PERSIST_HOW_CLAIM_MODULES.get(playbook_id, "execution")
            claim = Claim(
                id=new_id(),
                task_id=task_id,
                module=claim_module,
                claim_type="INVESTIGATED_MECHANISM",
                subject=subject,
                action=action,
                object=object_name,
                mechanism=str(fields["mechanism"]),
                condition="static evidence threshold satisfied; runtime execution not proven",
                statement=str(fields["statement"]),
                nature="STATIC_INFERRED",
                status="CANDIDATE",
                confidence="HIGH",
                attack_mapping=dict(fields.get("attack_mapping") or {}),
            )
            pending_claims.append(
                (
                    claim,
                    evidence_ids,
                    False,
                    {
                        "claim_kind": "persist_time_investigated_mechanism",
                        "playbook_id": playbook_id,
                        "module": claim_module,
                        "status": "CANDIDATE",
                    },
                )
            )

    @classmethod
    def _stamp_persist_how_snapshot(
        cls,
        snapshot: dict[str, object],
        *,
        thread_id: str,
        playbook: object | None,
        result: InvestigationResult,
        artifact_path: str,
    ) -> None:
        """Write persist HOW into the snapshot. Specialist failure must not hide it.

        Kunglao DISPATCH_VERIFIER / SUMMARY_FAKE: recovered command/named API
        is CANDIDATE content; HTTP/PPID static boundary is UNKNOWN content.
        Neither is a reason to leave the seed row as an empty UNKNOWN.
        """
        if playbook is None:
            return
        persist_ready = any(
            str(getattr(item, "phase", "") or "") == "persist_time_claim_ready"
            for item in (result.events or ())
        )
        persist_boundary = any(
            str(getattr(item, "phase", "") or "") == "persist_time_static_boundary"
            for item in (result.events or ())
        )
        if not persist_ready and not persist_boundary:
            if result.thread_state != InvestigationThreadState.CLAIM_READY:
                return
            persist_ready = True
        mechanism_type = str(getattr(playbook, "mechanism_type", "") or "").upper()
        fields = cls._catalog_candidate_mechanism_fields(
            playbook, result.evidence, artifact_path
        )
        if persist_ready:
            status = str(result.hypothesis_status or "CANDIDATE").upper()
            if status not in {"CANDIDATE", "SUPPORTED", "VERIFIED", "CONFIRMED"}:
                status = "CANDIDATE"
        else:
            status = "UNKNOWN"
            missing = [
                str(item)
                for item in (getattr(result.gate, "missing", ()) or ())
                if str(item).strip()
            ]
            reason = str(getattr(result.gate, "reason", "") or "").strip()
            fields["missing_fields"] = missing
            fields["unknowns"] = missing or (
                [reason] if reason else ["static boundary; TRACE was not charged"]
            )
        fields["type"] = mechanism_type or str(fields.get("type") or "")
        fields["mechanism_type"] = mechanism_type or str(fields.get("mechanism_type") or "")
        fields["status"] = status
        fields["thread_id"] = thread_id
        fields.setdefault("target", artifact_path)
        mechanisms = snapshot.setdefault("mechanisms", [])
        if not isinstance(mechanisms, list):
            snapshot["mechanisms"] = []
            mechanisms = snapshot["mechanisms"]
        for mechanism in mechanisms:
            if not isinstance(mechanism, dict):
                continue
            if str(mechanism.get("thread_id") or "") != str(thread_id):
                continue
            current = str(mechanism.get("status") or "").upper()
            if current in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
                return
            mechanism.update(fields)
            return
        mechanisms.append(
            {
                "id": f"persist-how:{thread_id}",
                **fields,
            }
        )

    MAX_RANKED_SYMBOL_EVIDENCE = 4096

    @classmethod
    def ranked_symbol_emissions(
        cls,
        output: Mapping[str, object],
    ) -> list[tuple[str, dict[str, object], dict[str, object]]]:
        """Rank Ghidra symbols so persist HOW can join Process32 before claims mint.

        Emit these before `_persist_how_claim_specs`. Do not invent explorer.exe.
        """
        symbols = output.get("symbols", [])
        if not isinstance(symbols, list):
            return []
        symbol_rows = [item for item in symbols if isinstance(item, dict)]
        ranked_symbols = sorted(
            enumerate(symbol_rows),
            key=lambda pair: (
                bool(pair[1].get("external")),
                bool(pair[1].get("name")),
                -pair[0],
            ),
            reverse=True,
        )
        emitted: list[tuple[str, dict[str, object], dict[str, object]]] = []
        for _, symbol in ranked_symbols[: cls.MAX_RANKED_SYMBOL_EVIDENCE]:
            if not isinstance(symbol, dict):
                continue
            kind = "import_symbol" if symbol.get("external") else "export_symbol"
            emitted.append(
                (kind, symbol, {"type": "symbol_address", "address": symbol.get("address")})
            )
        return emitted

    @classmethod
    def emit_ranked_symbols_then_stage(
        cls,
        output: Mapping[str, object],
        *,
        emit: Callable[..., object],
        extra_evidence: Iterable[object],
        emitted_evidence: list[object],
        artifact_path: str,
        pending_claims: list[tuple[object, object, object, object]],
        task_id: str,
        subject: str,
    ) -> None:
        """Emit ranked symbols, then mint persist HOW from the combined evidence."""
        for kind, value, anchor in cls.ranked_symbol_emissions(output):
            emit(kind, value, anchor)
        persist_evidence: list[object] = list(emitted_evidence)
        persist_evidence.extend(extra_evidence)
        how_specs = cls._persist_how_claim_specs(
            artifact_path=artifact_path,
            evidence=persist_evidence,
        )
        cls._stage_persist_how_claims(
            pending_claims,
            how_specs,
            task_id=task_id,
            subject=subject,
        )


def persist_how_claim_specs(
    *,
    artifact_path: str,
    evidence: Iterable[object],
) -> list[tuple[object, dict[str, object], tuple[str, ...]]]:
    return PersistHow._persist_how_claim_specs(
        artifact_path=artifact_path,
        evidence=evidence,
    )


def stage_persist_how_claims(
    pending_claims: list[tuple[object, object, object, object]],
    how_specs: Iterable[tuple[object, dict[str, object], tuple[str, ...]]],
    *,
    task_id: str,
    subject: str,
) -> None:
    PersistHow._stage_persist_how_claims(
        pending_claims,
        how_specs,
        task_id=task_id,
        subject=subject,
    )


def stamp_persist_how_snapshot(
    snapshot: dict[str, object],
    *,
    thread_id: str,
    playbook: object | None,
    result: InvestigationResult,
    artifact_path: str,
) -> None:
    PersistHow._stamp_persist_how_snapshot(
        snapshot,
        thread_id=thread_id,
        playbook=playbook,
        result=result,
        artifact_path=artifact_path,
    )


def persist_partial_how_ready(playbook_id: str, evidence: Iterable[object]) -> bool:
    return PersistHow._persist_partial_how_ready(playbook_id, evidence)


def catalog_candidate_mechanism_fields(
    playbook: object,
    evidence: Iterable[object],
    artifact_path: str,
) -> dict[str, object]:
    return PersistHow._catalog_candidate_mechanism_fields(
        playbook, evidence, artifact_path
    )


def ranked_symbol_emissions(
    output: Mapping[str, object],
) -> list[tuple[str, dict[str, object], dict[str, object]]]:
    return PersistHow.ranked_symbol_emissions(output)


def emit_ranked_symbols_then_stage(
    output: Mapping[str, object],
    *,
    emit: Callable[..., object],
    extra_evidence: Iterable[object],
    emitted_evidence: list[object],
    artifact_path: str,
    pending_claims: list[tuple[object, object, object, object]],
    task_id: str,
    subject: str,
) -> None:
    PersistHow.emit_ranked_symbols_then_stage(
        output,
        emit=emit,
        extra_evidence=extra_evidence,
        emitted_evidence=emitted_evidence,
        artifact_path=artifact_path,
        pending_claims=pending_claims,
        task_id=task_id,
        subject=subject,
    )
