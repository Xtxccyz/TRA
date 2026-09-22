"""Run an evaluator-only semantic differential from JSON files.

Usage: python scripts/evaluate_semantic_differential.py task-view.json gold.json
The Gold file is intentionally an explicit evaluator input, never a runtime
Agent configuration file.
"""

from __future__ import annotations

import json
import mmap
from pathlib import Path
import sys
from typing import Any, Iterator

# This evaluator is intentionally a repository-level tool, not a packaged
# runtime dependency. Make its sibling evaluator-only package importable when
# the script is invoked directly from any working directory.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

def main(argv: list[str]) -> int:
    from benchmarks.semantic_differential import build_semantic_differential

    if len(argv) != 3:
        print("usage: evaluate_semantic_differential.py TASK_VIEW_JSON GOLD_JSON")
        return 2
    task_path = Path(argv[1])
    task_view = _load_task_view(task_path)
    gold = json.loads(Path(argv[2]).read_text("utf-8"))
    if not isinstance(gold, dict) or gold.get("evaluator_only") is not True:
        print("GOLD_JSON must declare evaluator_only=true", file=sys.stderr)
        return 2
    print(json.dumps(build_semantic_differential(task_view, gold), ensure_ascii=False, indent=2))
    return 0


def _find_value_start(mapped: mmap.mmap, key: str) -> int:
    """Find a field on the task-view root object.

    A live task view contains thousands of nested objects, most of which also
    have an ``id`` field.  Searching for the first byte marker can therefore
    bind the evaluator to an Artifact/Evidence ID instead of the task ID.  A
    small top-level JSON scanner keeps the reader streaming while respecting
    strings, escapes, arrays, and nested objects.
    """
    position = 0
    while position < len(mapped) and mapped[position] in b" \t\r\n":
        position += 1
    if position >= len(mapped) or mapped[position] != ord("{"):
        return -1
    depth = 0
    in_string = False
    escaped = False
    string_start = -1
    for position in range(position, len(mapped)):
        byte = mapped[position]
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
                if depth == 1 and string_start >= 0:
                    raw_key = bytes(mapped[string_start:position])
                    try:
                        parsed_key = json.loads((b'"' + raw_key + b'"').decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        parsed_key = None
                    if parsed_key == key:
                        cursor = position + 1
                        while cursor < len(mapped) and mapped[cursor] in b" \t\r\n":
                            cursor += 1
                        if cursor < len(mapped) and mapped[cursor] == ord(":"):
                            cursor += 1
                            while cursor < len(mapped) and mapped[cursor] in b" \t\r\n":
                                cursor += 1
                            return cursor
                string_start = -1
            continue
        if byte == ord('"'):
            in_string = True
            string_start = position + 1
        elif byte in (ord("{"), ord("[")):
            depth += 1
        elif byte in (ord("}"), ord("]")):
            depth -= 1
    return -1


def _matching_end(mapped: mmap.mmap, start: int) -> int:
    opening = mapped[start]
    closing = {ord("["): ord("]"), ord("{"): ord("}")}.get(opening)
    if closing is None:
        raise ValueError("streamed field is not an array or object")
    depth = 0
    in_string = False
    escaped = False
    for position in range(start, len(mapped)):
        byte = mapped[position]
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte == opening:
            depth += 1
        elif byte == closing:
            depth -= 1
            if depth == 0:
                return position + 1
    raise ValueError("unterminated streamed JSON field")


def _iter_array_values(mapped: mmap.mmap, start: int) -> Iterator[Any]:
    """Yield array members without materialising a huge task projection."""
    if mapped[start] != ord("["):
        raise ValueError("streamed field is not an array")
    element_start: int | None = None
    depth = 0
    in_string = False
    escaped = False
    for position in range(start + 1, len(mapped)):
        byte = mapped[position]
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
            if element_start is None:
                element_start = position
            continue
        if byte in (ord("["), ord("{")):
            if element_start is None:
                element_start = position
            depth += 1
        elif byte in (ord("]"), ord("}")):
            depth -= 1
            if depth == 0 and element_start is not None:
                raw = bytes(mapped[element_start : position + 1]).strip()
                if raw:
                    yield json.loads(raw.decode("utf-8"))
                element_start = None
            if byte == ord("]") and depth < 0:
                return
        elif byte == ord(",") and depth == 0 and element_start is not None:
            raw = bytes(mapped[element_start:position]).strip()
            if raw:
                yield json.loads(raw.decode("utf-8"))
            element_start = None
        elif element_start is None and byte not in b" \t\r\n,":
            element_start = position
    raise ValueError("unterminated streamed JSON array")


def _scalar_end(mapped: mmap.mmap, start: int) -> int:
    """Return the end of a JSON scalar at ``start``.

    Large task views are produced by different API versions.  Optional
    projections such as ``investigation`` may be ``null`` or a scalar while
    the evidence ledger is still a large array.  The streaming reader must
    treat those values as valid JSON instead of passing them to the
    container-only matcher.
    """
    if start >= len(mapped):
        raise ValueError("missing JSON value")
    if mapped[start] == ord('"'):
        escaped = False
        for position in range(start + 1, len(mapped)):
            byte = mapped[position]
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                return position + 1
        raise ValueError("unterminated JSON string")
    position = start
    while position < len(mapped) and mapped[position] not in b",}\r\n":
        position += 1
    return position


def _json_value_end(mapped: mmap.mmap, start: int) -> int:
    """Match either a JSON container or scalar without materialising it."""
    if mapped[start] in (ord("["), ord("{")):
        return _matching_end(mapped, start)
    return _scalar_end(mapped, start)


def _load_task_view(path: Path) -> dict[str, Any]:
    """Load small fixtures normally and large live views with bounded memory."""
    if path.stat().st_size <= 8 * 1024 * 1024:
        payload = json.loads(path.read_text("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("task view must be a JSON object")
        return payload
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        payload: dict[str, Any] = {}
        for key in ("id", "limitations", "claims"):
            start = _find_value_start(mapped, key)
            if start < 0:
                continue
            if mapped[start] in (ord("["), ord("{")):
                end = _matching_end(mapped, start)
                payload[key] = json.loads(bytes(mapped[start:end]).decode("utf-8"))
            else:
                end = mapped.find(b",", start)
                if end < 0:
                    end = mapped.find(b"}", start)
                payload[key] = json.loads(bytes(mapped[start:end]).decode("utf-8"))
        evidence_start = _find_value_start(mapped, "evidence")
        if evidence_start < 0:
            raise ValueError("task view has no evidence array")
        payload["evidence"] = list(_iter_array_values(mapped, evidence_start))
        delivery_start = _find_value_start(mapped, "evidence_delivery")
        if delivery_start >= 0:
            delivery_end = _json_value_end(mapped, delivery_start)
            raw_delivery = bytes(mapped[delivery_start:delivery_end]).strip()
            if raw_delivery:
                payload["evidence_delivery"] = json.loads(raw_delivery.decode("utf-8"))
        investigation_start = _find_value_start(mapped, "investigation")
        if investigation_start >= 0:
            investigation_end = _json_value_end(mapped, investigation_start)
            raw_investigation = bytes(mapped[investigation_start:investigation_end]).strip()
            if raw_investigation:
                payload["investigation"] = json.loads(raw_investigation.decode("utf-8"))
        return payload


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
