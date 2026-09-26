"""Versioned behaviour catalogue and typed evidence contracts.

The catalogue is an investigation map, not a detector.  A seed can open a
thread, but only typed facts and explicit relations can satisfy a contract.
API names, field labels, ``UNKNOWN`` values and co-location in one
function/artifact are never sufficient to prove a behaviour.

This module has no dependency on :mod:`investigation`; action names are
strings so planning and report code can import it without a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Iterable, Mapping, Sequence


class SupportLevel(StrEnum):
    """Truthful implementation status for one catalogue dimension."""

    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    NOT_VALIDATED = "not_validated"


_UNKNOWN_WORDS = frozenset(
    {
        "unknown",
        "not_identified",
        "not identified",
        "not_recovered",
        "not recovered",
        "unresolved",
        "unobserved",
        "not observed",
        "not available",
        "n/a",
        "na",
        "null",
        "none",
        "missing",
        "unsupported",
        "not proven",
        "not_proven",
    }
)
_NEGATION_RE = re.compile(
    r"(?:^|[\s_:()\[\]{},;/-])"
    r"(?:no|not|never|without|absent|failed|failure|false|否定|未知)"
    r"(?:$|[\s_:()\[\]{},;/-])",
    re.IGNORECASE,
)
_PLACEHOLDER_WORDS = frozenset(
    {
        "input",
        "output",
        "consumer",
        "target",
        "condition",
        "side_effect",
        "side effect",
        "path",
        "buffer",
        "data",
        "key",
        "value",
        "module",
        "api",
        "function",
        "unknown(input)",
        "unknown(output)",
        "unknown(consumer)",
        "unknown(target)",
    }
)
_UNRESOLVED_STATUSES = frozenset(
    {
        "unknown", "not_identified", "not identified", "unresolved",
        "unobserved", "not observed", "not available", "missing",
        "unsupported", "not proven", "not_proven", "refuted", "rejected",
        "failed", "failure", "error", "candidate", "partial", "pending",
        "not_applicable", "not applicable",
    }
)


def _norm(value: object) -> str:
    return str(value or "").strip().casefold()


def _is_unknown_scalar(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return True
    if isinstance(value, (int, float)):
        return False
    text = _norm(value)
    if not text:
        return True
    if text in _UNKNOWN_WORDS or text in _PLACEHOLDER_WORDS:
        return True
    if any(marker in text for marker in ("unknown(", "unknown:", "<unknown>", "not_identified")):
        return True
    return bool(_NEGATION_RE.search(text))


_STATUS_LIKE_KEYS = frozenset(
    {
        "status",
        "verification_status",
        "resolution_status",
        "result_status",
        "validity",
        "resolved",
        "success",
    }
)

# Container types that could hide a nested status key.  A module-level constant
# tested with `type(x) in ...` rather than `isinstance(x, (A, B, C, D, E))`: the
# inline tuple form builds a fresh 5-tuple on EVERY loop iteration, and
# `isinstance` against a tuple runs ABC `__subclasscheck__` for each entry -
# both showed up in the live stack.  Measured on a 50,000-item status-free
# payload: 0.0276 s with the naive form.
_CONTAINER_TYPES = (dict, list, tuple, set, frozenset)


def _has_status_like_key(value: object, *, _depth: int = 0) -> bool:
    """Whether any status-like key exists anywhere in ``value``.

    Existence only - it does not interpret the value, so it is a sound pre-filter for
    `_contains_unresolved_status`, which can only ever return True when one of these
    keys is present.  A payload without one is provably not an unresolved-status row,
    and that is the overwhelming majority of the corpus (instruction windows, data
    references, raw strings).

    Why this exists: `is_concrete_value` called the full recursive
    `_contains_unresolved_status` walk on EVERY row.  Measured per payload - 1.76 MB
    instruction window 0.0258 s, 1.29 MB data references 0.0484 s - against ~38,000
    rows, i.e. roughly 32 minutes, which is exactly the observed stall.  A live stack
    sat in `behavior_catalog.py:139 <genexpr>` -> `:140` -> `typing.__subclasscheck__`.

    The sweep is a single flat pass over each container's immediate children plus
    recursion only into containers, so a list of 50,000 plain strings costs one
    `type() in` test per element and no status lookup per element.
    """
    if _depth > 32:
        return False
    if isinstance(value, Mapping):
        for key in value:
            if str(key or "").strip().casefold().replace("-", "_") in _STATUS_LIKE_KEYS:
                return True
        for item in value.values():
            if type(item) in _CONTAINER_TYPES and _has_status_like_key(
                item, _depth=_depth + 1
            ):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            if type(item) in _CONTAINER_TYPES and _has_status_like_key(
                item, _depth=_depth + 1
            ):
                return True
        return False
    return False


_UNRESOLVED_CACHE: dict[int, tuple[object, bool]] = {}
_UNRESOLVED_CACHE_LIMIT = 200_000


def _contains_unresolved_status(value: object) -> bool:
    """Return whether a typed row explicitly says its result is unresolved.

    A fact may carry additional diagnostic fields (for example an exporter
    status beside a recovered value).  Those diagnostics must not be hidden by
    another concrete-looking field in the same row.  This is intentionally
    limited to status-like keys; arbitrary business values such as a string
    named ``error`` are not interpreted as a verdict.

    Memoised on the payload's identity.  `EvidenceContract.evaluate` runs EVERY
    predicate over EVERY evidence row, so this walk is repeated for the same row once
    per predicate: a cProfile of one `Verifier.evaluate` on the real 39,833-row corpus
    measured **8,695,720 `_has_status_like_key` calls / 34 s self / 68 s cumulative**,
    the dominant cost of the gate the investigation loop runs each iteration.  The
    function is pure, so caching is exact; a miss costs work but cannot change an
    answer.  Bounded and identity-checked so a recycled ``id()`` cannot alias another
    payload.
    """
    if not isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return False
    key = id(value)
    cached = _UNRESOLVED_CACHE.get(key)
    if cached is not None and cached[0] is value:
        return cached[1]
    result = _contains_unresolved_status_uncached(value)
    if len(_UNRESOLVED_CACHE) >= _UNRESOLVED_CACHE_LIMIT:
        _UNRESOLVED_CACHE.clear()
    _UNRESOLVED_CACHE[key] = (value, result)
    return result


def _contains_unresolved_status_uncached(value: object) -> bool:
    if not _has_status_like_key(value):
        return False

    if isinstance(value, Mapping):
        for key, item in value.items():
            name = _norm(key).replace("-", "_")
            if name in {"status", "verification_status", "resolution_status", "result_status", "validity"}:
                if _norm(item) in _UNRESOLVED_STATUSES or _is_unknown_scalar(item):
                    return True
            elif name == "resolved" and item is False:
                return True
            elif name == "success" and item is False:
                return True
            if _contains_unresolved_status(item):
                return True
    elif isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_unresolved_status(item) for item in value)
    return False


def is_concrete_value(value: object) -> bool:
    """Return whether a value contains an affirmative, non-placeholder fact."""

    if isinstance(value, Mapping):
        if _contains_unresolved_status(value):
            return False
        return bool(value) and any(is_concrete_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return bool(value) and any(is_concrete_value(item) for item in value)
    return not _is_unknown_scalar(value)


def is_unknown_or_negative(value: object) -> bool:
    """Public inverse helper used by tests and report boundaries."""

    return not is_concrete_value(value)


def _mapping(row: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = row.get(key)
    return value if isinstance(value, Mapping) else {}


def _path_values(root: object, path: Sequence[str]) -> tuple[object, ...]:
    """Read a bounded dotted/wildcard path from an evidence row."""

    if not path:
        return (root,)
    head, *tail = path
    if head in {"*", "[]"}:
        if isinstance(root, Mapping):
            items: Iterable[object] = root.values()
        elif isinstance(root, (list, tuple, set, frozenset)):
            items = root
        else:
            return ()
        result: list[object] = []
        for item in items:
            result.extend(_path_values(item, tail))
        return tuple(result)
    if isinstance(root, Mapping) and head in root:
        return _path_values(root[head], tail)
    if isinstance(root, (list, tuple, set, frozenset)):
        result: list[object] = []
        for item in root:
            result.extend(_path_values(item, path))
        return tuple(result)
    return ()


def _parse_path(path: str | Sequence[str]) -> tuple[str, ...]:
    if isinstance(path, str):
        return tuple(item for item in path.replace("[", ".").replace("]", "").split(".") if item)
    return tuple(str(item) for item in path)


def _row_nature_allowed(row: Mapping[str, object], allowed: frozenset[str]) -> bool:
    nature = row.get("nature")
    return nature is None or _norm(nature).upper() in {item.upper() for item in allowed}


def _explicit_api_values(row: Mapping[str, object]) -> tuple[str, ...]:
    """Extract API identities only from typed symbol fields.

    Rendered ``text``/``statement`` fields are intentionally excluded.  They
    are navigation evidence, not facts that can satisfy a behaviour contract.
    """

    value = _mapping(row, "value")
    result: list[str] = []

    def collect(item: object) -> None:
        if isinstance(item, Mapping):
            for nested_key, nested_value in item.items():
                key_name = _norm(nested_key)
                if key_name in {
                    "api", "api_name", "resolved_api", "symbol", "target_name",
                    "target_api", "callee", "consumer_api", "export_name",
                }:
                    if isinstance(nested_value, str) and is_concrete_value(nested_value):
                        result.append(_norm(nested_value))
                elif key_name in {
                    "apis", "call_targets", "callees", "functions", "resolved_symbols",
                    "consumer_apis", "references",
                }:
                    collect(nested_value)
        elif isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                collect(child)

    collect(value)
    for key in (
        "api", "api_name", "resolved_api", "target_name", "callee", "consumer_api", "export_name",
    ):
        item = value.get(key)
        if isinstance(item, str) and is_concrete_value(item):
            result.append(_norm(item))
    return tuple(dict.fromkeys(result))


def _api_equal(actual: object, expected: object) -> bool:
    actual_text = _norm(actual)
    expected_text = _norm(expected)
    if not actual_text or not expected_text:
        return False
    # Strip only known import/decompiler decoration and call-site metadata;
    # never use substring matching (``FooWrapper`` is not ``Foo``).
    for name in ("actual_text", "expected_text"):
        value = locals()[name]
        value = value.rsplit("!", 1)[-1].rsplit(".", 1)[-1]
        value = re.sub(r"^(?:__imp_|imp_|j_|thunk_|stub_)+", "", value)
        value = re.split(r"[\s(]", value, maxsplit=1)[0]
        value = re.sub(r"@[0-9]+$", "", value)
        if name == "actual_text":
            actual_text = value
        else:
            expected_text = value
    return actual_text == expected_text


@dataclass(frozen=True)
class PredicateMatch:
    """Outcome for one typed predicate."""

    predicate_id: str
    matched_evidence_ids: tuple[str, ...] = ()
    reason: str = ""

    @property
    def matched(self) -> bool:
        return bool(self.matched_evidence_ids)


@dataclass(frozen=True)
class EvidencePredicate:
    """A typed, row-local fact predicate."""

    id: str
    paths: tuple[tuple[str, ...], ...] = ()
    kinds: tuple[str, ...] = ()
    expected_values: tuple[object, ...] = ()
    api_symbols: tuple[str, ...] = ()
    require_truthy: bool = False
    required: bool = True
    allowed_natures: frozenset[str] = frozenset(
        {"STATIC_OBSERVED", "STATIC_DERIVED", "STATIC_INFERRED", "EMULATION_OBSERVED"}
    )
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("evidence predicate requires a stable id")
        object.__setattr__(self, "paths", tuple(_parse_path(path) for path in self.paths))
        if not self.paths and not self.api_symbols:
            raise ValueError("evidence predicate requires a typed path or API symbol")

    @classmethod
    def field(
        cls,
        predicate_id: str,
        path: str | Sequence[str],
        *,
        kinds: Iterable[str] = (),
        expected_values: Iterable[object] = (),
        require_truthy: bool = False,
        description: str = "",
    ) -> "EvidencePredicate":
        return cls(
            id=predicate_id,
            paths=(_parse_path(path),),
            kinds=tuple(str(item) for item in kinds),
            expected_values=tuple(expected_values),
            require_truthy=require_truthy,
            description=description,
        )

    @classmethod
    def api(
        cls,
        predicate_id: str,
        symbols: Iterable[str],
        *,
        kinds: Iterable[str] = (),
        description: str = "",
    ) -> "EvidencePredicate":
        return cls(
            id=predicate_id,
            kinds=tuple(str(item) for item in kinds),
            api_symbols=tuple(str(item) for item in symbols),
            description=description,
        )

    def match_row(self, row: Mapping[str, object]) -> bool:
        """Whether this predicate is satisfied by one evidence row.

        The CHEAP structural filters run before the expensive payload walk.  Every
        conjunct here is order-independent - they are pure predicates over the same
        row and the function returns False on the first failure - so reordering cannot
        change the result.  It changes the cost enormously.

        `_contains_unresolved_status` walks the whole payload looking for status keys.
        Measured on the real sample's 39,833 rows with a 78 MB corpus, this method was
        called 199,165 times, `_has_status_like_key` 8,695,720 times, and the total was
        **230 s for one `Verifier.evaluate`** - which the investigation loop performs on
        every iteration.  Checking `kind`/`nature` first means the payload walk only
        runs for rows that could match at all.
        """
        if not _row_nature_allowed(row, self.allowed_natures):
            return False
        if self.kinds and _norm(row.get("kind")) not in {_norm(item) for item in self.kinds}:
            return False
        if _contains_unresolved_status(row):
            return False
        if self.api_symbols:
            actual = _explicit_api_values(row)
            if not any(_api_equal(candidate, expected) for candidate in actual for expected in self.api_symbols):
                return False
        if self.paths:
            values: list[object] = []
            for path in self.paths:
                values.extend(_path_values(row, path))
            if self.require_truthy and not any(bool(item) for item in values):
                return False
            if not any(is_concrete_value(item) for item in values):
                return False
            if self.expected_values and not any(
                _value_equal(candidate, expected)
                for candidate in values
                for expected in self.expected_values
            ):
                return False
        return bool(self.api_symbols or self.paths)

    def evaluate(self, evidence: Iterable[Mapping[str, object]]) -> PredicateMatch:
        ids = tuple(
            str(row.get("id"))
            for row in evidence
            if row.get("id") and self.match_row(row)
        )
        return PredicateMatch(self.id, ids, "typed fact matched" if ids else "no concrete typed fact")

    def as_dict(self) -> dict[str, object]:
        """Serialize the executable fact obligation for catalog consumers."""
        return {
            "id": self.id,
            "paths": [list(path) for path in self.paths],
            "kinds": list(self.kinds),
            "expected_values": list(self.expected_values),
            "api_symbols": list(self.api_symbols),
            "require_truthy": self.require_truthy,
            "required": self.required,
            "allowed_natures": sorted(self.allowed_natures),
            "description": self.description,
        }


TypedEvidencePredicate = EvidencePredicate
TypedFactPredicate = EvidencePredicate


def _value_equal(actual: object, expected: object) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual is expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return actual == expected
    return _norm(actual) == _norm(expected) and is_concrete_value(actual)


def _object_identity(value: object) -> tuple[tuple[str, str], ...] | None:
    """Return strict identity for a buffer/region/handle object.

    A function/API/name is not an identity.  Byte objects need artifact +
    address-space + address/offset + length (or a stable object id); handles
    need artifact + handle value/id.
    """

    if not isinstance(value, Mapping):
        return None
    artifact = value.get("artifact_id") or value.get("artifact")
    address_space = value.get("address_space") or value.get("memory_space")
    location = (
        value.get("address") if value.get("address") is not None else
        value.get("virtual_address") if value.get("virtual_address") is not None else
        value.get("va") if value.get("va") is not None else
        value.get("offset") if value.get("offset") is not None else
        value.get("rva")
    )
    size = value.get("length") if value.get("length") is not None else value.get("size")
    stable_id = value.get("object_id") or value.get("allocation_id") or value.get("buffer_id")
    handle = value.get("handle_id") or value.get("handle_value")
    if not artifact or not is_concrete_value(artifact):
        return None
    if handle is not None:
        if not is_concrete_value(handle):
            return None
        return (("artifact_id", _norm(artifact)), ("handle", _norm(handle)))
    if not address_space or not is_concrete_value(address_space):
        return None
    if stable_id is None and (location is None or size is None):
        return None
    if stable_id is not None and not is_concrete_value(stable_id):
        return None
    if location is not None and not is_concrete_value(location):
        return None
    if size is not None and not is_concrete_value(size):
        return None
    # A stable allocation/buffer identifier survives relocation and resizing
    # during a static or emulated trace.  Do not append optional coordinates
    # when one is present, otherwise the same object would compare unequal
    # merely because the exporter reported a different extent at a later use.
    if stable_id is not None:
        return (
            ("artifact_id", _norm(artifact)),
            ("address_space", _norm(address_space)),
            ("object_id", _norm(stable_id)),
        )
    pairs = [("artifact_id", _norm(artifact)), ("address_space", _norm(address_space))]
    if stable_id is not None:
        pairs.append(("object_id", _norm(stable_id)))
    if location is not None:
        pairs.append(("location", _norm(location)))
    if size is not None:
        pairs.append(("size", _norm(size)))
    return tuple(pairs)


def object_identity(value: object) -> tuple[tuple[str, str], ...] | None:
    """Public strict object identity helper."""

    return _object_identity(value)


def _candidate_objects(row: Mapping[str, object], paths: Sequence[tuple[str, ...]]) -> tuple[object, ...]:
    values: list[object] = []
    if paths:
        for path in paths:
            values.extend(_path_values(row, path))
    else:
        value = _mapping(row, "value")
        for key in (
            "source_buffer", "output_buffer", "input_buffer", "target_buffer",
            "source_region", "target_region", "region", "buffer",
            "source_object", "target_object", "handle",
        ):
            if key in value:
                values.append(value[key])
    return tuple(values)


def _provenance_ids(value: Mapping[str, object], *keys: str) -> tuple[str, ...]:
    """Normalize one endpoint's evidence citations.

    Derived relations must cite both endpoints.  Plural IDs are the canonical
    form, while singular legacy fields remain accepted when they contain a
    concrete ID.  Empty or placeholder IDs invalidate the endpoint.
    """
    raw: object = None
    for key in keys:
        if value.get(key) is not None:
            raw = value.get(key)
            break
    if isinstance(raw, str):
        candidates = (raw,)
    elif isinstance(raw, (list, tuple, set, frozenset)):
        candidates = tuple(raw)
    else:
        return ()
    def valid_id(item: object) -> bool:
        # Evidence IDs are opaque identifiers.  Names such as ``consumer`` or
        # ``target`` are valid IDs even though the same words are placeholders
        # when used as fact values; only an empty/unknown/negative ID is invalid.
        if not isinstance(item, (str, int)):
            return False
        text = _norm(item)
        return bool(text) and text not in _UNKNOWN_WORDS and not _NEGATION_RE.search(text)

    if not candidates or any(not valid_id(item) for item in candidates):
        return ()
    return tuple(dict.fromkeys(str(item).strip() for item in candidates))


@dataclass(frozen=True)
class RelationPredicate:
    """Require an explicit, provenance-bearing relation between objects."""

    id: str
    relation_types: tuple[str, ...]
    source_paths: tuple[tuple[str, ...], ...] = ()
    target_paths: tuple[tuple[str, ...], ...] = ()
    kinds: tuple[str, ...] = ()
    require_provenance: bool = True
    require_same_object: bool = False
    required: bool = True
    description: str = ""
    allowed_natures: frozenset[str] = frozenset(
        {"STATIC_OBSERVED", "STATIC_DERIVED", "STATIC_INFERRED", "EMULATION_OBSERVED"}
    )

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("relation predicate requires a stable id")
        if not self.relation_types or any(not str(item).strip() for item in self.relation_types):
            raise ValueError("relation predicate requires a relation type")
        object.__setattr__(self, "source_paths", tuple(_parse_path(path) for path in self.source_paths))
        object.__setattr__(self, "target_paths", tuple(_parse_path(path) for path in self.target_paths))

    def _relation_row_matches(self, row: Mapping[str, object]) -> bool:
        if _contains_unresolved_status(row):
            return False
        value = _mapping(row, "value")
        relation = value.get("relation") or value.get("relationship") or row.get("relation")
        if _norm(relation) not in {_norm(item) for item in self.relation_types}:
            return False
        if self.kinds and _norm(row.get("kind")) not in {_norm(item) for item in self.kinds}:
            return False
        if not _row_nature_allowed(row, self.allowed_natures):
            return False
        if self.require_provenance:
            source_ids = _provenance_ids(
                value,
                "source_evidence_ids",
                "source_evidence_id",
                "producer_evidence_id",
            )
            target_ids = _provenance_ids(
                value,
                "target_evidence_ids",
                "target_evidence_id",
                "consumer_evidence_id",
            )
            # Both the producer and consumer endpoint are required.  A list of
            # producer IDs alone is not a relation provenance record.
            if not source_ids or not target_ids:
                return False
        source_values = _candidate_objects(row, self.source_paths)
        target_values = _candidate_objects(row, self.target_paths)
        if not source_values or not target_values:
            return False
        source_objects = tuple(identity for item in source_values if (identity := _object_identity(item)))
        target_objects = tuple(identity for item in target_values if (identity := _object_identity(item)))
        if not source_objects or not target_objects:
            return False
        return not self.require_same_object or bool(set(source_objects).intersection(target_objects))

    def evaluate(self, evidence: Iterable[Mapping[str, object]]) -> PredicateMatch:
        rows = tuple(evidence)
        by_id = {str(row.get("id")): row for row in rows if row.get("id")}
        matched: list[str] = []
        for row in rows:
            if not row.get("id"):
                continue
            # A relation's provenance is part of the relation contract, not a
            # free-form annotation.  Resolve every cited endpoint before
            # accepting a direct object payload; otherwise a fabricated row
            # could claim a link using IDs that are absent from this snapshot.
            value = _mapping(row, "value")
            source_ids = _provenance_ids(
                value,
                "source_evidence_ids",
                "source_evidence_id",
                "producer_evidence_id",
            )
            target_ids = _provenance_ids(
                value,
                "target_evidence_ids",
                "target_evidence_id",
                "consumer_evidence_id",
            )
            if self.require_provenance and (
                not source_ids
                or not target_ids
                or any(item not in by_id for item in (*source_ids, *target_ids))
            ):
                continue
            if self.require_provenance and source_ids and target_ids:
                cited_sources = tuple(
                    identity
                    for item_id in source_ids
                    for item in _candidate_objects(by_id[item_id], self.source_paths)
                    if (identity := _object_identity(item))
                )
                cited_targets = tuple(
                    identity
                    for item_id in target_ids
                    for item in _candidate_objects(by_id[item_id], self.target_paths)
                    if (identity := _object_identity(item))
                )
                direct_sources = tuple(
                    identity
                    for item in _candidate_objects(row, self.source_paths)
                    if (identity := _object_identity(item))
                )
                direct_targets = tuple(
                    identity
                    for item in _candidate_objects(row, self.target_paths)
                    if (identity := _object_identity(item))
                )
                # If the link repeats endpoint objects, they must agree with
                # the objects on the cited producer/consumer rows.  When a
                # link omits endpoint objects, the second pass below resolves
                # them from the cited rows instead.
                if direct_sources and cited_sources and not set(direct_sources).intersection(cited_sources):
                    continue
                if direct_targets and cited_targets and not set(direct_targets).intersection(cited_targets):
                    continue
            if self._relation_row_matches(row):
                matched.append(str(row["id"]))
                continue
            # Derived links may cite producer/consumer rows rather than copy
            # their object records. Resolve citations and compare identities.
            relation = value.get("relation") or value.get("relationship")
            if _norm(relation) not in {_norm(item) for item in self.relation_types}:
                continue
            if self.kinds and _norm(row.get("kind")) not in {_norm(item) for item in self.kinds}:
                continue
            if not _row_nature_allowed(row, self.allowed_natures):
                continue
            if self.require_provenance and (not source_ids or not target_ids):
                continue
            source_rows = [by_id.get(item) for item in source_ids]
            target_rows = [by_id.get(item) for item in target_ids]
            if any(item is None for item in source_rows + target_rows):
                continue
            if any(
                not _row_nature_allowed(item, self.allowed_natures)
                for item in source_rows + target_rows
                if item is not None
            ):
                continue
            source_objects = [identity for source in source_rows if source for item in _candidate_objects(source, self.source_paths) if (identity := _object_identity(item))]
            target_objects = [identity for target in target_rows if target for item in _candidate_objects(target, self.target_paths) if (identity := _object_identity(item))]
            if source_objects and target_objects and (not self.require_same_object or set(source_objects).intersection(target_objects)):
                matched.append(str(row["id"]))
        return PredicateMatch(self.id, tuple(dict.fromkeys(matched)), "typed relation matched" if matched else "no explicit object relation")

    def as_dict(self) -> dict[str, object]:
        """Serialize the executable object/provenance obligation."""
        return {
            "id": self.id,
            "relation_types": list(self.relation_types),
            "source_paths": [list(path) for path in self.source_paths],
            "target_paths": [list(path) for path in self.target_paths],
            "kinds": list(self.kinds),
            "require_provenance": self.require_provenance,
            "require_same_object": self.require_same_object,
            "required": self.required,
            "allowed_natures": sorted(self.allowed_natures),
            "description": self.description,
        }


TypedRelationPredicate = RelationPredicate


@dataclass(frozen=True)
class CounterExample:
    """A versioned minimal counter-example from the methodology contract.

    Section 7 of the investigation plan states, for every behaviour contract,
    the *minimal counter-example* that must not be accepted as that behaviour:
    a resource API import alone, a once+run+delete task called durable
    persistence, a same-process APC called remote injection, a runtime timing
    query called anti-analysis.  Prose in ``forbidden_inferences`` documents
    those limits but cannot enforce them, so every counter-example that can be
    expressed as data is registered here and evaluated.

    A counter-example matches when ONE evidence row satisfies every predicate
    in ``row_predicates`` and at least one predicate in ``row_any_predicates``.
    The conjunction on a single row is deliberate: the counter-example is "the
    very row that supplies the required fact also says the claim does not
    hold".  Matching rows are withheld from the contract's facts (see
    :meth:`EvidenceContract.evaluate`), so they cannot be promoted, while an
    independent row that carries the same fact honestly still can.

    Predicates use the same typed matching as every other contract obligation -
    exact normalized field values and explicit kinds - never substring
    thresholds, so a value that merely mentions a word is not a match.
    """

    id: str
    source: str
    over_claim: str
    row_predicates: tuple[EvidencePredicate, ...] = ()
    row_any_predicates: tuple[EvidencePredicate, ...] = ()
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("counter-example requires a stable id")
        if not self.source.strip():
            raise ValueError("counter-example requires its methodology source")
        if not self.over_claim.strip():
            raise ValueError("counter-example requires the over-claim it blocks")
        if not self.row_predicates and not self.row_any_predicates:
            raise ValueError("counter-example requires at least one typed row predicate")
        ids = [item.id for item in (*self.row_predicates, *self.row_any_predicates)]
        if len(ids) != len(set(ids)):
            raise ValueError("counter-example predicate IDs must be unique")

    def matches(self, evidence: Iterable[Mapping[str, object]]) -> tuple[str, ...]:
        """Evidence row IDs that carry this counter-example pattern."""
        matched: list[str] = []
        for row in evidence:
            if not isinstance(row, Mapping) or not row.get("id"):
                continue
            if not all(item.match_row(row) for item in self.row_predicates):
                continue
            if self.row_any_predicates and not any(
                item.match_row(row) for item in self.row_any_predicates
            ):
                continue
            matched.append(str(row["id"]))
        return tuple(dict.fromkeys(matched))

    def as_dict(self) -> dict[str, object]:
        """Serialize the executable counter-example for catalog consumers."""
        return {
            "id": self.id,
            "version": self.version,
            "source": self.source,
            "over_claim": self.over_claim,
            "row_predicates": [item.as_dict() for item in self.row_predicates],
            "row_any_predicates": [item.as_dict() for item in self.row_any_predicates],
        }


def counter_example(
    counter_example_id: str,
    source: str,
    over_claim: str,
    *,
    all_of: Iterable[EvidencePredicate] = (),
    any_of: Iterable[EvidencePredicate] = (),
) -> CounterExample:
    """Build one registered counter-example."""

    return CounterExample(
        id=counter_example_id,
        source=source,
        over_claim=over_claim,
        row_predicates=tuple(all_of),
        row_any_predicates=tuple(any_of),
    )


def _values_predicate(predicate_id: str, path: str, *values: object) -> EvidencePredicate:
    """Exact normalized value match on one typed field."""
    return EvidencePredicate(
        id=predicate_id,
        paths=(_parse_path(path),),
        expected_values=tuple(values),
    )


def _any_field_values_predicate(
    predicate_id: str, paths: Iterable[str], values: Iterable[object]
) -> EvidencePredicate:
    """Exact normalized value match on the first of several equivalent fields."""
    return EvidencePredicate(
        id=predicate_id,
        paths=tuple(_parse_path(path) for path in paths),
        expected_values=tuple(values),
    )


@dataclass(frozen=True)
class ContractEvaluation:
    """Auditable result of evaluating all facts and relations in a contract."""

    accepted: bool
    status: str
    evidence_ids: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    checks: tuple[dict[str, object], ...] = ()
    reason: str = ""
    # Counter-example IDs that matched this evidence window, kept on BOTH the
    # accepted and the rejected result so a reader can tell "the pattern was
    # present and independent evidence still closed the contract" from "the
    # pattern was present and is exactly why the contract did not close".
    counter_examples: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "status": self.status,
            "evidence_ids": list(self.evidence_ids),
            "missing": list(self.missing),
            "contradictions": list(self.contradictions),
            "checks": [dict(item) for item in self.checks],
            "reason": self.reason,
            "counter_examples": list(self.counter_examples),
        }


@dataclass(frozen=True)
class EvidenceContract:
    """Typed facts/relations required before a mechanism can be supported."""

    required_facts: tuple[str, ...] = ()
    required_relations: tuple[str, ...] = ()
    forbidden_inferences: tuple[str, ...] = ()
    fact_predicates: tuple[EvidencePredicate, ...] = ()
    relation_predicates: tuple[RelationPredicate, ...] = ()
    counter_examples: tuple[CounterExample, ...] = ()

    def __post_init__(self) -> None:
        facts = tuple(str(item).strip() for item in self.required_facts if str(item).strip())
        relations_required = tuple(str(item).strip() for item in self.required_relations if str(item).strip())
        object.__setattr__(self, "required_facts", facts)
        object.__setattr__(self, "required_relations", relations_required)
        predicates = list(self.fact_predicates)
        existing = {item.id for item in predicates}
        if len(existing) != len(predicates):
            raise ValueError("evidence predicate IDs must be unique within a contract")
        for fact in self.required_facts:
            if fact not in existing:
                predicates.append(EvidencePredicate.field(f"fact:{fact}", ("value", _fact_key(fact))))
        object.__setattr__(self, "fact_predicates", tuple(predicates))
        relations = list(self.relation_predicates)
        existing_relations = {item.id for item in relations}
        if len(existing_relations) != len(relations):
            raise ValueError("relation predicate IDs must be unique within a contract")
        for relation in relations_required:
            if relation not in existing_relations:
                relations.append(RelationPredicate(f"relation:{relation}", (relation,), require_same_object=True))
        object.__setattr__(self, "relation_predicates", tuple(relations))
        counter_ids = [item.id for item in self.counter_examples]
        if len(counter_ids) != len(set(counter_ids)):
            raise ValueError("counter-example IDs must be unique within a contract")
        # A counter-example must document a limit the contract itself states.
        # Registering one without the matching forbidden inference would let
        # the executable gate and the published contract drift apart.
        unstated = [
            item.id
            for item in self.counter_examples
            if not any(
                _counter_example_documented(item, text)
                for text in self.forbidden_inferences
            )
        ]
        if unstated:
            raise ValueError(
                "counter-example requires a matching forbidden_inferences entry: "
                + ", ".join(unstated)
            )

    @property
    def predicates(self) -> tuple[EvidencePredicate | RelationPredicate, ...]:
        return (*self.fact_predicates, *self.relation_predicates)

    def evaluate_counter_examples(
        self, evidence: Iterable[Mapping[str, object]]
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        """Return ``(counter_example_id, matched_row_ids)`` for every match."""
        rows = tuple(evidence)
        found: list[tuple[str, tuple[str, ...]]] = []
        for item in self.counter_examples:
            ids = item.matches(rows)
            if ids:
                found.append((item.id, ids))
        return tuple(found)

    def evaluate(self, evidence: Iterable[Mapping[str, object]]) -> ContractEvaluation:
        rows = tuple(evidence)
        checks: list[dict[str, object]] = []
        matched: list[str] = []
        missing: list[str] = []
        matched_counter_examples = self.evaluate_counter_examples(rows)
        blocked_rows = {
            row_id
            for _, row_ids in matched_counter_examples
            for row_id in row_ids
        }
        for item in self.counter_examples:
            ids = next(
                (row_ids for ce_id, row_ids in matched_counter_examples if ce_id == item.id),
                (),
            )
            checks.append(
                {
                    "id": item.id,
                    "type": "counter_example",
                    "passed": False,
                    "blocked": bool(ids),
                    "over_claim": item.over_claim,
                    "source": item.source,
                    "evidence_ids": list(ids)[:16],
                }
            )
        # Rows that carry a registered counter-example cannot supply this
        # contract's facts.  The pattern is present in the same row that would
        # have proven the behaviour, so the row is not evidence for it: a
        # once+delete task row cannot be the durable trigger, a runtime timing
        # query row cannot be the anti-analysis gate probe.
        usable_rows = tuple(
            row for row in rows if str(row.get("id")) not in blocked_rows
        )
        for predicate in self.fact_predicates:
            result = predicate.evaluate(usable_rows)
            checks.append({"id": predicate.id, "type": "fact", "passed": result.matched, "evidence_ids": list(result.matched_evidence_ids)[:16]})
            matched.extend(result.matched_evidence_ids)
            if not result.matched and predicate.required:
                missing.append(predicate.id)
        for predicate in self.relation_predicates:
            result = predicate.evaluate(usable_rows)
            checks.append({"id": predicate.id, "type": "relation", "passed": result.matched, "evidence_ids": list(result.matched_evidence_ids)[:16]})
            matched.extend(result.matched_evidence_ids)
            if not result.matched and predicate.required:
                missing.append(predicate.id)
        contradictions = tuple(
            str(row.get("id")) for row in rows if row.get("id") and _is_contradiction_row(row)
        )
        counter_ids = tuple(ce_id for ce_id, _ in matched_counter_examples)
        if contradictions:
            return ContractEvaluation(False, "CONTRADICTED", tuple(dict.fromkeys(matched)), tuple(missing), contradictions, tuple(checks), "explicit contradictory evidence is present", counter_ids)
        if counter_ids and missing:
            over_claims = "; ".join(
                item.over_claim
                for item in self.counter_examples
                if item.id in counter_ids
            )
            return ContractEvaluation(
                False,
                "COUNTER_EXAMPLE",
                tuple(dict.fromkeys(matched)),
                tuple(missing),
                (),
                tuple(checks),
                "registered counter-example withholds the evidence: " + over_claims,
                counter_ids,
            )
        if missing:
            return ContractEvaluation(False, "UNKNOWN", tuple(dict.fromkeys(matched)), tuple(missing), (), tuple(checks), "typed evidence contract is incomplete", counter_ids)
        return ContractEvaluation(True, "SUPPORTED_STATIC", tuple(dict.fromkeys(matched)), (), (), tuple(checks), "all typed facts and relations are present", counter_ids)

    def as_dict(self) -> dict[str, object]:
        """Return the complete, replayable contract definition."""
        return {
            "required_facts": list(self.required_facts),
            "required_relations": list(self.required_relations),
            "forbidden_inferences": list(self.forbidden_inferences),
            "fact_predicates": [item.as_dict() for item in self.fact_predicates],
            "relation_predicates": [item.as_dict() for item in self.relation_predicates],
            "counter_examples": [item.as_dict() for item in self.counter_examples],
        }


def _counter_example_documented(item: CounterExample, text: str) -> bool:
    """Whether one ``forbidden_inferences`` entry covers this counter-example.

    The published limit and the executable gate must stay in step.  The link is
    the documented over-claim text, compared on normalized words rather than a
    substring so a reworded inference cannot accidentally certify a different
    counter-example.
    """
    documented = _normalized_words(text)
    if not documented:
        return False
    claim = _normalized_words(item.over_claim)
    return bool(claim) and claim <= documented


def _normalized_words(text: object) -> frozenset[str]:
    return frozenset(
        word
        for word in re.split(r"[^a-z0-9]+", _norm(text))
        if word
    )


def _is_contradiction_row(row: Mapping[str, object]) -> bool:
    value = row.get("value")
    if not isinstance(value, Mapping):
        text = _norm(value)
        return any(token in text for token in ("contradicted", "refuted", "create_suspended"))
    status = _norm(value.get("status") or row.get("status"))
    return status in {"contradicted", "refuted", "rejected"}


def _fact_key(fact: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", fact.casefold()).strip("_")


def _fact(
    predicate_id: str,
    *paths: str,
    kinds: Iterable[str] = (),
    expected: Iterable[object] = (),
    required: bool = True,
) -> EvidencePredicate:
    return EvidencePredicate(
        id=predicate_id,
        paths=tuple(_parse_path(path) for path in paths),
        kinds=tuple(kinds),
        expected_values=tuple(expected),
        required=required,
    )


def _api(predicate_id: str, *symbols: str, kinds: Iterable[str] = ()) -> EvidencePredicate:
    return EvidencePredicate.api(predicate_id, symbols, kinds=kinds)


def _relation(
    predicate_id: str,
    relation: str,
    *,
    source_paths: Iterable[str] = (),
    target_paths: Iterable[str] = (),
    same_object: bool = False,
    kinds: Iterable[str] = (),
    required: bool = True,
) -> RelationPredicate:
    return RelationPredicate(
        id=predicate_id,
        relation_types=(relation,),
        source_paths=tuple(_parse_path(path) for path in source_paths),
        target_paths=tuple(_parse_path(path) for path in target_paths),
        kinds=tuple(kinds),
        require_same_object=same_object,
        required=required,
    )


_DECODE_OUTPUT_TO_PROCESS_COMMAND = _relation(
    "decode_output_to_process_command",
    "decode_output_to_process_command",
    source_paths=("value.output_buffer",),
    target_paths=("value.command_buffer", "value.input_buffer"),
    same_object=True,
    required=False,
)

# --------------------------------------------------------------------------
# Versioned minimal counter-examples (plan section 7, "最小反例" column).
#
# Each entry below is executable catalog data registered against a published
# ``forbidden_inferences`` line on the entry it protects.  They name the row
# that would otherwise have supplied a required fact, so the pattern the plan
# calls an over-claim cannot reach SUPPORTED_STATIC or CANDIDATE.
# --------------------------------------------------------------------------

# Section 7 row 11 - "once+run+delete 自动称长驻".  The row that carries the
# trigger is itself a one-shot task that deletes itself, so it is not evidence
# of a durable trigger.  A separate Run-key row that really is durable is
# untouched by this counter-example and can still close the contract.
_CE_PERSISTENCE_ONE_SHOT = counter_example(
    "ce:persistence:one-shot-trigger",
    "plan section 7 row 11 (persistence minimal counter-example)",
    "single execution plus delete is durable persistence",
    all_of=(
        EvidencePredicate.field("ce:persistence:trigger", "value.trigger"),
        _values_predicate(
            "ce:persistence:lifetime",
            "value.lifetime",
            "once",
            "one-shot",
            "one_shot",
            "oneshot",
            "single",
            "single run",
            "single-run",
            "/sc once",
            "run once",
            "temporary",
            "transient",
        ),
        EvidencePredicate.field("ce:persistence:cleanup", "value.cleanup"),
    ),
)

# Section 7 row 5 - "同进程 APC、普通异步 I/O".  A cross-process claim needs an
# explicit cross-process marker; a row that says the target is this process, or
# that the scope is the same process, cannot supply ``target_process``.
_CE_PROCESS_INJECTION_SAME_PROCESS = counter_example(
    "ce:process-injection:same-process-target",
    "plan section 7 row 5 (APC/remote injection minimal counter-example)",
    "same-process call is injection",
    all_of=(EvidencePredicate.field("ce:process-injection:target", "value.target_process"),),
    any_of=(
        _values_predicate(
            "ce:process-injection:scope",
            "value.process_scope",
            "same_process",
            "same-process",
            "self",
            "local",
            "current_process",
        ),
        _values_predicate("ce:process-injection:cross-process-flag", "value.cross_process", False),
        _values_predicate(
            "ce:process-injection:self-target",
            "value.target_process",
            "self",
            "current process",
            "current_process",
            "same process",
            "local process",
        ),
    ),
)

# Section 7 row 8 / M06 "PPID 即注入".  A parent-process attribute row chooses a
# parent; it is not a cross-address-space code transfer, so it cannot supply the
# injection target.  Row 8's own counter-example is "只 OpenProcess", and §2.2
# states PPID spoofing is parent attribute masquerading, not process injection.
_CE_PROCESS_INJECTION_PPID_ONLY = counter_example(
    "ce:process-injection:ppid-attribute-only",
    "plan section 7 row 8 (process/PPID minimal counter-example) and M06 'PPID/APC as injection'",
    "parent-process spoofing is not process injection",
    all_of=(EvidencePredicate.field("ce:process-injection:ppid-target", "value.target_process"),),
    any_of=(
        _values_predicate(
            "ce:process-injection:ppid-attribute",
            "value.attribute",
            "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        ),
        _api(
            "ce:process-injection:ppid-api",
            "UpdateProcThreadAttribute",
            "InitializeProcThreadAttributeList",
            "DeleteProcThreadAttributeList",
        ),
    ),
)

# Section 7 row 10 / M06 "网络即 C2".  A polling loop whose recovered handler
# side effect is explicitly not a side effect is a retry or health check, not
# command and control; that row cannot supply ``handler_side_effect``.
_CE_COMMUNICATION_LOOP_HEALTH_CHECK = counter_example(
    "ce:communication-loop:health-check-handler",
    "plan section 7 row 10 (communication loop minimal counter-example) and M06 'network as C2'",
    "a retry or health check handler is command and control",
    all_of=(
        _values_predicate(
            "ce:communication-loop:non-effect",
            "value.handler_side_effect",
            "none",
            "no side effect",
            "no effect",
            "no-op",
            "noop",
            "health check",
            "healthcheck",
            "keepalive",
            "keep-alive",
            "log only",
            "status only",
            "read only",
        ),
    ),
)

# Section 7 row 11 / M06 "注册表即持久化".  A row whose recovered trigger is a
# configuration/session-scoped write, or that explicitly says it does not
# autostart, is not a durable trigger.  The one-shot task shape is the separate
# ``ce:persistence:one-shot-trigger`` above.
_CE_PERSISTENCE_CONFIGURATION_TRIGGER = counter_example(
    "ce:persistence:configuration-trigger",
    "plan section 7 row 11 (persistence minimal counter-example) and M06 'task/registry as persistence'",
    "a configuration value write is durable persistence",
    all_of=(EvidencePredicate.field("ce:persistence:cfg-trigger", "value.trigger"),),
    any_of=(
        _any_field_values_predicate(
            "ce:persistence:cfg-trigger-kind",
            ("value.trigger_kind", "value.persistence_scope", "value.trigger_source"),
            (
                "configuration",
                "config",
                "settings",
                "setting",
                "preference",
                "on_demand",
                "on-demand",
                "manual",
                "session",
                "user_session",
                "process",
                "volatile",
            ),
        ),
        _values_predicate("ce:persistence:cfg-autostart", "value.autostart", False),
    ),
)

# Section 7 row 4 - "只有 CreateThread；入口是普通 runtime worker".  A row whose
# entry routine is declared to be the runtime's own thread bootstrap cannot
# supply a behaviour's ``entry_routine``.
_CE_THREAD_CALLBACK_RUNTIME_WORKER = counter_example(
    "ce:thread-and-callback:runtime-worker-entry",
    "plan section 7 row 4 (thread/callback minimal counter-example)",
    "a runtime worker entry is a callback",
    all_of=(
        EvidencePredicate.field("ce:thread-and-callback:entry", "value.entry_routine"),
        _any_field_values_predicate(
            "ce:thread-and-callback:entry-kind",
            ("value.entry_kind", "value.entry_role", "value.entry_source"),
            (
                "runtime",
                "runtime_worker",
                "runtime worker",
                "crt",
                "crt_thread",
                "threadpool_worker",
                "thread_pool_worker",
            ),
        ),
    ),
)

# Section 7 row 12 - "Rust CRT/异常处理或系统查询自动称反分析".  A row whose
# recovered gated behaviour is to continue is not a gate, so it cannot supply
# the ``gated_behavior`` fact of an environment guard.
_CE_ENVIRONMENT_GUARD_NON_GATING = counter_example(
    "ce:environment-guard:non-gating-probe",
    "plan section 7 row 12 (environment branch minimal counter-example)",
    "environment API alone proves anti-analysis",
    all_of=(
        _values_predicate(
            "ce:environment-guard:gated-behavior",
            "value.gated_behavior",
            "continue",
            "none",
            "no action",
            "proceed",
            "normal",
            "not gated",
            "ungated",
        ),
    ),
)

# Section 7 row 1 - "只看到资源 API 导入".  An import/string row naming a
# resource API cannot supply the recovered resource bytes of the new
# resource-extraction contract.
_CE_RESOURCE_EXTRACTION_API_ONLY = counter_example(
    "ce:resource-extraction:api-import-only",
    "plan section 7 row 1 (resource extraction minimal counter-example)",
    "resource API import alone proves resource extraction",
    all_of=(
        _values_predicate(
            "ce:resource-extraction:import-kind",
            "kind",
            "import_symbol",
            "import",
            "string",
            "api_import",
        ),
    ),
    any_of=(
        EvidencePredicate.api(
            "ce:resource-extraction:resource-api",
            (
                "FindResourceA",
                "FindResourceW",
                "FindResourceExA",
                "FindResourceExW",
                "LoadResource",
                "LockResource",
                "SizeofResource",
                "EnumResourceNamesA",
                "EnumResourceNamesW",
            ),
        ),
    ),
)

# Section 7 row 9 - "配置 URL 或 socket import，没有调用链".  A delete-API
# import row is likewise not a self-delete, and a URL string is not a download.
_CE_URL_STRING_ONLY = counter_example(
    "ce:download-and-drop:url-string-only",
    "plan section 7 row 9 (HTTP download minimal counter-example)",
    "a URL string proves a download occurred",
    all_of=(
        _values_predicate(
            "ce:download-and-drop:string-kind",
            "kind",
            "string",
            "config_value",
            "configuration",
        ),
        EvidencePredicate(
            id="ce:download-and-drop:url",
            paths=(("value", "url"), ("value", "endpoint")),
            require_truthy=True,
        ),
    ),
)

_CE_SELF_DELETE_IMPORT_ONLY = counter_example(
    "ce:self-delete:delete-import-only",
    "plan section 7 row 6/11 (cleanup minimal counter-example)",
    "a delete API import proves self-deletion",
    all_of=(
        _values_predicate(
            "ce:self-delete:import-kind",
            "kind",
            "import_symbol",
            "import",
            "api_import",
        ),
    ),
    any_of=(
        EvidencePredicate.api(
            "ce:self-delete:delete-api",
            ("DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW", "SetFileInformationByHandle"),
        ),
    ),
)


@dataclass(frozen=True)
class BehaviorCatalogEntry:
    """Stable, versioned investigation contract for one behaviour."""

    id: str
    version: str
    category: str
    discovery_seeds: tuple[str, ...]
    contract: EvidenceContract
    # Input/container families where the discovery profile may be useful.
    # This is metadata for routing, not evidence that the behaviour exists.
    applicability: tuple[str, ...] = ("pe", "script", "document")
    preferred_actions: tuple[str, ...] = ()
    attack_candidates: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    verifier_id: str | None = None
    verifier_version: str | None = None
    discovery: SupportLevel = SupportLevel.SUPPORTED
    executable_contract: SupportLevel = SupportLevel.PARTIAL
    executor: SupportLevel = SupportLevel.SUPPORTED
    verifier: SupportLevel = SupportLevel.PARTIAL
    real_validation: SupportLevel = SupportLevel.NOT_VALIDATED
    # Whether the declared behaviour-entry path
    # (``MechanismPlaybookRegistry.behavior_entry`` -> ``Verifier._evaluate_playbook``
    # -> ``verify_mechanism(entry.verifier_id)``) can actually reach this entry.
    # B03: an entry that advertises a specialist the claim gate can never invoke
    # must not describe itself as gated by it, and must record where the
    # specialist IS invoked instead (``verifier_call_paths``).
    verifier_reachable_from_entry_path: bool = True
    # Concrete main-path call sites for the specialist, for entries whose
    # specialist is invoked outside the behaviour-entry path.  Empty means the
    # entry path above is the only recorded route.
    verifier_call_paths: tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.version.strip():
            raise ValueError("catalog entry requires stable id and version")
        if not isinstance(self.contract, EvidenceContract):
            raise TypeError("catalog entry contract must be an EvidenceContract")
        for field_name in ("discovery", "executable_contract", "executor", "verifier", "real_validation"):
            value = getattr(self, field_name)
            if not isinstance(value, SupportLevel):
                try:
                    value = SupportLevel(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"invalid {field_name} support level: {value!r}") from exc
                object.__setattr__(self, field_name, value)
        object.__setattr__(
            self,
            "verifier_call_paths",
            tuple(str(item).strip() for item in self.verifier_call_paths if str(item).strip()),
        )
        if (
            self.verifier_id
            and self.verifier is SupportLevel.SUPPORTED
            and not self.verifier_reachable_from_entry_path
            and not self.verifier_call_paths
        ):
            raise ValueError(
                f"{self.id}: a specialist that no recorded main path can call "
                "cannot be declared supported"
            )
        object.__setattr__(
            self,
            "applicability",
            tuple(
                str(item).strip().casefold()
                for item in self.applicability
                if str(item).strip()
            ),
        )

    @property
    def support(self) -> Mapping[str, object]:
        return {
            "applicability": list(self.applicability),
            "discovery": self.discovery.value,
            "executable_contract": self.executable_contract.value,
            "executor": self.executor.value,
            "verifier": self.verifier.value,
            "verifier_reachable_from_entry_path": self.verifier_reachable_from_entry_path,
            "verifier_call_paths": (
                list(self.verifier_call_paths)
                if self.verifier_call_paths
                else (["verifier.evaluate->_evaluate_playbook"] if self.verifier_id else [])
            ),
            "real_validation": self.real_validation.value,
            "validation": self.real_validation.value,
        }

    @property
    def executor_support(self) -> SupportLevel:
        """Compatibility name used by the public B02 contract."""

        return self.executor

    @property
    def qualified_id(self) -> str:
        return f"{self.id}@{self.version}"

    @property
    def mechanism_type(self) -> str:
        return self.verifier_id or self.id


def _entry(
    entry_id: str,
    category: str,
    seeds: Iterable[str],
    facts: Iterable[str],
    relations: Iterable[str],
    actions: Iterable[str],
    *,
    attack: Iterable[str] = (),
    forbidden: Iterable[str] = (),
    aliases: Iterable[str] = (),
    verifier_id: str | None = None,
    verifier: SupportLevel = SupportLevel.PARTIAL,
    executable_contract: SupportLevel = SupportLevel.PARTIAL,
    notes: str = "",
    applicability: Iterable[str] = ("pe", "script", "document"),
    fact_predicates: Iterable[EvidencePredicate] = (),
    relation_predicates: Iterable[RelationPredicate] = (),
    counter_examples: Iterable[CounterExample] = (),
    verifier_reachable_from_entry_path: bool = True,
    verifier_call_paths: Iterable[str] = (),
) -> BehaviorCatalogEntry:
    return BehaviorCatalogEntry(
        id=entry_id,
        version="1.0.0",
        category=category,
        discovery_seeds=tuple(seeds),
        contract=EvidenceContract(
            tuple(facts),
            tuple(relations),
            tuple(forbidden),
            tuple(fact_predicates),
            tuple(relation_predicates),
            tuple(counter_examples),
        ),
        applicability=tuple(applicability),
        preferred_actions=tuple(actions),
        attack_candidates=tuple(attack),
        aliases=tuple(aliases),
        verifier_id=verifier_id,
        verifier_version="1.0.0" if verifier_id else None,
        verifier=verifier,
        executable_contract=executable_contract,
        verifier_reachable_from_entry_path=verifier_reachable_from_entry_path,
        verifier_call_paths=tuple(verifier_call_paths),
        notes=notes,
    )


def _standard_entries() -> tuple[BehaviorCatalogEntry, ...]:
    """Build the broad v1 map; unsupported dimensions remain explicit."""

    return (
        _entry("file-operations", "file", ("CreateFile", "WriteFile", "DeleteFile", "MoveFile"), ("path", "access", "buffer_source", "return_branch"), ("buffer_to_file_sink",), ("TRACE_API_ARGUMENT", "TRACE_RETURN_VALUE"), attack=("T1105",), aliases=("file-write",), forbidden=("filename string alone is a file operation",), fact_predicates=(_fact("path", "value.path", "value.file_path", "value.target_path"), _fact("access", "value.access", "value.desired_access"), _fact("size", "value.size", "value.length", required=False)), relation_predicates=(_relation("buffer_to_file_sink", "buffer_to_file_sink", source_paths=("value.source_buffer", "value.output_buffer"), target_paths=("value.target_file", "value.file_object")),)),
        _entry("file-metadata", "file_metadata", ("SetFileInformation", "SetFileAttributes", "timestomp", "ADS"), ("target", "attribute", "new_value", "condition"), ("metadata_to_target",), ("TRACE_API_ARGUMENT", "GET_DECOMPILE"), forbidden=("metadata API alone proves hiding",), notes="Discovery profile only; no dedicated verifier."),
        _entry("registry-operations", "registry", ("RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey"), ("hive", "key", "value_name", "type", "data", "return_branch"), ("handle_to_write",), ("TRACE_API_ARGUMENT", "TRACE_GLOBAL_USAGE"), aliases=("registry-modification", "registry-configuration", "REGISTRY_CONFIGURATION", "v3-registry-configuration"), forbidden=("registry API alone is persistence",), fact_predicates=(_fact("hive", "value.hive"), _fact("key", "value.key", "value.subkey"), _fact("value_name", "value.value_name", "value.name"), _fact("data", "value.data", "value.value_data")), relation_predicates=(_relation("handle_to_write", "handle_to_write", source_paths=("value.registry_handle", "value.handle"), target_paths=("value.registry_target", "value.key_object")),)),
        _entry("process-creation", "process", ("CreateProcess", "ShellExecute", "WinExec"), ("image_or_command", "creation_flags", "return_branch"), ("command_to_process_sink",), ("TRACE_API_ARGUMENT", "EVALUATE_CONSTANT"), attack=("T1059",), aliases=("process-execution", "PROCESS_EXECUTION", "PROCESS_CREATION", "command-execution", "COMMAND_EXECUTION", "v3-command-execution"), verifier_id="PROCESS_EXECUTION", verifier=SupportLevel.SUPPORTED, forbidden=("process import alone proves execution", "matching plaintext and command string is not a decode join"), fact_predicates=(_api("process_sink", "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "WinExec"), _fact("image_or_command", "value.image", "value.command", "value.command_line"), _fact("creation_flags", "value.creation_flags", "value.flags")), relation_predicates=(_relation("command_to_process_sink", "command_to_process_sink", source_paths=("value.command_buffer", "value.input_buffer"), target_paths=("value.process_sink", "value.target")), _DECODE_OUTPUT_TO_PROCESS_COMMAND)),
        _entry("child-process-output", "process", ("CreatePipe", "PeekNamedPipe", "ReadFile", "redirected stdout", "redirected stderr"), ("child_process", "pipe_handle", "output_buffer", "consumer"), ("child_to_output_pipe",), ("GET_CALLEES", "TRACE_API_ARGUMENT", "TRACE_RETURN_VALUE"), aliases=("SHELL_OUTPUT", "shell-output"), verifier_id="SHELL_OUTPUT", verifier=SupportLevel.SUPPORTED, verifier_reachable_from_entry_path=False, verifier_call_paths=("derivation.verify_mechanism(static_link_types['mechanism_shell_output_link'])", "investigation.apply_emulation_reverification(mechanism_type=SHELL_OUTPUT)"), forbidden=("CreatePipe alone proves command execution",), notes="B03: verify_shell_output_mechanism is registered and IS called on main paths, but no declared playbook resolves to this entry, so the behaviour-entry gate (Verifier.evaluate -> _evaluate_playbook) never evaluates this contract; the specialist is reached from static-link derivation instead."),
        _entry("parent-process-spoofing", "identity", ("PPID", "parent_process", "UpdateProcThreadAttribute", "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"), ("parent_selection", "access_mask", "attribute", "startup_info", "creation_flags"), ("parent_handle_to_attribute",), ("GET_CALLEES", "TRACE_API_ARGUMENT", "EVALUATE_CONSTANT"), attack=("T1134.004",), aliases=("PPID_SPOOFING", "PPID_SPOOF", "ppid-process-chain", "v3-ppid-spoof"), verifier_id="PPID_SPOOFING", verifier=SupportLevel.SUPPORTED, forbidden=("OpenProcess alone proves PPID spoofing"), relation_predicates=(_relation("parent_handle_to_attribute", "parent_handle_to_attribute", source_paths=("value.parent_handle", "value.source_handle"), target_paths=("value.attribute_handle", "value.target_handle")),)),
        _entry("identity-and-privilege", "identity", ("OpenProcessToken", "DuplicateToken", "AdjustTokenPrivileges", "CreateProcessWithToken"), ("token_source", "requested_privilege", "consumer", "return_branch"), ("token_to_consumer",), ("TRACE_API_ARGUMENT", "TRACE_RETURN_VALUE"), attack=("T1134",), forbidden=("token API alone proves privilege escalation",)),
        _entry("thread-and-callback", "thread", ("CreateThread", "CreateRemoteThread", "QueueUserAPC", "TLS", "threadpool"), ("entry_routine", "parameter", "trigger", "lifetime"), ("routine_to_thread",), ("GET_CALLEES", "TRACE_API_ARGUMENT", "GET_CFG_SLICE"), attack=("T1055",), aliases=("THREAD_CALLBACK", "thread-callback"), verifier_id="THREAD_CALLBACK", verifier=SupportLevel.SUPPORTED, verifier_reachable_from_entry_path=False, verifier_call_paths=("investigation.apply_emulation_reverification(mechanism_type=THREAD_CALLBACK)", "derivation.verify_mechanism(playbook.mechanism_type)"), forbidden=("thread API alone proves injection", "a runtime worker entry is a callback"), counter_examples=(_CE_THREAD_CALLBACK_RUNTIME_WORKER,), notes="B03: verify_thread_callback_mechanism is registered and IS called on main paths, but no declared playbook resolves to this entry, so the behaviour-entry gate (Verifier.evaluate -> _evaluate_playbook) never evaluates this contract; the specialist is reached from emulation re-verification instead."),
        _entry("process-injection", "process_manipulation", ("WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtMapViewOfSection"), ("source_region", "target_process", "target_region", "entry_routine"), ("cross_process_code_flow",), ("TRACE_API_ARGUMENT", "GET_CALLEES"), attack=("T1055",), aliases=("PROCESS_INJECTION", "process_injection"), forbidden=("same-process call is injection", "APC alone is remote injection", "parent-process spoofing is not process injection"), relation_predicates=(_relation("cross_process_code_flow", "cross_process_code_flow", source_paths=("value.source_region",), target_paths=("value.target_region",)),), counter_examples=(_CE_PROCESS_INJECTION_SAME_PROCESS, _CE_PROCESS_INJECTION_PPID_ONLY)),
        _entry("memory-and-mapping", "memory", ("VirtualAlloc", "VirtualProtect", "MapViewOfFile", "WriteProcessMemory"), ("region_identity", "size", "protection", "entry_point"), ("region_to_execution",), ("TRACE_API_ARGUMENT", "GET_PCODE_SLICE"), attack=("T1055",), aliases=("memory-execution", "memory-permission-change", "MEMORY_PERMISSION_CHANGE", "v3-memory-permission-change"), forbidden=("different regions may not be merged",)),
        _entry("loader-and-api-resolution", "loader", ("LoadLibrary", "GetProcAddress", "API hash", "manual map"), ("module_input", "api_identity", "resolver", "consumer"), ("resolved_pointer_to_call",), ("GET_XREFS_TO", "TRACE_RETURN_VALUE"), aliases=("dynamic-api-resolution", "DYNAMIC_API_RESOLUTION", "v3-api-hash-resolver", "API_HASH_RESOLVER", "plugin-load", "PLUGIN_LOAD", "PLUGIN_MODULE_LOAD", "manual-pe-load", "MANUAL_PE_LOAD", "v3-manual-pe-load"), verifier_id="DYNAMIC_API_RESOLUTION", verifier=SupportLevel.SUPPORTED, forbidden=("resolver import alone proves API use",), relation_predicates=(_relation("resolved_pointer_to_call", "resolved_pointer_to_call", source_paths=("value.resolved_pointer", "value.output_buffer"), target_paths=("value.consumer_pointer", "value.input_buffer"), same_object=True),)),
        _entry("config-and-crypto", "config_crypto", ("decode", "decrypt", "XOR", "AES", "CryptDecrypt", "RC4"), ("input_bytes", "algorithm", "key_or_state", "output_bytes", "output_hash"), ("output_to_consumer",), ("DECODE_CANDIDATE", "TRACE_RETURN_VALUE"), aliases=("decode-payload", "xor-config-recovery", "v3-config-decoder", "v3-string-decoder", "DECODE_CONFIG", "CONFIG_DECODER"), verifier_id="DECODE_CONFIG", verifier=SupportLevel.SUPPORTED, forbidden=("hook success alone is plaintext", "high entropy alone proves encryption", "API co-occurrence is not a decode consumer", "function xref is not a decode consumer", "matching plaintext and command string is not a decode join"), relation_predicates=(_relation("output_to_consumer", "output_to_consumer", source_paths=("value.output_buffer",), target_paths=("value.input_buffer",), same_object=True), _DECODE_OUTPUT_TO_PROCESS_COMMAND)),
        _entry("multi-stage-payload", "multi_stage", ("resource", "embedded", "decompress", "child payload", "drop"), ("parent_artifact", "child_hash", "transform", "entry_point"), ("parent_to_child",), ("READ_BYTES", "DECODE_CANDIDATE", "GET_FUNCTION"), attack=("T1027",), aliases=("MULTI_STAGE_PAYLOAD", "v3-multi-stage"), forbidden=("resource extraction alone proves execution",), relation_predicates=(_relation("parent_to_child", "parent_to_child", source_paths=("value.parent_object", "value.output_buffer"), target_paths=("value.child_object", "value.input_buffer")),)),
        _entry("resource-extraction", "multi_stage", ("FindResource", "LoadResource", "LockResource", "SizeofResource", "resource section"), ("resource_id", "resource_type", "module", "byte_range", "length", "copy_output"), ("resource_bytes_to_consumer",), ("READ_BYTES", "GET_DATA_REFERENCES", "TRACE_API_ARGUMENT"), attack=("T1027",), aliases=("RESOURCE_EXTRACTION", "resource-extract"), forbidden=("resource API import alone proves resource extraction",), fact_predicates=(_fact("resource_id", "value.resource_id", "value.name_id", "value.name"), _fact("resource_type", "value.resource_type", "value.type"), _fact("module", "value.module", "value.module_name", "value.artifact"), _fact("byte_range", "value.byte_range", "value.resource_offset", "value.offset"), _fact("length", "value.length", "value.size"), _fact("copy_output", "value.output_buffer", "value.copied_bytes", "value.resource_bytes")), relation_predicates=(_relation("resource_bytes_to_consumer", "resource_bytes_to_consumer", source_paths=("value.output_buffer", "value.resource_bytes"), target_paths=("value.input_buffer", "value.consumer_buffer")),), counter_examples=(_CE_RESOURCE_EXTRACTION_API_ONLY,), notes="Section 7 row 1: the resource identity, its real byte range, the copied output and that output's consumer are separate obligations; seeing a resource API import is not one of them."),
        _entry("download-and-drop", "multi_stage", ("URLDownloadToFile", "WinHttpReadData", "download", "drop", "write to temp"), ("source", "write_path", "write_api", "consumer"), ("download_to_file_sink",), ("TRACE_API_ARGUMENT", "GET_CALLEES", "TRACE_RETURN_VALUE"), attack=("T1105",), aliases=("DOWNLOAD_DROP", "download-drop", "v3-download-drop"), forbidden=("a URL string proves a download occurred",), relation_predicates=(_relation("download_to_file_sink", "download_to_file_sink", source_paths=("value.response_buffer", "value.output_buffer"), target_paths=("value.file_object", "value.target_file")),), counter_examples=(_CE_URL_STRING_ONLY,), notes="Section 7 row 9: the dropped file needs the transfer source, the write path, the write API and the file's consumer."),
        _entry("network-transport", "network", ("connect", "WinHttpSendRequest", "recv", "HTTP", "DNS"), ("role", "endpoint", "request", "response", "response_consumer"), ("response_to_consumer",), ("TRACE_API_ARGUMENT", "TRACE_RETURN_VALUE"), attack=("T1071",), aliases=("http-download", "HTTP_DOWNLOAD", "v3-network-transport", "NETWORK_TRANSPORT", "network-transport"), verifier_id="HTTP_DOWNLOAD", verifier=SupportLevel.SUPPORTED, forbidden=("URL/import alone proves active C2",), relation_predicates=(_relation("response_to_consumer", "response_to_consumer", source_paths=("value.response_buffer", "value.output_buffer"), target_paths=("value.consumer_buffer", "value.input_buffer"), same_object=True),)),
        _entry("communication-loop", "network_loop", ("poll", "retry", "heartbeat", "jitter", "back-off"), ("time_state", "message_format", "handler", "network_path", "handler_side_effect"), ("network_path_to_loop",), ("GET_CFG_SLICE", "TRACE_GLOBAL_USAGE"), attack=("T1071",), aliases=("COMMUNICATION_LOOP", "v3-communication-loop"), forbidden=("ordinary retry is heartbeat", "Sleep is not C2 tasking", "a retry or health check handler is command and control"), fact_predicates=(_fact("back_edge", "value.back_edge", "value.loop", required=False), _fact("time_state", "value.time_state", "value.delay", "value.timeout"), _fact("message_format", "value.message_format", "value.protocol"), _fact("handler", "value.handler", "value.consumer"), _fact("network_path", "value.network_path", "value.transport_call", "value.endpoint"), _fact("handler_side_effect", "value.handler_side_effect", "value.side_effect", "value.handler_output")), counter_examples=(_CE_COMMUNICATION_LOOP_HEALTH_CHECK,), notes="Section 7 row 10 requires the network path and the handler side effect, not only a timer and a message shape."),
        _entry("network-listener", "network", ("bind", "listen", "accept", "WSAAccept", "socket listen"), ("server_role", "bind_endpoint", "accept_loop", "connection_consumer"), ("accept_to_handler",), ("TRACE_API_ARGUMENT", "GET_CALLEES"), attack=("T1095",), aliases=("NETWORK_LISTENER", "network-listener", "service-listen"), forbidden=("socket import alone proves a listener",), relation_predicates=(_relation("accept_to_handler", "accept_to_handler", source_paths=("value.accepted_socket", "value.connection_handle"), target_paths=("value.handler_handle", "value.consumer_handle")),), notes="Section 7 row 9 server half: bind/listen/accept and the accepted-connection consumer are separate obligations from the client transport."),
        _entry("self-delete", "file", ("DeleteFile", "MoveFileEx", "SetFileInformationByHandle", "cleanup", "uninstall"), ("delete_target", "condition", "preceding_activity"), ("delete_to_self_target",), ("GET_CALLEES", "TRACE_API_ARGUMENT", "GET_CFG_SLICE"), aliases=("CLEANUP_SELF_DELETE", "cleanup-self-delete", "v3-cleanup-self-delete", "SELF_DELETE"), forbidden=("a delete API import proves self-deletion",), relation_predicates=(_relation("delete_to_self_target", "delete_to_self_target", source_paths=("value.delete_target_object", "value.source_object"), target_paths=("value.self_object", "value.target_object")),), counter_examples=(_CE_SELF_DELETE_IMPORT_ONLY,), notes="Section 7 row 6/11: a delete import is not a self-delete; the target identity, the condition and the preceding activity are separate facts."),
        _entry("command-dispatch", "command", ("opcode", "switch", "strcmp", "dispatcher"), ("input", "dispatch", "handler", "handler_side_effect"), ("input_to_handler",), ("GET_CFG_SLICE", "GET_CALLEES"), aliases=("v3-command-dispatch",), forbidden=("command string without dispatch proves backdoor",)),
        _entry("persistence", "persistence", ("RunOnce", "CreateService", "schtasks", "startup folder"), ("trigger", "payload", "permission", "lifetime", "cleanup"), ("trigger_to_payload",), ("TRACE_API_ARGUMENT", "GET_CALLEES"), attack=("T1547",), aliases=("registry-persistence", "scheduled-task-execution", "v3-registry-persistence", "v3-scheduled-task", "v3-service"), forbidden=("single execution plus delete is durable persistence", "a configuration value write is durable persistence"), counter_examples=(_CE_PERSISTENCE_ONE_SHOT, _CE_PERSISTENCE_CONFIGURATION_TRIGGER)),
        _entry("service-and-driver", "service_driver", ("CreateService", "StartService", "driver", "DeviceIoControl"), ("service_identity", "binary_path", "start_result", "ioctl"), ("service_to_payload",), ("TRACE_API_ARGUMENT", "GET_CALLEES"), attack=("T1543",), aliases=("service",), forbidden=("service-related strings alone prove persistence",)),
        _entry("host-discovery", "discovery", ("GetComputerName", "GetSystemInfo", "process enumeration", "security product"), ("probe", "collected_value", "consumer", "branch_effect"), ("probe_to_branch",), ("GET_CALLEES", "TRACE_API_ARGUMENT"), forbidden=("discovery API alone proves malicious intent",)),
        _entry("environment-guard", "defense_evasion", ("IsDebuggerPresent", "GetTickCount", "sandbox", "VM"), ("probe_input", "comparison", "threshold", "gated_behavior"), ("probe_to_branch",), ("GET_CFG_SLICE", "EVALUATE_CONSTANT"), aliases=("v3-environment-guard", "ENVIRONMENT_GUARD"), verifier_id="ENVIRONMENT_GUARD", verifier=SupportLevel.SUPPORTED, forbidden=("environment API alone proves anti-analysis",), fact_predicates=(_api("probe_input", "GetTickCount64", "GetTickCount", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GlobalMemoryStatus", "GlobalMemoryStatusEx", kinds=("function_call", "api_argument_trace")), _fact("comparison", "value.comparison", "value.threshold"), _fact("threshold", "value.threshold", "value.comparison"), _fact("gated_behavior", "value.gated_behavior", "value.return_branch", "value.exit")), relation_predicates=(_relation("probe_to_branch", "probe_to_branch", source_paths=("value.probe_input", "value.probe"), target_paths=("value.branch", "value.gated_behavior", "value.exit"), same_object=False, required=False),), counter_examples=(_CE_ENVIRONMENT_GUARD_NON_GATING,)),
        _entry("defense-evasion", "defense_evasion", ("ETW", "AMSI", "unhook", "self-modification", "timestomp"), ("target", "patch_or_change", "condition", "effect"), ("change_to_target",), ("READ_BYTES", "TRACE_API_ARGUMENT", "GET_PCODE_SLICE"), aliases=("etw-patch", "etw-amsi-patch", "v3-etw-amsi-patch", "ETW_PATCH", "ETW_AMSI_PATCH"), verifier_id="ETW_PATCH", verifier=SupportLevel.SUPPORTED, forbidden=("ETW/AMSI strings alone prove a patch", "DWORD value is not invented without evidence"), fact_predicates=(_fact("dword", "value.data", "value.dword", "value.value_data", required=False),)),
        _entry("defender-modification", "defense_evasion", ("DisableAntiSpyware", "MpPreference", "Windows Defender"), ("key", "value_name", "write_operation"), (), ("TRACE_API_ARGUMENT", "TRACE_GLOBAL_USAGE"), aliases=("DEFENDER_MODIFICATION",), forbidden=("Defender service killed", "complete disablement without value evidence", "DWORD value is not invented without evidence"), fact_predicates=(_fact("key", "value.key", "value.path", "value.subkey"), _fact("value_name", "value.value_name", "value.name"), _fact("write_operation", "value.api", "value.operation"), _fact("dword", "value.data", "value.dword", "value.value_data", required=False))),
        _entry("credentials-and-sensitive-data", "credentials", ("LSASS", "SAM", "DPAPI", "browser cookie", "keylog", "clipboard"), ("data_source", "access_method", "decryption", "consumer"), ("source_to_collection",), ("TRACE_API_ARGUMENT", "TRACE_RETURN_VALUE"), attack=("T1003",), forbidden=("DPAPI use alone proves credential theft",)),
        _entry("collection-and-exfiltration", "collection_exfil", ("archive", "screenshot", "clipboard", "upload", "exfil"), ("collection_source", "staging", "transform", "network_sink"), ("collected_to_network",), ("TRACE_GLOBAL_USAGE", "TRACE_RETURN_VALUE"), attack=("T1041",), forbidden=("collection alone proves exfiltration",), relation_predicates=(_relation("collected_to_network", "collected_to_network", source_paths=("value.staging_buffer", "value.output_buffer"), target_paths=("value.network_buffer", "value.input_buffer"), same_object=True),)),
        _entry("ipc", "ipc", ("named pipe", "mailslot", "shared memory", "ALPC", "COM", "mutex"), ("channel", "role", "message", "handler"), ("channel_to_handler",), ("GET_CALLEES", "TRACE_API_ARGUMENT"), aliases=("v3-ipc",), forbidden=("IPC API import proves command and control",)),
        _entry("lateral-movement", "lateral_movement", ("SMB", "PsExec", "WMI", "WinRM", "RDP", "DCOM"), ("remote_target", "credential_source", "remote_action", "return_branch"), ("credential_to_remote_action",), ("TRACE_API_ARGUMENT", "GET_CALLEES"), attack=("T1021",), forbidden=("protocol presence alone proves lateral movement",)),
        _entry("impact-and-resource-abuse", "impact", ("encrypt files", "shadow copy", "mass delete", "mining", "DoS"), ("target_scope", "transform", "recovery_effect", "condition"), ("operation_to_impact",), ("TRACE_API_ARGUMENT", "GET_CFG_SLICE"), attack=("T1486",), forbidden=("crypto API alone proves ransomware",)),
        _entry("unique-or-unknown", "unknown", (), ("entry", "state_transition", "input", "terminal_side_effect"), ("state_to_effect",), ("GET_DECOMPILE", "GET_PCODE_SLICE", "GET_CFG_SLICE"), verifier=SupportLevel.UNSUPPORTED, executable_contract=SupportLevel.UNSUPPORTED, notes="Open category for mechanisms outside the catalogue; never auto-promoted."),
    )


def default_behavior_catalog() -> tuple[BehaviorCatalogEntry, ...]:
    return _standard_entries()


# Compatibility record for legacy mechanism/profile IDs.  Every key below is a
# real identifier declared by ``investigation.MechanismPlaybookRegistry`` (a
# playbook ID, a ``mechanism_type`` or an older catalogue alias); catalogue
# 1.0.0 left these unresolvable, so
# ``MechanismPlaybookRegistry.behavior_entry`` fell back to "typed behaviour
# contract is unavailable" for ten declared profiles.  Value is
# ``(current behaviour id, catalogue version that first resolved it)``.  The
# mapping is data, not a code branch, so a version bump keeps old stored IDs
# resolvable and the compatibility claim is testable.
LEGACY_BEHAVIOR_IDS: Mapping[str, tuple[str, str]] = {
    "v3-download-drop": ("download-and-drop", "1.1.0"),
    "DOWNLOAD_DROP": ("download-and-drop", "1.1.0"),
    "download-drop": ("download-and-drop", "1.1.0"),
    "v3-cleanup-self-delete": ("self-delete", "1.1.0"),
    "CLEANUP_SELF_DELETE": ("self-delete", "1.1.0"),
    "cleanup-self-delete": ("self-delete", "1.1.0"),
    "v3-command-execution": ("process-creation", "1.1.0"),
    "COMMAND_EXECUTION": ("process-creation", "1.1.0"),
    "command-execution": ("process-creation", "1.1.0"),
    "v3-memory-permission-change": ("memory-and-mapping", "1.1.0"),
    "MEMORY_PERMISSION_CHANGE": ("memory-and-mapping", "1.1.0"),
    "memory-permission-change": ("memory-and-mapping", "1.1.0"),
    "v3-manual-pe-load": ("loader-and-api-resolution", "1.1.0"),
    "MANUAL_PE_LOAD": ("loader-and-api-resolution", "1.1.0"),
    "manual-pe-load": ("loader-and-api-resolution", "1.1.0"),
    "v3-registry-configuration": ("registry-operations", "1.1.0"),
    "REGISTRY_CONFIGURATION": ("registry-operations", "1.1.0"),
    "registry-configuration": ("registry-operations", "1.1.0"),
}

# Main-path playbook profiles that deliberately do not resolve to a behaviour
# entry, with the reason.  B02 requires the unknown mechanism to still enter
# investigation; it also requires the unmapped set to be declared instead of
# silently returning the legacy-threshold answer.
UNMAPPED_PLAYBOOK_PROFILES: Mapping[str, str] = {
    "generic-mechanism-investigation": "navigation profile with no trigger terms; never selected by best_match",
    "entrypoint-timeline": "call-ordering profile, not a behaviour category; has no typed contract by design",
}


def verifier_reachability(
    playbook_links: Iterable[tuple[str, str]],
    entries: Iterable[BehaviorCatalogEntry] | None = None,
) -> Mapping[str, tuple[str, ...]]:
    """Verifier IDs the behaviour-entry path can reach, and via which profiles.

    ``playbook_links`` are ``(playbook_id, mechanism_type)`` pairs from the
    declared main-path profiles.  Resolution mirrors
    ``MechanismPlaybookRegistry.behavior_entry``: the mechanism type is tried
    first, then the playbook ID.  A verifier that appears in no value here is
    never invoked from ``Verifier.evaluate`` -> ``_evaluate_playbook``, which
    B03 treats as not implemented *for that gate*: the behaviour contract of
    the affected entry is never evaluated either.  Such an entry must record
    the main paths that do call its specialist in ``verifier_call_paths``
    (``derive_static_mechanism_links`` link verification and
    ``apply_emulation_reverification`` are the two in this tree), otherwise it
    cannot claim supported verification.
    """
    catalog = entries if entries is not None else default_behavior_catalog()
    by_key: dict[str, BehaviorCatalogEntry] = {}
    for entry in catalog:
        for key in (entry.id, entry.qualified_id, *entry.aliases):
            by_key.setdefault(_norm(key), entry)
    reached: dict[str, list[str]] = {}
    for playbook_id, mechanism_type in playbook_links:
        entry = by_key.get(_norm(mechanism_type)) or by_key.get(_norm(playbook_id))
        if entry is None or not entry.verifier_id:
            continue
        reached.setdefault(entry.verifier_id, []).append(str(playbook_id))
    return {key: tuple(dict.fromkeys(value)) for key, value in reached.items()}


def unreachable_verifier_entries(
    playbook_links: Iterable[tuple[str, str]],
    entries: Iterable[BehaviorCatalogEntry] | None = None,
) -> tuple[BehaviorCatalogEntry, ...]:
    """Entries whose declared verifier the behaviour-entry path cannot call."""
    catalog = tuple(entries if entries is not None else default_behavior_catalog())
    reached = set(verifier_reachability(playbook_links, catalog))
    return tuple(
        entry
        for entry in catalog
        if entry.verifier_id and entry.verifier_id not in reached
    )


def unmapped_playbook_profiles(
    playbook_links: Iterable[tuple[str, str]],
    entries: Iterable[BehaviorCatalogEntry] | None = None,
) -> tuple[str, ...]:
    """Declared profiles whose IDs resolve to no catalogue behaviour."""
    catalog = BehaviorCatalog(entries)
    return tuple(
        str(playbook_id)
        for playbook_id, mechanism_type in playbook_links
        if catalog.by_id(mechanism_type) is None and catalog.by_id(playbook_id) is None
    )


class BehaviorCatalog:
    """Immutable registry with stable IDs, aliases and deterministic digest."""

    VERSION = "1.1.0"
    PREVIOUS_VERSIONS = ("1.0.0",)

    def __init__(self, entries: Iterable[BehaviorCatalogEntry] | None = None) -> None:
        self.entries = tuple(entries or default_behavior_catalog())
        ids = [item.id for item in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("behavior catalog IDs must be unique")
        aliases: dict[str, BehaviorCatalogEntry] = {}
        for item in self.entries:
            for key in (item.id, item.qualified_id, *item.aliases):
                normalized = _norm(key)
                previous = aliases.get(normalized)
                if previous is not None and previous.id != item.id:
                    raise ValueError(f"behavior catalog alias collision: {key}")
                aliases[normalized] = item
        for legacy_id, (current_id, _retired_in) in LEGACY_BEHAVIOR_IDS.items():
            target = aliases.get(_norm(current_id))
            if target is None:
                raise ValueError(f"legacy behaviour id {legacy_id} points outside the catalogue")
            normalized = _norm(legacy_id)
            previous = aliases.get(normalized)
            if previous is not None and previous.id != target.id:
                raise ValueError(f"legacy behaviour id collision: {legacy_id}")
            aliases[normalized] = target
        self._aliases = aliases

    def by_id(self, entry_id: str) -> BehaviorCatalogEntry | None:
        return self._aliases.get(_norm(entry_id))

    resolve = by_id

    def resolve_or_unknown(self, entry_id: str) -> BehaviorCatalogEntry:
        entry = self.by_id(entry_id)
        if entry is None:
            entry = self.by_id("unique-or-unknown")
        assert entry is not None
        return entry

    def matching_seed(self, text: str) -> tuple[BehaviorCatalogEntry, ...]:
        """Return discovery leads; this method never verifies a behaviour."""

        value = _norm(text)
        return tuple(item for item in self.entries if any(_norm(seed) in value for seed in item.discovery_seeds))

    def matching_evidence(self, evidence: Iterable[Mapping[str, object]]) -> tuple[BehaviorCatalogEntry, ...]:
        rows = tuple(evidence)
        typed_text: list[str] = []
        for row in rows:
            typed_text.extend(_explicit_api_values(row))
            value = _mapping(row, "value")
            for key in ("category", "behavior_id", "mechanism_type"):
                if isinstance(value.get(key), str):
                    typed_text.append(_norm(value[key]))
        text = " ".join(typed_text)
        return tuple(item for item in self.entries if any(_norm(seed) in text for seed in item.discovery_seeds))

    @property
    def digest(self) -> str:
        encoded = json.dumps(self._digest_data(), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def catalog_id(self) -> str:
        return f"behavior-catalog-v{self.VERSION}"

    def _digest_data(self) -> list[dict[str, object]]:
        return [
            {
                "id": item.id,
                "version": item.version,
                "category": item.category,
                "applicability": list(item.applicability),
                "facts": list(item.contract.required_facts),
                "relations": list(item.contract.required_relations),
                "contract": item.contract.as_dict(),
                "aliases": list(item.aliases),
                "verifier_id": item.verifier_id,
                "verifier_reachable_from_entry_path": item.verifier_reachable_from_entry_path,
                "support": dict(item.support),
            }
            for item in self.entries
        ]

    def as_dict(self) -> dict[str, object]:
        return {
            "catalog_id": self.catalog_id,
            "version": self.VERSION,
            "previous_versions": list(self.PREVIOUS_VERSIONS),
            "digest": self.digest,
            "entries": [
                {
                    "id": item.id,
                    "version": item.version,
                    "qualified_id": item.qualified_id,
                    "category": item.category,
                    "applicability": list(item.applicability),
                    "discovery_seeds": list(item.discovery_seeds),
                    "support": dict(item.support),
                    "required_facts": list(item.contract.required_facts),
                    "required_relations": list(item.contract.required_relations),
                    "forbidden_inferences": list(item.contract.forbidden_inferences),
                    "contract": item.contract.as_dict(),
                    "counter_examples": [
                        counter.as_dict() for counter in item.contract.counter_examples
                    ],
                    "preferred_actions": list(item.preferred_actions),
                    "attack_candidates": list(item.attack_candidates),
                    "alternatives": list(item.alternatives),
                    "aliases": list(item.aliases),
                    "verifier_id": item.verifier_id,
                    "verifier_version": item.verifier_version,
                    "verifier_reachable_from_entry_path": item.verifier_reachable_from_entry_path,
                    "notes": item.notes,
                }
                for item in self.entries
            ],
        }

    def coverage(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "id": item.id,
                "version": item.version,
                "category": item.category,
                "applicability": list(item.applicability),
                "support": dict(item.support),
                "verifier_id": item.verifier_id,
            }
            for item in self.entries
        )

    def compatibility(self) -> dict[str, object]:
        """Versioned compatibility record for stored/legacy behaviour IDs."""

        return {
            "catalog_id": self.catalog_id,
            "version": self.VERSION,
            "previous_versions": list(self.PREVIOUS_VERSIONS),
            "legacy_ids": {
                legacy: {"resolves_to": current, "since_version": since}
                for legacy, (current, since) in LEGACY_BEHAVIOR_IDS.items()
            },
            "unmapped_playbook_profiles": dict(UNMAPPED_PLAYBOOK_PROFILES),
        }

    def verifier_reachability(
        self, playbook_links: Iterable[tuple[str, str]]
    ) -> Mapping[str, tuple[str, ...]]:
        """Verifier IDs reachable from the declared main-path profiles."""

        return verifier_reachability(playbook_links, self.entries)

    def unreachable_verifier_entries(
        self, playbook_links: Iterable[tuple[str, str]]
    ) -> tuple[BehaviorCatalogEntry, ...]:
        """Entries whose declared verifier no declared profile can call."""

        return unreachable_verifier_entries(playbook_links, self.entries)

    def counter_examples(
        self,
    ) -> tuple[dict[str, object], ...]:
        """Every registered executable counter-example, with its owning entry."""

        return tuple(
            {
                "entry_id": entry.id,
                "entry_version": entry.version,
                **item.as_dict(),
            }
            for entry in self.entries
            for item in entry.contract.counter_examples
        )

    def evaluate(self, entry_id: str, evidence: Iterable[Mapping[str, object]]) -> ContractEvaluation:
        entry = self.by_id(entry_id)
        if entry is None:
            return ContractEvaluation(False, "UNKNOWN", (), (f"catalog:{entry_id}",), reason="behaviour is outside the declared catalogue")
        return entry.contract.evaluate(evidence)


def evaluate_evidence_contract(contract: EvidenceContract, evidence: Iterable[Mapping[str, object]]) -> ContractEvaluation:
    return contract.evaluate(evidence)


__all__ = [
    "BehaviorCatalog", "BehaviorCatalogEntry", "ContractEvaluation", "CounterExample",
    "EvidenceContract", "EvidencePredicate", "LEGACY_BEHAVIOR_IDS", "RelationPredicate",
    "PredicateMatch", "SupportLevel", "UNMAPPED_PLAYBOOK_PROFILES",
    "TypedEvidencePredicate", "TypedFactPredicate", "TypedRelationPredicate",
    "counter_example", "default_behavior_catalog", "evaluate_evidence_contract",
    "is_concrete_value", "is_unknown_or_negative", "object_identity",
    "unmapped_playbook_profiles", "unreachable_verifier_entries",
    "verifier_reachability",
]
