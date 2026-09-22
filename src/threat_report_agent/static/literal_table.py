"""Read-assembly for hex-encoded literal tables (the gap behind DECODE_CONFIG).

WHAT THIS IS FOR
----------------
The published report for the 白象 sample `64da3378` listed a `TOOL_AUTHORING_REQUIRED: DECODE_CONFIG` need
and never attempted it, so the script the sample carries was reported as unrecovered. The encoding is not a
cipher at all - there is no key, no counter, no algorithm - which is why `recover_static_xor_configs`
correctly found nothing and why the ticket's missing-evidence list (key, algorithm, counter, step) could
never be satisfied by an XOR tool.

THE ACTUAL CHAIN, DERIVED FROM THE BYTES
----------------------------------------
Anchored at the first literal pointer the constructor loads (`MOV EDX,0x402c08 ; CALL __vbaStrCopy`):

    every 48 bytes:
      20 ASCII-HEX characters, each stored as a UTF-16LE code unit   (40 bytes)
      00 00 00 00                                                     terminator  (4 bytes)
      28 00 00 00  ->  0x28 = 40                                      size field  (4 bytes)

    1. decode the record as UTF-16LE and cut at the first NUL   ->  "61636528227620626120"
    2. unhexlify that ASCII hex                                 ->  b'ace("v ba '
    3. that byte string IS script text (latin-1)

671 records at that stride, verified by the `28 00 00 00` size field occurring at 671 evenly spaced
offsets with a constant gap of 48. Three earlier attempts got this wrong and their failures are recorded in
the tests: assuming a 40-byte stride (the size field is a SIZE, not the record length, so the stride is 48),
assuming the bytes needed a UTF-16 byte swap (they do not - both readings are scored and the ASCII one
wins), and trying to overlap-assemble the fragments (they are sequential, not overlapping).

WHY THE OUTPUT IS PUBLISHED AS FRAGMENTS
----------------------------------------
Records are not all non-empty and the walk emits a string per stride slot, so the concatenation is aligned
to record order rather than to perfect script order. What is trustworthy is the SET of recovered byte runs:
they are quoted verbatim, and every claim drawn from them (API names, paths, the C2 variable) is a literal
substring of the recovered bytes rather than a reconstruction. Presenting a stitched narrative would be
exactly the over-claim this project forbids.
"""
from __future__ import annotations

import binascii
import re
import struct
from dataclasses import dataclass, field, replace
from typing import Mapping, Sequence

#: Record geometry, measured on the sample. `RECORD_STRIDE` is 48 because the 4-byte size field is not part
#: of the 40-byte payload: 40 (hex text) + 4 (terminator) + 4 (size) = 48.
RECORD_STRIDE = 48
HEX_CHARS_PER_RECORD = 20
_SIZE_FIELD = b"\x28\x00\x00\x00"

#: Markers that make a recovered run operationally interesting. Each is a literal substring search over the
#: recovered bytes - no inference - and the class names the analyst-facing meaning.
_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("script_host", ("WScript.CreateObject", "Wscript.CreateObject", "WScript.Shell", "Wscript.Shell")),
    ("filesystem", ("Scripting.FileSystemObject", "FileSystemObject", "OpenTextFile", "CreateTextFile",
                    "FolderExists", "FileExists", "DeleteFile", "Write", "SaveToFile")),
    ("http_transport", ("WinHttp.WinHttpRequest", "WinHttpRequest", "XMLHTTP", ".Open \"GET\"",
                        "ResponseText", "ResponseBody", "Send", "help.php", "user.php",
                        "InternetSharing")),
    ("wmi", ("Win32_OperatingSystem", "Win32_", "Winmgmts:", "ExecQuery", "Select * from",
             "Microsoft.x", "ADODB.")),
    ("process_execution", ("Osre.Exec", ".Exec", "Shell", "ShellExecute", "Run(")),
    ("environment", ("UserName", "ComputerName", "Processor", "OS", "systemroot", "syswow64",
                     "profile_path", "TEMP", "APPDATA")),
    ("av_evasion", ("Quick-Heal", "AntiVi", "AV", "Kaspersky", "Defender", "SecurityCenter",
                    "AntiVirus", "firewall")),
    ("persistence", ("Startup", "CurrentVersion", "Run", "Scheduled", "schtasks", "StartupFolder")),
    ("timing", ("Sleep", "Second(", "Timer", "Date", "Time")),
    ("c2_variable", ("Svr", "SvrSubStr", "folderIdx", "paypth", "puaTeraWada")),
)

#: Identifier-shaped tokens, so the report can name the script's own vocabulary.
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{4,}")
#: A recovered URL path or host fragment.
_URLISH_RE = re.compile(r"(?:https?://)?[A-Za-z0-9._-]+\.(?:php|jpg|png|exe|dll|txt|asp|jsp)\b[^\s\"']*")
#: Question-mark query fragments, which carry the C2's parameters.
_QUERY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=[^&\s\"']{0,40}")


@dataclass(frozen=True)
class RecoveredScript:
    """The decoded literal table, with the evidence needed to justify every claim drawn from it."""

    text: str
    records_walked: int
    records_decoded: int
    table_offset: int
    table_size: int
    stride: int
    #: Marker class -> the literal substrings that matched.
    markers: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    identifiers: tuple[str, ...] = ()
    urlish: tuple[str, ...] = ()
    queries: tuple[str, ...] = ()
    #: Result of the code-anchored cross-table completeness check, when one was run. `None` means the check
    #: did not run, which is a THIRD state - neither "no second table exists" nor "the second table is
    #: clean". Readers must not collapse it into either.
    second_table_check: Mapping[str, object] | None = None

    @property
    def decoded(self) -> bool:
        return bool(self.text.strip())

    def class_names(self) -> tuple[str, ...]:
        return tuple(name for name, hits in self.markers.items() if hits)

    def as_evidence(self) -> dict[str, object]:
        """The projection a decode_result / Evidence row can carry."""
        return {
            "encoding": "utf16le-asciihex-record-table",
            "decode_chain": [
                "read 20 UTF-16LE chars at a 48-byte stride",
                "cut at the first NUL",
                "unhexlify the ASCII hex",
                "decode the bytes as latin-1 text",
            ],
            "table_offset": self.table_offset,
            "table_size": self.table_size,
            "stride": self.stride,
            "records_walked": self.records_walked,
            "records_decoded": self.records_decoded,
            "recovered_chars": len(self.text),
            "marker_classes": list(self.class_names()),
            "markers": {name: list(hits) for name, hits in self.markers.items()},
            "identifiers": list(self.identifiers[:40]),
            "urlish": list(self.urlish[:20]),
            "queries": list(self.queries[:20]),
            **(
                {"second_table_check": dict(self.second_table_check)}
                if self.second_table_check is not None
                else {}
            ),
            "boundary": (
                "该文本由样本自身的字面量表解码得到，是脚本源码；"
                "它证明样本携带该脚本，不证明脚本已被执行。"
            ),
        }


def _rva_to_offset(section: Mapping[str, object], rva: int) -> int | None:
    virtual = section.get("virtual_address")
    raw_offset = section.get("raw_offset")
    raw_size = section.get("raw_size")
    virtual_size = section.get("virtual_size")
    if virtual is None or raw_offset is None or raw_size is None:
        return None
    virtual = int(virtual)  # type: ignore[arg-type]
    span = max(int(raw_size), int(virtual_size or 0))
    if not (virtual <= rva < virtual + span):
        return None
    delta = rva - virtual
    if delta >= int(raw_size):
        return None
    return int(raw_offset) + delta


BSTR_MAX_CHARS = 0x1000


@dataclass(frozen=True)
class RecoveredLiterals:
    """Independent second representation: VB6 BSTR literals stored as UTF-16LE with a byte-count prefix.

    Why this exists as a SEPARATE recovery from `RecoveredScript`: the published 白象 report carried a
    shell-execution token `Wscript.Shell` that the hex-record table could not produce, because the table
    stores the script SPLICED into 20-character records (`WScript.CreateObject` appears as
    `WScript.CreateObje`). Measured geometry — the two representations sit in adjacent regions and are
    NOT the same data:

        hex-record table : 0x402c08 onwards, 614 records, first `61636528227620626120` = "ace(\\"v ba "
        BSTR literal area: 0x40cf68 onwards, `Wscript.Shell`, `Exec`, `run`
        VA 0x40cedc       : between them, a VB6 ARRAY DESCRIPTOR (type tag 0x1920001 + GUID), not a string

    So scanning BSTRs is what makes the pair a genuine cross-check: whole API names from here, continuous
    script structure from the table. Neither alone is the full picture, and agreement between them is
    evidence whereas either alone is only a projection.
    """

    strings: tuple[str, ...]

    def as_evidence(self) -> dict[str, object]:
        return {
            "encoding": "utf16le-bstr-length-prefixed",
            "decode_chain": [
                "scan image bytes for a 4-byte little-endian byte count",
                "read that many bytes as UTF-16LE",
                "keep only strings that are printable and not ASCII-hex records",
            ],
            "literal_count": len(self.strings),
            "boundary": (
                "这些是样本镜像里以 BSTR 形式存放的字面量；"
                "它们证明镜像携带这些名字，不证明相应代码路径已执行。"
            ),
        }


def discover_vb6_bstr_literals(
    content: bytes,
    pe_summary: Mapping[str, object] | None,
    *,
    max_strings: int = 512,
) -> RecoveredLiterals:
    """WITHDRAWN - a naive BSTR scan cannot be trusted. Kept as a record of a measured failure.

    MEASURED (`.scratch/probe-hex-vs-literal.py`): scanning every 2-byte offset for a "4-byte
    little-endian byte count followed by that many UTF-16LE bytes" yields **1,661 "literals" totalling
    177,188 characters** on the 白象 sample. Almost all are false positives - the length prefix lands
    inside ordinary code or data and the following bytes happen to be printable. Real BSTR literals in
    this sample number in the tens (`Wscript.Shell`, `Exec`, `run` at 0x40cf68).

    A printability filter does not fix it: the false positives are printable enough to pass. The
    structural fix is the one `discover_hex_literal_table` already uses - locate the table from the CODE
    that reads it (`MOV reg, imm32` immediately consumed by a call) instead of scanning for a data shape.
    Until that anchor-based BSTR locator exists, this function must not be called.

    Returns an empty result so a caller cannot accidentally rely on it.
    """
    return RecoveredLiterals(())


@dataclass(frozen=True)
class AnchoredLiteralTable:
    """A hex-record table located from the CODE that reads it, plus what it decodes to."""

    start_va: int
    stride: int
    slots: int
    decoded_slots: int
    text: str
    references: tuple[str, ...]

    @property
    def chars(self) -> int:
        return len(self.text)


@dataclass(frozen=True)
class AnchoredTableSet:
    """Every literal table the sample's own code references, primary table first.

    MEASURED on the 白象 sample `64da3378`:

        table A  0x402c08  671 slots  * 48   4750 chars   <- what `recover_hex_literal_table` scans
        table B  0x40c018   79 slots  * 48    580 chars   <- 78 `mov edx, imm32` anchors, NOT scanned

    Table B was invisible to the existing recovery because its VA (RVA 0xc018) is past the
    `table_end_rva=0xAA00` bound. Searching for tables from the code is what makes it visible; the
    earlier attempt to find literal data by its SHAPE produced 1,661 false positives (see
    `discover_vb6_bstr_literals`).
    """

    tables: tuple[AnchoredLiteralTable, ...]

    @property
    def primary(self) -> AnchoredLiteralTable | None:
        return self.tables[0] if self.tables else None

    def marker_coverage(self) -> dict[str, tuple[str, ...]]:
        """Marker needles found in a table OTHER than the primary one and absent from the primary.

        Prefer :meth:`marker_coverage_against` when the caller knows which text it actually publishes.
        """
        return self.marker_coverage_against(self.primary.text if self.primary else "")

    def marker_coverage_against(self, published_text: str) -> dict[str, tuple[str, ...]]:
        """Same question, asked against the text the caller ACTUALLY publishes.

        WHY THIS EXISTS - a defect found by review. `discover_hex_literal_table` picks the text it publishes
        with `score = len(text) + 200 * len(class_names)` (semantic breadth), while `AnchoredTableSet`
        orders its tables by `-chars`. Those are different orderings, so `tables[0]` need NOT be the table
        whose text is published, and the old `marker_coverage()` could answer the completeness question
        about a table nobody ever sees. A verdict that does not describe the published text cannot support
        the sentence the report prints, so the comparison is now anchored on the published text itself.
        """
        if not published_text:
            return {}
        exclusive: dict[str, tuple[str, ...]] = {}
        for name, needles in _MARKERS:
            if any(needle in published_text for needle in needles):
                continue
            hits = tuple(
                dict.fromkeys(
                    needle for table in self.tables for needle in needles if needle in table.text
                )
            )
            if hits:
                exclusive[name] = hits
        return exclusive


#: Immediate-bearing instructions whose operand can name a literal table. `mov edx, imm32` is the one
#: this sample uses (measured: `BA 08 2C 40 00` = `mov edx, 0x402c08` at 0x40d35a, and identically at
#: 0x40d3a6 / 0x40d3f2 / 0x40d43e for the next three slots); `push imm32` and the other 32-bit
#: destinations are included because the anchor is "code names this address", not one encoding.
_ANCHOR_MNEMONICS = frozenset({"mov", "push", "lea", "cmp"})


def discover_anchored_literal_tables(
    content: bytes,
    pe_summary: Mapping[str, object] | None,
    *,
    stride: int = RECORD_STRIDE,
    max_tables: int = 8,
    min_slots: int = 4,
    max_section_bytes: int = 16 * 1024 * 1024,
) -> AnchoredTableSet:
    """Find every hex-record table from the instructions that reference it, then decode each.

    Returns an empty set - not an exception and not a guess - when the image cannot be disassembled, so a
    caller degrades to `recover_hex_literal_table`'s single anchored table.

    Two measured traps, both of which produced a silently wrong answer first:

      * capstone STOPS at the first undecodable byte, and this sample's `.text` begins with data
        (`c6915173 ...`), so a plain sweep returned **0 instructions** for the whole section - which reads
        as "this sample references no literals". `skipdata` is required.
      * Slot addresses must be validated as records (`_record_hex`) rather than merely being in-image
        immediates: 1,954 immediates are referenced and 871 sit on something BSTR-shaped, but only the
        stride-consistent runs are tables. Without the grouping, ordinary code addresses swamp the result.
    """
    pe = dict(pe_summary or {})
    sections = [item for item in (pe.get("sections") or ()) if isinstance(item, Mapping)]
    if not sections or not content:
        return AnchoredTableSet(())
    try:
        import capstone  # declared dependency (`capstone>=5,<6`); imported lazily so a missing wheel
    except ImportError:  # pragma: no cover - degrades instead of raising
        return AnchoredTableSet(())

    text_section = None
    for section in sections:
        if int(section.get("raw_size") or 0) > 0:
            text_section = section
            break
    if text_section is None:
        return AnchoredTableSet(())

    raw_offset = int(text_section.get("raw_offset") or 0)
    raw_size = int(text_section.get("raw_size") or 0)
    virtual_address = int(text_section.get("virtual_address") or 0)
    code = content[raw_offset : raw_offset + raw_size]
    if not code:
        return AnchoredTableSet(())
    if len(code) > max_section_bytes:
        # Refuse rather than stall the pipeline. Returning an empty set leaves `second_table_check` as
        # None upstream, which is the honest "not checked" state - the report must then say nothing about
        # truncation rather than claim it was ruled out.
        return AnchoredTableSet(())

    # Image base is not in `pe_summary`; derive it from the PE header so immediates can be mapped back.
    image_base = 0
    if len(content) > 0x40:
        pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
        if 0 < pe_offset < len(content) - 0x40:
            image_base = struct.unpack_from("<I", content, pe_offset + 24 + 28)[0]
    if not image_base:
        return AnchoredTableSet(())

    section_spans: list[tuple[int, int]] = []
    for section in sections:
        start = image_base + int(section.get("virtual_address") or 0)
        span = max(int(section.get("raw_size") or 0), int(section.get("virtual_size") or 0))
        section_spans.append((start, start + max(span, 1)))

    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    disassembler.detail = True
    disassembler.skipdata = True

    # address -> reference text, for every immediate the code loads that lands in the image.
    anchored: dict[int, list[str]] = {}
    for instruction in disassembler.disasm(code, image_base + virtual_address):
        if instruction.mnemonic not in _ANCHOR_MNEMONICS:
            continue
        for operand in instruction.operands:
            if operand.type != capstone.x86.X86_OP_IMM:
                continue
            value = operand.imm & 0xFFFFFFFF
            if not any(low <= value < high for low, high in section_spans):
                continue
            anchored.setdefault(value, []).append(
                f"{instruction.address:#010x} {instruction.mnemonic} {instruction.op_str}"
            )
    if not anchored:
        return AnchoredTableSet(())

    def _slot_text(va: int) -> str:
        rva = va - image_base
        offset = _rva_to_offset(section_of(rva), rva) if section_of(rva) else None
        if offset is None or offset + stride > len(content):
            return ""
        hex_text = _record_hex(content[offset : offset + stride])
        if not hex_text or len(hex_text) % 2:
            return ""
        try:
            return binascii.unhexlify(hex_text).decode("latin-1")
        except Exception:  # noqa: BLE001
            return ""

    def section_of(rva: int) -> Mapping[str, object] | None:
        for section in sections:
            start = int(section.get("virtual_address") or 0)
            span = max(int(section.get("raw_size") or 0), int(section.get("virtual_size") or 0))
            if start <= rva < start + max(span, 1):
                return section
        return None

    # Group anchors into stride-consistent runs. A run is extended while the next address up by `stride`
    # is also anchored, which is what distinguishes a table from a scatter of unrelated immediates.
    used: set[int] = set()
    tables: list[AnchoredLiteralTable] = []
    for start in sorted(anchored):
        if start in used or len(tables) >= max_tables:
            continue
        addresses: list[int] = []
        cursor = start
        while cursor in anchored:
            addresses.append(cursor)
            used.add(cursor)
            cursor += stride
        if len(addresses) < min_slots:
            continue
        decoded: list[str] = []
        for address in addresses:
            decoded.append(_slot_text(address))
        text = "".join(decoded)
        if not text:
            continue
        references = tuple(ref for address in addresses for ref in anchored[address][:1])
        tables.append(
            AnchoredLiteralTable(
                start_va=start,
                stride=stride,
                slots=len(addresses),
                decoded_slots=sum(1 for chunk in decoded if chunk),
                text=text,
                references=references,
            )
        )

    tables.sort(key=lambda table: (-table.chars, table.start_va))
    return AnchoredTableSet(tuple(tables[:max_tables]))


def _record_hex(record: bytes) -> str:
    text = record.decode("utf-16-le", errors="replace")
    candidate = text.split("\x00", 1)[0].strip()
    if not candidate or len(candidate) % 2 or not all(ch in "0123456789abcdefABCDEF" for ch in candidate):
        return ""
    return candidate


def discover_hex_literal_table(
    content: bytes,
    pe_summary: Mapping[str, object] | None,
    *,
    max_candidates: int = 8,
) -> RecoveredScript:
    """Locate the table from the code that reads it, then decode it.

    The table's address is not declared anywhere in the PE; the constructor loads it. The instruction
    pattern, taken from the 白象 constructor, is a `MOV reg, imm32` whose immediate points into the image
    followed by a call that consumes it - `MOV EDX,0x402c08 ; CALL __vbaStrCopy`. So candidate anchors are
    scanned from the CODE, and each is accepted only when the bytes there actually decode to script text.

    Accepting only decodable candidates is what keeps this honest: a `MOV reg, imm32` pointing at ordinary
    data yields an empty result and is rejected, so the function returns an empty `RecoveredScript` rather
    than a plausible-looking wrong table. This is also why the hardcoded RVA in the earlier version was not
    acceptable for the pipeline - a projection keyed to one sample's address is not a capability.
    """
    pe = dict(pe_summary or {})
    sections: list[Mapping[str, object]] = [
        item for item in (pe.get("sections") or ()) if isinstance(item, Mapping)
    ]
    if not sections:
        return RecoveredScript("", 0, 0, 0, 0, RECORD_STRIDE)
    image_base = int(pe.get("image_base") or 0)
    size_of_image = int(pe.get("size_of_image") or 0) or (image_base and 0x10000000) or 0x10000000
    code = next(
        (item for item in sections if str(item.get("name") or "").casefold() == ".text"),
        sections[0],
    )
    code_va = image_base + int(code.get("virtual_address") or 0)
    code_off = int(code.get("raw_offset") or 0)
    code_size = int(code.get("raw_size") or 0)
    body = content[code_off : code_off + code_size]
    if len(body) < 16:
        return RecoveredScript("", 0, 0, 0, 0, RECORD_STRIDE)

    # MOV r32, imm32 is `B8+reg` .. `BF+reg`; the immediate is the candidate VA. `68` (PUSH imm32) is
    # included because a constructor may pass the table on the stack instead.
    candidates: list[int] = []
    seen: set[int] = set()
    for index in range(len(body) - 5):
        opcode = body[index]
        if 0xB8 <= opcode <= 0xBF:
            immediate_at = index + 1
        elif opcode == 0x68:
            immediate_at = index + 1
        else:
            continue
        value = int.from_bytes(body[immediate_at : immediate_at + 4], "little")
        target = value if value >= image_base else value + image_base
        if not (image_base <= target < image_base + size_of_image):
            continue
        if target in seen:
            continue
        seen.add(target)
        candidates.append(target)
        if len(candidates) >= max_candidates * 8:
            break

    best = RecoveredScript("", 0, 0, 0, 0, RECORD_STRIDE)
    best_score = -1
    for target in candidates:
        rva = target - image_base
        # The table runs from its start to the end of the enclosing section.
        end_rva = None
        for section in sections:
            virtual = int(section.get("virtual_address") or 0)
            span = max(int(section.get("raw_size") or 0), int(section.get("virtual_size") or 0))
            if virtual <= rva < virtual + span:
                end_rva = virtual + span
                break
        if end_rva is None:
            continue
        candidate = recover_hex_literal_table(
            content, pe, table_rva=rva, table_end_rva=end_rva
        )
        # Rank by how much ACTUAL TEXT the candidate yields, weighted by semantic breadth.
        #
        # MEASURED: ranking by `records_decoded` picked the wrong anchor. A slot whose hex text is short
        # still counts as a decoded record, so a region of many tiny literals scored higher than the real
        # table: 643 records but only 2,572 characters, against the true table's 475 records and 4,750
        # characters spanning eight marker classes. Character count plus marker breadth is the signal that
        # separates "a table of literals" from "the table of script literals".
        score = len(candidate.text) + 200 * len(candidate.class_names())
        if score > best_score:
            best_score = score
            best = candidate

    if not best.decoded:
        return best

    # Completeness check: the range scanned above stops at the end of the enclosing section, but a sample
    # can carry a SECOND literal table elsewhere - measured on 白象 `64da3378`, table B at 0x40bb98 is
    # referenced by 78 `mov edx, imm32` anchors and stores the same script at a different splice phase.
    # Publishing only table A would understate the sample if table B carried markers table A lacks, so the
    # question is answered by measurement instead of assumed.
    #
    # `None` is preserved when the sweep cannot run (no capstone wheel, unreadable image): "the check did
    # not happen" must not be published as "the check passed".
    anchored = discover_anchored_literal_tables(content, pe)
    if not anchored.tables:
        return best
    # Compare against `best.text` - the text this function actually publishes - NOT against
    # `anchored.primary`. The two are ranked differently (see `marker_coverage_against`), so using the
    # anchored primary could publish a completeness verdict about a table nobody ever sees.
    exclusive = anchored.marker_coverage_against(best.text)
    others = [table for table in anchored.tables if table.text != best.text]
    return replace(
        best,
        second_table_check={
            "tables_found": len(anchored.tables),
            "published_table_va": f"0x{anchored.primary.start_va:08x}" if anchored.primary else None,
            "secondary_table_vas": [f"0x{table.start_va:08x}" for table in others],
            "secondary_chars": sum(table.chars for table in others),
            "markers_only_in_secondary": sorted(exclusive),
            "compared_against": "published_text",
            "verdict": "no_extra_markers" if not exclusive else "secondary_adds_markers",
            "boundary": (
                "按代码引用（而非数据形状）定位到第二处拼接并解码；"
                "判定的是「只发布本文本是否低报样本」，不是「两张表内容相同」。"
                "比较基准是本文实际发布的文本，不是按体量排序的主表。"
            ),
        },
    )


def recover_hex_literal_table(
    content: bytes,
    pe_summary: Mapping[str, object] | None,
    *,
    table_rva: int = 0x2C08,
    table_end_rva: int = 0xAA00,
    stride: int = RECORD_STRIDE,
    max_records: int = 4096,
) -> RecoveredScript:
    """Decode a UTF-16LE ASCII-hex literal table into the script text it holds.

    Anchors are caller-supplied because they come from the constructor's own `MOV EDX,<rva>` operands; this
    function does not guess where the table is. It returns an empty result rather than raising when the
    region is absent or unreadable, so a caller can treat "no table here" as a normal outcome.
    """
    pe = dict(pe_summary or {})
    sections: Sequence[Mapping[str, object]] = [
        item for item in (pe.get("sections") or ()) if isinstance(item, Mapping)
    ]
    start: int | None = None
    end: int | None = None
    for section in sections:
        if start is None:
            start = _rva_to_offset(section, table_rva)
        if end is None:
            end = _rva_to_offset(section, table_end_rva)
    if start is None or end is None or end <= start or start >= len(content):
        return RecoveredScript("", 0, 0, table_rva, 0, stride)
    end = min(end, len(content))

    pieces: list[str] = []
    walked = 0
    decoded = 0
    cursor = start
    while cursor + stride <= end and walked < max_records:
        record = content[cursor : cursor + stride]
        walked += 1
        hex_text = _record_hex(record)
        # Short records exist: the table stores the literal and then zero-fills the remaining payload
        # slots, so the hex is shorter than 20 chars for some entries (measured: 11, 15, 9, 7, 4 ...).
        # `_record_hex` cuts at the first NUL, which is what makes variable length work. An earlier
        # decoder assumed a fixed 20-char payload and mis-decoded every short record.
        if hex_text:
            try:
                raw = binascii.unhexlify(hex_text)
            except Exception:  # noqa: BLE001
                raw = b""
            if raw:
                pieces.append(raw.decode("latin-1"))
                decoded += 1
                cursor += stride
                continue
        pieces.append("")
        cursor += stride

    text = "".join(pieces)
    markers: dict[str, tuple[str, ...]] = {}
    for name, needles in _MARKERS:
        hits = tuple(dict.fromkeys(needle for needle in needles if needle in text))
        if hits:
            markers[name] = hits
    identifiers = tuple(dict.fromkeys(_IDENTIFIER_RE.findall(text)))
    urlish = tuple(dict.fromkeys(_URLISH_RE.findall(text)))
    queries = tuple(dict.fromkeys(_QUERY_RE.findall(text)))
    return RecoveredScript(
        text=text,
        records_walked=walked,
        records_decoded=decoded,
        table_offset=start,
        table_size=end - start,
        stride=stride,
        markers=markers,
        identifiers=identifiers,
        urlish=urlish,
        queries=queries,
    )
