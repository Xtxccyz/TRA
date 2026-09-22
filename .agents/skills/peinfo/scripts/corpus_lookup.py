#!/usr/bin/env python3
"""Local corpus duplicate check -- is this file already in our own collected corpus?

Answers one question: does the local already-collected corpus (the EQGRP /
DanderSpritz / Shadow Brokers tree and friends) contain this exact file? If yes,
the file is someone else's already-collected artifact, and its provenance MUST be
explained before it is written up as a finding.

Mandatory gate before any sample enters a fact file. See SKILL.md
"样本进 fact 前的强制前置检查".

Why this exists (the 30-second check that was skipped):
  MD5 61110bea272972903985d5d5e452802c was written up as "an unpublished Slingshot
  userland RAT", purely because it was absent from Kaspersky's 5 published MD5s.
  It was byte-identical to EQGRP_Lost_in_Translation-master/windows/Resources/Df/
  Uploads/i386-winnt/DoubleFeatureDll.dll.unfinalized -- a file already indexed in
  this local corpus. Four facts plus a cross-organization code-reuse conclusion
  were built on it and all had to be retracted. This lookup takes ~30s.

Usage:
  py corpus_lookup.py <path-or-md5> [<path-or-md5> ...]
  py corpus_lookup.py --index <extra_index.json> <input> ...
  py corpus_lookup.py --show-indexes

Inputs: an existing file path (md5 computed), or a 32-hex MD5. The index is
MD5-keyed; for a SHA1/SHA256 input pass the file path or its MD5 instead.

Exit codes:
  0  ran; no input is in the local corpus (clean)
  2  no usable index found, or usage error
  3  at least one input IS in the local corpus -> explain provenance before proceeding
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Project corpus indexes, in preference order. The full tree index is complete
# (one entry per file); the small one is an md5 -> path map over a subset.
DEFAULT_INDEXES = [
    Path(r"E:\claudework\apt-anay\knowledge\nation-state-tools\nsa\_file_md5_index.json"),
    Path(r"E:\claudework\apt-anay\knowledge\nation-state-tools\nsa\_md5_index.json"),
]

ENV_VAR = "PEINFO_CORPUS_INDEX"


def discover_indexes(extra):
    """Ordered, de-duplicated, existing index paths."""
    out = []
    for raw in os.environ.get(ENV_VAR, "").split(os.pathsep):
        if raw.strip():
            out.append(Path(raw.strip()))
    out.extend(extra or [])
    out.extend(DEFAULT_INDEXES)
    seen, uniq = set(), []
    for p in out:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def sibling_root(path):
    """The small md5 map carries no root; borrow it from the full tree index
    sitting next to it, so results print as usable absolute paths."""
    sib = Path(path).parent / "_file_md5_index.json"
    if not sib.is_file() or sib.resolve() == Path(path).resolve():
        return None
    try:
        return json.loads(sib.read_text(encoding="utf-8")).get("root")
    except Exception:  # noqa: BLE001
        return None


def load_index(path):
    """Return (md5 -> [(display_path, size_or_None)], note).

    Two shapes are handled, both in use in this repo:
      _file_md5_index.json  {"root":..,"count":..,"files":{relpath:{"md5":..,"size":..}}}
      _md5_index.json       {md5: relpath}
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    root = data.get("root") if isinstance(data, dict) else None
    if not root:
        root = sibling_root(path)
    table = {}

    files = data.get("files") if isinstance(data, dict) else None
    if isinstance(files, dict):
        for rel, meta in files.items():
            if isinstance(meta, dict) and meta.get("md5"):
                table.setdefault(meta["md5"].lower(), []).append(
                    (join(root, rel), meta.get("size"))
                )
        return table, f"full tree index ({len(files)} files, root={root})"

    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and len(k) == 32 and _is_hex(k):
                table.setdefault(k.lower(), []).append((join(root, v), None))
        if table:
            return table, f"md5 map ({len(table)} entries, root={root})"

    return {}, "unrecognized index shape (skipped)"


def join(root, rel):
    if not root:
        return rel
    return str(Path(root) / rel)


def _is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", help="file paths or 32-hex MD5s")
    ap.add_argument("--index", action="append", default=[],
                    help="extra index json (repeatable)")
    ap.add_argument("--show-indexes", action="store_true",
                    help="list the index files that would be consulted, then exit")
    args = ap.parse_args()

    indexes = discover_indexes(args.index)

    if args.show_indexes:
        for p in indexes:
            state = "EXISTS" if Path(p).is_file() else "missing"
            print(f"  [{state}] {p}")
        return 0

    if not args.inputs:
        ap.print_help()
        return 2

    loaded = []
    for p in indexes:
        if not Path(p).is_file():
            continue
        try:
            table, note = load_index(p)
        except Exception as exc:  # noqa: BLE001
            print(f"[index] {p} -- FAILED to parse: {exc}")
            continue
        if table:
            loaded.append((p, table))
            print(f"[index] {p}\n        {note}")

    if not loaded:
        print(f"\nNo usable corpus index found. Checked:\n" +
              "\n".join(f"  {p}" for p in indexes) +
              f"\nSet {ENV_VAR} or pass --index <path>.")
        return 2
    print()

    hits = 0
    for raw in args.inputs:
        print(f"=== {raw}")
        if Path(raw).is_file():
            h = md5_of(raw)
            size = Path(raw).stat().st_size
            print(f"    md5 {h}  size {size}")
        elif len(raw) == 32 and _is_hex(raw):
            h = raw.lower()
        else:
            print("    SKIP: not an existing file path and not a 32-hex MD5")
            continue

        found, seen_paths = [], set()
        for index_path, table in loaded:
            for display, size in table.get(h, []):
                key = display.replace("/", "\\").lower()
                if key in seen_paths:      # same file reachable via both indexes
                    continue
                seen_paths.add(key)
                found.append((index_path, display, size))

        if found:
            hits += 1
            print("    PRESENT in local corpus:")
            for _idx, display, size in found:
                s = f"  ({size} B)" if size else ""
                print(f"      {display}{s}")
            print("    -> already-collected artifact. Explain its provenance BEFORE")
            print("       writing any fact / attribution claim about it.")
        else:
            print("    ABSENT from local corpus (clean)")
        print()

    print(f"summary: {hits}/{len(args.inputs)} present in local corpus")
    return 3 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
