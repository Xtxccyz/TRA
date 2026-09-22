#!/usr/bin/env python3
"""Run a granted Linux ELF in Qiling. Never opens a host sample_path."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    spec = json.load(sys.stdin)
    elf_path = str(spec.get("elf_path") or "")
    rootfs = str(spec.get("rootfs") or "")
    arch = str(spec.get("arch") or "x86_64")
    timeout_us = int(spec.get("timeout_us") or 1_000_000)
    count = int(spec.get("count") or 64)
    if not elf_path or not Path(elf_path).is_file():
        json.dump(
            {
                "status": "FAILED",
                "stop_reason": "MISSING_INPUT",
                "observations": [],
                "limitations": ["Qiling linux runner was not given an ELF tempfile"],
            },
            sys.stdout,
        )
        return 0
    if not rootfs or not Path(rootfs).is_dir():
        json.dump(
            {
                "status": "UNSUPPORTED",
                "stop_reason": "ROOTFS_REQUIRED",
                "observations": [],
                "limitations": ["Qiling linux runner has no pinned rootfs"],
            },
            sys.stdout,
        )
        return 0
    try:
        from qiling import Qiling
        from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
        import qiling
    except Exception as exc:
        json.dump(
            {
                "status": "UNAVAILABLE",
                "stop_reason": "IMPORT_UNAVAILABLE",
                "observations": [],
                "limitations": [f"Qiling linux import unavailable: {type(exc).__name__}"],
            },
            sys.stdout,
        )
        return 0
    archtype = QL_ARCH.X8664 if arch in {"x86_64", "amd64"} else QL_ARCH.X86
    try:
        ql = Qiling(
            [elf_path],
            rootfs,
            ostype=QL_OS.LINUX,
            archtype=archtype,
            verbose=QL_VERBOSE.OFF,
            console=False,
        )
        ql.run(timeout=timeout_us, count=count)
        json.dump(
            {
                "status": "SUCCEEDED",
                "stop_reason": "END_ADDRESS",
                "observations": [{"event": "summary", "kind": "control_flow"}],
                "limitations": [],
                "tool_version": getattr(qiling, "__version__", None),
            },
            sys.stdout,
        )
    except Exception as exc:
        json.dump(
            {
                "status": "FAILED",
                "stop_reason": "EXECUTION_ERROR",
                "observations": [],
                "limitations": [f"Qiling linux execution failed: {type(exc).__name__}"],
                "tool_version": getattr(qiling, "__version__", None),
                "error": str(exc)[:400],
            },
            sys.stdout,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
