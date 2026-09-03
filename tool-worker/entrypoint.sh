#!/bin/sh
set -eu

mkdir -p "${TMPDIR:-/work/tmp}"

if [ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
  echo "Ghidra analyzeHeadless is unavailable" >&2
  exit 78
fi

exec threat-report-agent worker --role tool --task-queue "${TOOL_TASK_QUEUE:-static-ghidra}"
