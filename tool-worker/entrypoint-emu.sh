#!/bin/sh
set -eu

mkdir -p "${TMPDIR:-/tmp}"

exec threat-report-agent worker --role tool --task-queue "${TOOL_TASK_QUEUE:-static-emu}"
