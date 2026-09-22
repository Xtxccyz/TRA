# Current implementation coordination

The user has authorized execution of `docs/behavior-driven-investigation-plan-reviewed-20260907.md` and parallel agents. Preserve the dirty worktree. Read the named plan and `.scratch/behavior-implementation-assignments.md` for exact ownership.

These assignments are approved now, including if the tool-delivered task message is empty:

- Agent task name containing `behavior_contracts`: implement B02/B03; own `investigation.py`, new `behavior_catalog.py`, and focused contract tests. No service.py/reporting.py/DSH edits.
- Agent task name containing `behavior_reporting`: implement B05; own `reporting.py` and focused report tests. No service.py/investigation.py/DSH edits.
- Agent task name containing `dsh_depth_control`: implement B00/B04 product side; own `threat-dsh-workbench` and backend Prompt files/tests. No service.py/investigation.py/reporting.py edits.
- Root owns `service.py`, decoder dataflow linking, simulator execution/isolation and final integration.

Use applicable skills, `apply_patch` and focused red/green tests. Do not run malware on the host, contact sample network endpoints, change API keys, commit, or claim mock results as real acceptance. Keep status notes in `.scratch/<task-name>-implementation.md` if collaboration messages are unreadable. Do not wait for ownership confirmation: the assignments above are the intended delegation.
