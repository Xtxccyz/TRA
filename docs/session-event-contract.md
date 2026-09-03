# Session Event Contract v1

Backend audit events are projected to DSH `session/event` records by the
Threat Session plugin. The minimum event vocabulary is:

`threat/case-linked`, `threat/task-started`, `threat/task-status`,
`threat/thread-created`, `threat/thread-updated`, `threat/hypothesis-created`,
`threat/hypothesis-updated`, `threat/action-proposed`, `threat/action-started`,
`threat/action-completed`, `threat/action-rejected`, `threat/evidence-summary`,
`threat/mechanism-created`, `threat/mechanism-verified`,
`threat/mechanism-rejected`, `threat/claim-created`, `threat/claim-rejected`,
`threat/relation-created`, `threat/sample-timeline-updated`,
`threat/report-started`, `threat/report-ready`, and `threat/task-completed`.

Events contain IDs, state, counts, links, backend sequence, and a short summary.
They do not contain complete Evidence, sample bytes, prompts, model payloads,
or private chain-of-thought. The backend event cursor is persisted in
`interaction_session_links`; reconnect uses `after_seq` and is idempotent.
