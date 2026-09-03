# Backend Workbench API v1

The DSH integration surface is versioned under `/api/v1/workbench`.

| Endpoint | Purpose |
|---|---|
| `GET /capabilities/static-actions` | Closed Action Catalog manifest |
| `GET /cases/{case_id}` | Case and task projection |
| `GET /artifacts/{artifact_id}` | Artifact summary and bounded evidence index |
| `GET /tasks/{task_id}` | Domain projection for Workbench views |
| `GET/POST /tasks/{task_id}/session` | Unique primary DSH session mapping |
| `GET /tasks/{task_id}/events?after_seq=&limit=` | Ordered reconnectable event stream |
| `POST /evidence/query` | Bounded, task-scoped Evidence query |
| `GET /tasks/{task_id}/report` | Latest Report Revision projection |

All responses include `schema_version` where the projection is persisted or
replayed. Event `seq` is monotonic within a task and `after_seq` is inclusive
of neither boundary. Limits are server bounded. Complete Evidence values are
never placed into event payload summaries.
