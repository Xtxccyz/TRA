# Migration Runbook

1. Run `Start-ThreatReportAgent.bat` (or
   `powershell -File scripts/start-dsh-threat-workbench.ps1`). This is the
   single supported product start path: it starts PostgreSQL, MinIO, Temporal,
   static workers, the backend API, and DSH `threat-static`, then opens DSH on
   `http://127.0.0.1:3080/`.
2. Verify `/healthz` plus
   `/api/v1/workbench/capabilities/static-actions`.
3. Install the out-of-tree packages from `threat-dsh-workbench` into a DSH
   profile and select `profiles/threat-static`.
4. Open the DSH web client, create/link a Case task, upload samples, and follow
   Conversation, Trajectory, Investigation, Evidence, and Report projections.
5. On reconnect, use the stored `after_seq` cursor. On restart, reopen the DSH
   session and re-fetch the backend projection; PostgreSQL remains authoritative.

Stop with `Stop-ThreatReportAgent.bat`; it uses `docker compose stop` and does
not delete data volumes. The migration never executes a sample. Do not use
`docker compose down -v`.
