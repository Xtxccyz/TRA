import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'

export const manifest: ThreatPluginManifest = {
  id: 'threat-ui-overview', version: '1.0.0', plugin_api: 1,
  capabilities: ['view'], required_backend_api: '>=1,<2', required_event_schema: 1,
  security_profile: ['threat-static'],
}

/** Cordis entrypoint; the host registers the keyed renderer separately. */
export function apply(): void {}

/** Renderer-neutral view model consumed by a DSH keyed renderer. */
export interface OverviewViewModel { readonly taskId: string; readonly lifecycle: string; readonly outcome: string | null; readonly findingCount: number; readonly artifactCount: number; readonly latestReportRevisionId: string | null }

export function buildOverviewViewModel(data: Record<string, unknown>): OverviewViewModel {
  const task = (data.task && typeof data.task === 'object' ? data.task : {}) as Record<string, unknown>
  return { taskId: String(task.id ?? ''), lifecycle: String(task.lifecycle ?? 'UNKNOWN'), outcome: task.outcome == null ? null : String(task.outcome), findingCount: Array.isArray(data.claims) ? data.claims.length : 0, artifactCount: Array.isArray(data.artifacts) ? data.artifacts.length : 0, latestReportRevisionId: task.latest_report_revision_id == null ? null : String(task.latest_report_revision_id) }
}
