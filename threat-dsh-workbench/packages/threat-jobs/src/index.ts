import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'

export const manifest: ThreatPluginManifest = {
  id: 'threat-jobs', version: '1.0.0', plugin_api: 1, capabilities: ['event-projector'],
  required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'],
}

/** Cordis entrypoint; job projection is driven by the session bridge. */
export function apply(): void {}

export interface ThreatJobStatus { readonly task_id: string; readonly lifecycle: string; readonly outcome: string | null; readonly resumable: boolean }
export function toJobStatus(taskId: string, task: Record<string, unknown>): ThreatJobStatus {
  const state = (task.task && typeof task.task === 'object' ? task.task : {}) as Record<string, unknown>
  const lifecycle = String(state.lifecycle ?? 'UNKNOWN')
  return { task_id: taskId, lifecycle, outcome: state.outcome == null ? null : String(state.outcome), resumable: !['SUCCEEDED', 'FAILED', 'CANCELLED'].includes(lifecycle) }
}
