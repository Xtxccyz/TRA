import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
export const manifest: ThreatPluginManifest = { id: 'threat-ui-evidence', version: '1.0.0', plugin_api: 1, capabilities: ['view'], required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'] }
export function apply(): void {}
export function evidenceExplorerQuery(taskId: string, filters: Record<string, string | number | undefined> = {}): { task_id: string; filters: Record<string, string | number | undefined>; bounded: true } { return { task_id: taskId, filters, bounded: true } }

export interface EvidenceFunnelRow { readonly evidence_id: string; readonly available: boolean; readonly eligible: boolean; readonly candidate: boolean; readonly selected: boolean; readonly delivered: boolean; readonly referenced: boolean; readonly accepted: boolean; readonly exclusion_reason?: string }

export function buildEvidenceFunnelRows(records: readonly Record<string, unknown>[]): readonly EvidenceFunnelRow[] {
  const grouped = new Map<string, EvidenceFunnelRow>()
  for (const record of records) {
    const id = String(record.evidence_id ?? '')
    if (!id) continue
    const current = grouped.get(id) ?? { evidence_id: id, available: true, eligible: false, candidate: false, selected: false, delivered: false, referenced: false, accepted: false }
    const stage = String(record.stage ?? '').toLowerCase()
    grouped.set(id, {
      ...current,
      eligible: current.eligible || stage !== 'excluded',
      candidate: current.candidate || ['candidate', 'selected', 'delivered', 'referenced_by_model', 'accepted_as_support'].includes(stage),
      selected: current.selected || ['selected', 'delivered', 'referenced_by_model', 'accepted_as_support'].includes(stage),
      delivered: current.delivered || ['delivered', 'referenced_by_model', 'accepted_as_support'].includes(stage),
      referenced: current.referenced || ['referenced_by_model', 'accepted_as_support'].includes(stage),
      accepted: current.accepted || stage === 'accepted_as_support',
      exclusion_reason: typeof record.exclusion_reason === 'string' ? record.exclusion_reason : current.exclusion_reason,
    })
  }
  return [...grouped.values()]
}
