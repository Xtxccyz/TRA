import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
export const manifest: ThreatPluginManifest = { id: 'threat-ui-investigation', version: '1.0.0', plugin_api: 1, capabilities: ['view'], required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'] }
export function apply(): void {}
export const INVESTIGATION_VIEWS = ['threads', 'hypotheses', 'actions', 'trajectory', 'mechanisms', 'behavior-graph', 'sample-timeline', 'evidence-explorer', 'report'] as const

export interface HypothesisHistoryEntry { readonly status: string; readonly confidence: string; readonly evidence_ids: readonly string[]; readonly updated_at?: string }

export function buildHypothesisHistory(rows: readonly Record<string, unknown>[]): readonly HypothesisHistoryEntry[] {
  return rows.map(row => ({
    status: String(row.status ?? 'OPEN'),
    confidence: String(row.confidence ?? 'LOW'),
    evidence_ids: Array.isArray(row.evidence_ids) ? row.evidence_ids.filter((item): item is string => typeof item === 'string').slice(0, 5) : [],
    updated_at: typeof row.updated_at === 'string' ? row.updated_at : undefined,
  }))
}
