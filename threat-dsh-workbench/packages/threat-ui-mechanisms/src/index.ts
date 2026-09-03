import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
export const manifest: ThreatPluginManifest = { id: 'threat-ui-mechanisms', version: '1.0.0', plugin_api: 1, capabilities: ['view'], required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'] }
export function apply(): void {}
export interface MechanismViewModel {
  readonly id: string
  readonly type: string
  readonly target: string
  readonly statement: string
  readonly status: string
  readonly confidence: string
  readonly completeness_score: number
  readonly evidence_ids: readonly string[]
  readonly requirements: Record<string, number>
  readonly verifier: Record<string, unknown>
  readonly attack_mapping: Record<string, unknown>
}

function count(row: Record<string, unknown>, key: string): number {
  const value = row[key]
  return Array.isArray(value) ? value.length : typeof value === 'number' ? value : 0
}

export function buildMechanismViewModel(row: Record<string, unknown>): MechanismViewModel {
  const verifier = row.verifier && typeof row.verifier === 'object' ? row.verifier as Record<string, unknown> : {}
  const requirements = row.requirements && typeof row.requirements === 'object' ? row.requirements as Record<string, number> : {
    available: count(row, 'available_evidence_ids'),
    candidate: count(row, 'candidate_evidence_ids'),
    delivered: count(row, 'delivered_evidence_ids'),
    used: count(row, 'used_evidence_ids'),
    verified: String(verifier.status ?? '').toUpperCase() === 'VERIFIED' ? 1 : 0,
  }
  return {
    id: String(row.id ?? ''),
    type: String(row.type ?? row.dimension ?? 'STATIC_MECHANISM'),
    target: String(row.target ?? ''),
    statement: String(row.statement ?? row.mechanism ?? ''),
    status: String(row.status ?? 'UNKNOWN'),
    confidence: String(row.confidence ?? 'LOW'),
    completeness_score: typeof row.completeness_score === 'number' ? row.completeness_score : 0,
    evidence_ids: Array.isArray(row.evidence_ids) ? row.evidence_ids.filter((v): v is string => typeof v === 'string').slice(0, 5) : [],
    requirements,
    verifier,
    attack_mapping: row.attack_mapping && typeof row.attack_mapping === 'object' ? row.attack_mapping as Record<string, unknown> : {},
  }
}

export function buildMechanismDebugRows(row: Record<string, unknown>): readonly Record<string, unknown>[] {
  const view = buildMechanismViewModel(row)
  return Object.entries(view.requirements).map(([stage, value]) => ({ mechanism_id: view.id, stage, count: value, status: stage === 'verified' ? view.status : 'AVAILABLE' }))
}
