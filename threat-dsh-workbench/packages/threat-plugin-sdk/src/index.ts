export const THREAT_PLUGIN_API_VERSION = 1 as const
export const BACKEND_API_VERSION = 1 as const
export const SESSION_EVENT_VERSION = 1 as const
export const THREAT_TOOL_CONTRACT_VERSION = 'threat-tools-v4' as const
export const THREAT_SESSION_CONTEXT_PROTOCOL = 'v3' as const

export type ThreatCapability =
  | 'tool'
  | 'context'
  | 'view'
  | 'event-projector'
  | 'report-section'
  | 'model-gateway'

export interface ThreatPluginManifest {
  readonly id: string
  readonly version: string
  readonly plugin_api: 1
  readonly capabilities: readonly ThreatCapability[]
  readonly required_backend_api: '>=1,<2'
  readonly required_event_schema: 1
  readonly security_profile: readonly ('threat-static')[]
  readonly tool_contract_version?: string
  readonly session_context_protocol?: string
  readonly capability_profile?: string
}

export interface ThreatActionRequest {
  readonly action_type: string
  readonly target_artifact_id: string
  readonly hypothesis_id?: string
  readonly reason: string
  readonly expected_information: string
  readonly expected_evidence_kinds: readonly string[]
  readonly success_condition: string
  readonly failure_interpretation: 'UNKNOWN' | 'NO_NEW_EVIDENCE' | 'STATIC_BOUNDARY'
  readonly dedupe_key?: string
  readonly estimated_cost?: number
  readonly target_selector: Readonly<Record<string, string | number>>
}

export interface ThreatSessionEvent {
  readonly type: `threat/${string}`
  readonly data: Readonly<Record<string, unknown>>
}

export function assertManifest(manifest: ThreatPluginManifest): ThreatPluginManifest {
  if (!/^[-a-z0-9]+$/.test(manifest.id)) throw new Error('plugin id must be kebab-case')
  if (manifest.plugin_api !== THREAT_PLUGIN_API_VERSION) throw new Error('unsupported plugin API')
  if (manifest.required_event_schema !== SESSION_EVENT_VERSION) throw new Error('unsupported event schema')
  if (!manifest.security_profile.includes('threat-static')) throw new Error('plugin is not approved for threat-static')
  return Object.freeze({ ...manifest, capabilities: [...manifest.capabilities], security_profile: [...manifest.security_profile] })
}

export function boundedText(value: unknown, max = 512): string {
  return typeof value === 'string' ? value.slice(0, max) : ''
}

export function boundedIds(value: unknown, max = 32): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string').slice(0, max)
}
