export const THREAT_PLUGIN_API_VERSION = 1 as const
export const BACKEND_API_VERSION = 1 as const
export const SESSION_EVENT_VERSION = 1 as const
export const THREAT_TOOL_CONTRACT_VERSION = 'threat-tools-v4' as const
export const THREAT_SESSION_CONTEXT_PROTOCOL = 'v3' as const

// #region failure-interpretation contract (generated from contracts.FailureInterpretation)
import {
  FAILURE_INTERPRETATION_SOURCE_SHA256,
  FAILURE_INTERPRETATION_TOKENS,
  type FailureInterpretation,
  type ModelTransportFailure,
} from './failure-interpretation.generated.ts'

export {
  FAILURE_INTERPRETATION_SOURCE_SHA256,
  FAILURE_INTERPRETATION_TOKENS,
  type FailureInterpretation,
  type ModelTransportFailure,
}

/**
 * The token for a model/provider fault. Typed from the generated union, so it cannot name a token the backend does not
 * define: a generator or enum change that drops it fails `pnpm typecheck` here.
 */
export const MODEL_TRANSPORT_FAILURE: ModelTransportFailure = 'MODEL_TRANSPORT_FAILURE'

/**
 * The generated tuple is `as const`, so a generator that emits a token outside the union is a COMPILE error here. This
 * is the type-level half of the drift guard; `tests/model-routing-audit.test.mjs` is the set-equality half, which also
 * catches a token silently disappearing.
 */
const FAILURE_INTERPRETATION_CONTRACT = FAILURE_INTERPRETATION_TOKENS satisfies readonly FailureInterpretation[]
void FAILURE_INTERPRETATION_CONTRACT
// #endregion

export {
  MODEL_FAILURE_CONTRACT_VERSION,
  MODEL_TRANSPORT_FAILURE_TOKENS,
  classifyModelFailure,
  isBlankModelContent,
  modelFailureFields,
  modelTransportFailureInProse,
  type ModelFailureClass,
  type ModelFailureInput,
  type ModelFailureKind,
} from './model-failure.ts'

export {
  FIRST_REQUEST_PROTOCOL_ID,
  FIRST_REQUEST_PROTOCOL_VERSION,
  TEN_INVESTIGATION_QUESTIONS,
  firstRequestInvestigationProtocol,
  firstRequestProtocolPacket,
  type FirstRequestInvestigationProtocol,
  type InvestigationQuestionSlot,
} from './investigation-protocol.ts'

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
  // The backend owns this vocabulary (contracts.FailureInterpretation); the union is
  // generated from it, so this type cannot accept a token the backend does not define.
  readonly failure_interpretation: FailureInterpretation
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
