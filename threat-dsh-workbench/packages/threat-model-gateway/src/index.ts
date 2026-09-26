import { boundedText, classifyModelFailure, modelFailureFields, type ModelFailureClass, type ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
import type { ThreatApiClient } from '@threat-dsh/api-client'

export const manifest: ThreatPluginManifest = {
  id: 'threat-model-gateway', version: '1.0.0', plugin_api: 1,
  capabilities: ['model-gateway'], required_backend_api: '>=1,<2', required_event_schema: 1,
  security_profile: ['threat-static'],
}

/** Cordis entrypoint; deployments bind the adapter through the host bridge. */
export function apply(): void {}

export interface GatewayRequest {
  readonly case_id: string; readonly task_id: string; readonly session_id: string
  readonly turn_id: string; readonly step_id: string; readonly module: string
  readonly messages: readonly { role: 'system' | 'user' | 'assistant'; content: string }[]
  readonly response_schema: Record<string, unknown>
}
export interface GatewayResponse { readonly model_call_id: string; readonly provider: string; readonly model: string; readonly content: string; readonly usage?: Record<string, number> }

/**
 * Transport contract for a DSH LLM adapter. Deployments bind `complete` to a
 * protected backend route; this package never contacts a provider directly.
 */
export interface ExistingModelGateway {
  complete(request: GatewayRequest, signal?: AbortSignal): Promise<GatewayResponse>
}

/**
 * A model/transport fault carried as data instead of a bare message.
 *
 * The backend already returns the per-attempt `http_status` / `error_type` /
 * `error_detail`; throwing `new Error("backend model call failed: FAILED")`
 * discarded them, so every DSH caller saw one indistinguishable failure and an
 * HTTP 402, a timeout and an empty reply read exactly alike. Nothing in the
 * workbench may turn one of these into a static-analysis boundary.
 */
export class ModelTransportError extends Error {
  readonly failure: ModelFailureClass
  readonly attempts: readonly Record<string, unknown>[]

  constructor(failure: ModelFailureClass, attempts: readonly Record<string, unknown>[] = []) {
    super(`backend model call failed: ${failure.kind}`)
    this.name = 'ModelTransportError'
    this.failure = failure
    this.attempts = attempts
  }

  get failure_kind(): string {
    return this.failure.kind
  }

  get http_status(): number | null {
    return this.failure.http_status
  }

  get distinct_from_static_boundary(): true {
    return true
  }

  get not_an_analysis_result(): true {
    return true
  }

  asResult(): Record<string, unknown> {
    return { state: 'MODEL_OR_TRANSPORT', accepted: false, ...modelFailureFields(this.failure) }
  }
}

/** Runtime binding used by DSH; all provider I/O remains in the backend. */
export class BackendModelGatewayAdapter implements ExistingModelGateway {
  constructor(private readonly client: ThreatApiClient, private readonly operation: 'planning' | 'claims' = 'planning') {}
  async complete(request: GatewayRequest, signal?: AbortSignal): Promise<GatewayResponse> {
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
    const result = await this.client.completeModel({ ...request, operation: this.operation })
    const attempts = Array.isArray(result.attempts) ? result.attempts as Record<string, unknown>[] : []
    const content = boundedText(result.content, 100_000)
    // An empty body is an empty reply even when the status says SUCCEEDED: a
    // reasoning model that spent its completion budget returns HTTP 200 with no
    // content, and returning that as a completion is what makes a model that
    // never answered look like one that did.
    const failure = classifyModelFailure({ ...result, content })
    if (String(result.status ?? '') !== 'SUCCEEDED' || failure.kind !== 'NONE') {
      throw new ModelTransportError(failure, attempts)
    }
    return {
      model_call_id: String(result.model_call_id ?? ''), provider: String(result.provider ?? ''),
      model: String(result.model ?? ''), content,
      usage: result.usage && typeof result.usage === 'object' ? result.usage as Record<string, number> : undefined,
    }
  }
}

export function redactGatewayResponse(response: GatewayResponse): Record<string, unknown> {
  return { model_call_id: response.model_call_id, provider: response.provider, model: response.model, content_preview: boundedText(response.content, 512), usage: response.usage }
}
