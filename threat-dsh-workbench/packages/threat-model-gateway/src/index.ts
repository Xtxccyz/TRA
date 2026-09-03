import { boundedText, type ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
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

/** Runtime binding used by DSH; all provider I/O remains in the backend. */
export class BackendModelGatewayAdapter implements ExistingModelGateway {
  constructor(private readonly client: ThreatApiClient, private readonly operation: 'planning' | 'claims' = 'planning') {}
  async complete(request: GatewayRequest, signal?: AbortSignal): Promise<GatewayResponse> {
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
    const result = await this.client.completeModel({ ...request, operation: this.operation })
    if (String(result.status ?? '') !== 'SUCCEEDED') throw new Error(`backend model call failed: ${String(result.status ?? 'UNKNOWN')}`)
    return {
      model_call_id: String(result.model_call_id ?? ''), provider: String(result.provider ?? ''),
      model: String(result.model ?? ''), content: boundedText(result.content, 100_000),
      usage: result.usage && typeof result.usage === 'object' ? result.usage as Record<string, number> : undefined,
    }
  }
}

export function redactGatewayResponse(response: GatewayResponse): Record<string, unknown> {
  return { model_call_id: response.model_call_id, provider: response.provider, model: response.model, content_preview: boundedText(response.content, 512), usage: response.usage }
}
