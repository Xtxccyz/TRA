import { ThreatApiClient } from '@threat-dsh/api-client'
import { boundedIds, boundedText, type ThreatPluginManifest } from '@threat-dsh/plugin-sdk'

export const manifest: ThreatPluginManifest = {
  id: 'threat-context-provider', version: '1.0.0', plugin_api: 1,
  capabilities: ['context'], required_backend_api: '>=1,<2', required_event_schema: 1,
  security_profile: ['threat-static'],
}

/** Cordis entrypoint; context assembly is invoked by the host adapter. */
export function apply(): void {}

export interface ThreatContext { readonly task_id: string; readonly question: string; readonly context: Record<string, unknown> }

export async function buildContext(client: ThreatApiClient, taskId: string, question: string): Promise<ThreatContext> {
  const task = await client.task(taskId)
  const context = task as Record<string, unknown>
  const evidence = Array.isArray(context.evidence) ? context.evidence.slice(0, 64) : []
  return {
    task_id: taskId,
    question: boundedText(question, 1000),
    context: {
      task: { lifecycle: (context.task as Record<string, unknown> | undefined)?.lifecycle, outcome: (context.task as Record<string, unknown> | undefined)?.outcome },
      threads: Array.isArray(context.threads) ? context.threads.slice(0, 32) : [],
      hypotheses: Array.isArray(context.hypotheses) ? context.hypotheses.slice(0, 64) : [],
      evidence: evidence.map((row) => typeof row === 'object' && row ? { id: (row as Record<string, unknown>).id, kind: (row as Record<string, unknown>).kind, anchor: (row as Record<string, unknown>).anchor } : row),
      evidence_ids: boundedIds(evidence.map((row) => typeof row === 'object' && row ? (row as Record<string, unknown>).id : undefined)),
    },
  }
}
