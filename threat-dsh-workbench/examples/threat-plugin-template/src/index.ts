import type { Context } from '@deepseek-ai/cordis'

export const name = 'threat-plugin-acceptance-example'
export const inject = ['tools']
export const manifest = Object.freeze({ id: 'threat-plugin-acceptance-example', version: '1.0.0', plugin_api: 1, capabilities: ['tool', 'event-projector', 'view'], required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'] as const })

export function apply(ctx: Context): void {
  ctx.tools.register({
    name: 'threat_echo_evidence_summary',
    description: 'Return a bounded acceptance-test summary without reading sample bytes.',
    parameters: { type: 'object', additionalProperties: false, required: ['task_id', 'evidence_count'], properties: { task_id: { type: 'string' }, evidence_count: { type: 'integer' } } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { task_id: { type: 'string' }, evidence_count: { type: 'integer' } } }, render: (_args: unknown, value: Record<string, unknown>) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args: { task_id: string; evidence_count: number }) { return { task_id: args.task_id, evidence_count: Math.min(args.evidence_count, 500) } },
    presentCall: (args: { task_id: string }) => ({ card: 'generic', title: 'Plugin Test: evidence summary', kind: 'read', rawInput: { task_id: args.task_id } }),
  })
}

/** The producer is explicit and tiny so a host integration can append it to
 * the durable DSH Session log without coupling this plugin to Session storage.
 */
export function appendPluginTestEvent(session: { append(type: string, data: Record<string, unknown>): unknown }, taskId: string): void {
  session.append('threat/plugin-test', { task_id: taskId, summary: 'pluginability acceptance event' })
}
