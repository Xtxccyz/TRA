import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'

export const name = 'threat-ui-evidence-client'
export const inject = ['slots']
function EvidenceView(): string { return 'Evidence explorer' }

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('conversation.view', () => ctx.slots.register({
    name: 'conversation.view', id: 'threat-evidence', order: 60, label: 'Evidence',
  }, EvidenceView))
}
