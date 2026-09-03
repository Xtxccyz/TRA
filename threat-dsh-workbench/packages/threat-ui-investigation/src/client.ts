import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'

export const name = 'threat-ui-investigation-client'
export const inject = ['slots']
function InvestigationView(): string { return 'Investigation threads and hypotheses' }

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('conversation.view', () => ctx.slots.register({
    name: 'conversation.view', id: 'threat-investigation', order: 30, label: 'Investigation',
  }, InvestigationView))
}
