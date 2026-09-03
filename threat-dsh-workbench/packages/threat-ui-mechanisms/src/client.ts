import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'

export const name = 'threat-ui-mechanisms-client'
export const inject = ['slots']
function MechanismsView(): string { return 'Verified mechanisms and behavior graph' }

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('conversation.view', () => ctx.slots.register({
    name: 'conversation.view', id: 'threat-mechanisms', order: 40, label: 'Mechanisms',
  }, MechanismsView))
}
