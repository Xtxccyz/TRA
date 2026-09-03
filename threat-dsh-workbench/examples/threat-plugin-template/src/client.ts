import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'

export const name = 'threat-plugin-acceptance-example-client'
export const inject = ['slots']
function PluginTestView(): string { return 'Plugin Test: dynamically loaded view' }

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('conversation.view', () => ctx.slots.register({
    name: 'conversation.view', id: 'plugin-test', order: 999, label: 'Plugin Test',
  }, PluginTestView))
}
