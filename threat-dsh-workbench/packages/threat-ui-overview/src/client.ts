import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'

export const name = 'threat-ui-overview-client'
export const inject = ['slots']

/** A real additive DSH view contribution. The backend projection is fetched by
 * the host workbench shell; this entry deliberately renders only bounded copy.
 */
function OverviewView(): string { return 'Threat analysis overview' }

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('conversation.view', () => ctx.slots.register({
    name: 'conversation.view', id: 'threat-overview', order: 20, label: 'Overview',
  }, OverviewView))
}
