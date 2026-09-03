import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'

export const name = 'threat-ui-sample-timeline-client'
export const inject = ['slots']
function SampleTimelineView(): string { return 'Recovered sample execution timeline' }

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('conversation.view', () => ctx.slots.register({
    name: 'conversation.view', id: 'threat-sample-timeline', order: 50, label: 'Sample timeline',
  }, SampleTimelineView))
}
