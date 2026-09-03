import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'

export const name = 'threat-ui-report-client'
export const inject = ['slots']
function ReportView(): string { return 'Analyst report' }

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('conversation.view', () => ctx.slots.register({
    name: 'conversation.view', id: 'threat-report', order: 70, label: 'Report',
  }, ReportView))
}
