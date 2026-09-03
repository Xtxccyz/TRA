import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
export const manifest: ThreatPluginManifest = { id: 'threat-ui-report', version: '1.0.0', plugin_api: 1, capabilities: ['view', 'report-section'], required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'] }
export function apply(): void {}
export interface ReportViewModel { readonly revisionId: string | null; readonly status: string; readonly markdown: string; readonly editable: boolean }
export function buildReportViewModel(report: Record<string, unknown>): ReportViewModel { const revision = report.revision && typeof report.revision === 'object' ? report.revision as Record<string, unknown> : {}; return { revisionId: revision.id == null ? null : String(revision.id), status: String(revision.status ?? 'UNAVAILABLE'), markdown: String(revision.markdown ?? ''), editable: revision.status === 'DRAFT' } }
