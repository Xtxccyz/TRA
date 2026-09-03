import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
export const manifest: ThreatPluginManifest = { id: 'threat-ui-sample-timeline', version: '1.0.0', plugin_api: 1, capabilities: ['view'], required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'] }
export function apply(): void {}
export interface TimelineItem { readonly id: string; readonly phase: string; readonly label: string; readonly status: string; readonly evidence_ids: readonly string[] }
export function buildTimeline(items: readonly Record<string, unknown>[]): TimelineItem[] { return items.slice(0, 256).map((row, index) => ({ id: String(row.id ?? index), phase: String(row.phase ?? 'static'), label: String(row.label ?? row.event_type ?? 'observation'), status: String(row.status ?? 'OBSERVED'), evidence_ids: Array.isArray(row.evidence_ids) ? row.evidence_ids.filter((v): v is string => typeof v === 'string').slice(0, 32) : [] })) }
