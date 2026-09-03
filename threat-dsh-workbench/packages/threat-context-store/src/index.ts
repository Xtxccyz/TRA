import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'

export const manifest: ThreatPluginManifest = {
  id: 'threat-context-store', version: '1.0.0', plugin_api: 1,
  capabilities: ['context'], required_backend_api: '>=1,<2', required_event_schema: 1,
  security_profile: ['threat-static'],
}

export function apply(): void {}
