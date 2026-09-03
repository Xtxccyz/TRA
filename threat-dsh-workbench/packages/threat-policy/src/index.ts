import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'

export const manifest: ThreatPluginManifest = {
  id: 'threat-policy', version: '1.0.0', plugin_api: 1, capabilities: ['context'],
  required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'],
}

/** Cordis entrypoint; policy checks are called by the tool bridge. */
export function apply(): void {}

export const FORBIDDEN_TOOLS = ['bash', 'pwsh', 'terminal', 'run_code', 'web_fetch', 'subprocess'] as const
export function assertThreatStaticToolSet(names: readonly string[]): void {
  const exposed = new Set(names)
  const unsafe = FORBIDDEN_TOOLS.filter((name) => exposed.has(name))
  if (unsafe.length) throw new Error(`threat-static exposes forbidden tools: ${unsafe.join(',')}`)
}
