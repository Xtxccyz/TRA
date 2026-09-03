export const name = 'threat-bundle-workbench'
export const version = '1.0.0'

export const WORKBENCH_PLUGINS = [
  '@threat-dsh/plugin-sdk',
  '@threat-dsh/api-client',
  '@threat-dsh/context-provider',
  '@threat-dsh/context-store',
  '@threat-dsh/model-gateway',
  '@threat-dsh/session-events',
  '@threat-dsh/tool-provider',
  '@threat-dsh/policy',
  '@threat-dsh/jobs',
  '@threat-dsh/ui-overview',
  '@threat-dsh/ui-investigation',
  '@threat-dsh/ui-mechanisms',
  '@threat-dsh/ui-sample-timeline',
  '@threat-dsh/ui-evidence',
  '@threat-dsh/ui-report',
  '@threat-dsh/brand',
] as const

// Stable IDs are used by acceptance tooling and deployment diagnostics. Keep
// them separate from package names so a future package rename does not change
// the profile contract.
export const WORKBENCH_PLUGIN_IDS = [
  'threat-plugin-sdk',
  'threat-api-client',
  'threat-context-provider',
  'threat-context-store',
  'threat-model-gateway',
  'threat-session-events',
  'threat-tool-provider',
  'threat-policy',
  'threat-jobs',
  'threat-ui-overview',
  'threat-ui-investigation',
  'threat-ui-mechanisms',
  'threat-ui-sample-timeline',
  'threat-ui-evidence',
  'threat-ui-report',
  'threat-brand',
] as const
