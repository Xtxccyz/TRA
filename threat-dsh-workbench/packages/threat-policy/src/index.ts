import type { Context } from '@deepseek-ai/cordis'
import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'

export const manifest: ThreatPluginManifest = {
  id: 'threat-policy', version: '1.0.0', plugin_api: 1, capabilities: ['context'],
  required_backend_api: '>=1,<2', required_event_schema: 1, security_profile: ['threat-static'],
}

/**
 * Model-facing names that must never run on the threat-static host, even if a
 * later preset or overlay accidentally remounts the upstream plugin.
 * `todo_write` and `ask_user_question` are intentionally absent: they do not
 * execute samples, write the sample workspace, or contact sample networks.
 */
export const FORBIDDEN_TOOLS = [
  'bash', 'pwsh', 'terminal', 'run_code', 'web_fetch', 'web_search', 'subprocess',
  'write', 'edit', 'str_replace_editor', 'ralph', 'workflow', 'subagent', 'subagent_fork',
] as const

type GuardedExecution = { readonly name?: string }
type GuardableTools = {
  guard?(decide: (execution: GuardedExecution) => string | undefined): unknown
}

/** Deny host execution, sample-workspace mutation, and sample-directed network. */
export function apply(ctx: Context): void {
  ctx.inject(['tools'], (scope: Context) => {
    const tools = scope.tools as unknown as GuardableTools
    if (typeof tools.guard !== 'function') return
    tools.guard((execution) => {
      const name = typeof execution?.name === 'string' ? execution.name : ''
      if ((FORBIDDEN_TOOLS as readonly string[]).includes(name)) {
        return `threat-static policy denies ${name}`
      }
      return undefined
    })
  })
}

export function assertThreatStaticToolSet(names: readonly string[]): void {
  const exposed = new Set(names)
  const unsafe = FORBIDDEN_TOOLS.filter((name) => exposed.has(name))
  if (unsafe.length) throw new Error(`threat-static exposes forbidden tools: ${unsafe.join(',')}`)
}
