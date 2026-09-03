import type { Context } from '@deepseek-ai/cordis'
import Schema from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { ThreatApiClient } from '@threat-dsh/api-client'
import { assertManifest, boundedIds, boundedText, THREAT_TOOL_CONTRACT_VERSION, THREAT_SESSION_CONTEXT_PROTOCOL, type ThreatPluginManifest } from '@threat-dsh/plugin-sdk'

export const name = 'threat-tool-provider'
export const inject = ['tools']
export interface Config { backendUrl: string; token?: string }
export const Config: Schema<Config> = Schema.object({ backendUrl: Schema.string(), token: Schema.string() })
export const manifest: ThreatPluginManifest = assertManifest({
  id: 'threat-tool-provider', version: '2.0.0', plugin_api: 1,
  capabilities: ['tool'], required_backend_api: '>=1,<2', required_event_schema: 1,
  security_profile: ['threat-static'],
  tool_contract_version: THREAT_TOOL_CONTRACT_VERSION,
  session_context_protocol: THREAT_SESSION_CONTEXT_PROTOCOL,
  capability_profile: 'threat-static',
})

const output = {
  schema: { type: 'object', additionalProperties: true } as const,
  render: (_args: unknown, value: Record<string, unknown>) => [{ type: 'text' as const, text: JSON.stringify(compactToolResult(value)) }],
}

type TaskArgs = Record<string, never>
type SessionExecution = { readonly agent?: { readonly session?: { readonly id?: string } } }

function sessionIdOf(exec: SessionExecution): string {
  return typeof exec.agent?.session?.id === 'string' ? exec.agent.session.id.trim() : ''
}

async function resolveTaskId(client: ThreatApiClient, exec: SessionExecution): Promise<string> {
  const sessionId = sessionIdOf(exec)
  if (!sessionId) throw new Error('NO_DSH_SESSION')
  const context = await client.sessionContext(sessionId)
  const active = typeof context.active_task_id === 'string' ? context.active_task_id : ''
  if (!active) throw new Error('NO_ACTIVE_ANALYSIS')
  return active
}

function compactToolResult(value: unknown): Record<string, unknown> {
  const row = value && typeof value === 'object' ? { ...(value as Record<string, unknown>) } : {}
  for (const key of ['value', 'message', 'reason', 'summary']) {
    if (typeof row[key] === 'string' && String(row[key]).length > 1200) row[key] = `${String(row[key]).slice(0, 1200)}...[compacted]`
  }
  for (const key of ['items', 'events', 'evidence', 'actions']) {
    if (Array.isArray(row[key])) {
      const items = row[key] as unknown[]
      row[key] = items.slice(-32).map((item) => {
        if (!item || typeof item !== 'object') return item
        const copy = { ...(item as Record<string, unknown>) }
        for (const field of ['value', 'output', 'raw', 'detail']) {
          if (typeof copy[field] === 'string' && String(copy[field]).length > 600) copy[field] = `${String(copy[field]).slice(0, 600)}...[compacted]`
        }
        return copy
      })
      row[`${key}_total`] = items.length
    }
  }
  return row
}

export function apply(ctx: Context, config: Config): void {
  const client = new ThreatApiClient({ baseUrl: config.backendUrl, token: config.token })
  ctx.tools.register(defineTool({
    name: 'threat_get_session_analysis_context',
    description: 'Read the server-authoritative analysis context for the current DSH session. The session identity is injected by DSH; never provide or guess a task ID.',
    parameters: {}, output,
    async execute(_args: Record<string, never>, exec: SessionExecution) {
      const id = sessionIdOf(exec); if (!id) return { state: 'UNBOUND', code: 'NO_ACTIVE_ANALYSIS', active_task_id: null }
      return client.sessionContext(id)
    },
    presentCall: () => ({ card: 'generic', title: 'Read current analysis context', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_list_session_artifacts',
    description: 'List only artifacts explicitly attached to the current DSH session.',
    parameters: {}, output,
    async execute(_args: Record<string, never>, exec: SessionExecution) {
      const id = sessionIdOf(exec); if (!id) return { state: 'UNBOUND', items: [] }
      return client.sessionArtifacts(id)
    },
    presentCall: () => ({ card: 'generic', title: 'List current session samples', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_list_session_workspace_artifacts',
    description: 'List analyzable files under the configured current DSH workspace. Paths are workspace-relative; this never reads outside the approved root and never executes a file.',
    parameters: { relative_dir: { type: 'string' } }, output,
    async execute(args: { relative_dir?: string }, exec: SessionExecution) {
      const id = sessionIdOf(exec); if (!id) return { state: 'UNBOUND', items: [], code: 'NO_DSH_SESSION' }
      try { return await client.workspaceArtifacts(id, args.relative_dir || '.') }
      catch (error) { return { state: 'WORKSPACE_UNAVAILABLE', code: error instanceof Error ? error.message : String(error), items: [] } }
    },
    presentCall: (args: { relative_dir?: string }) => ({ card: 'generic', title: 'List workspace sample candidates', kind: 'read', rawInput: { relative_dir: args.relative_dir || '.' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_import_workspace_artifact',
    description: 'Import one user-selected workspace-relative file as a static Artifact and attach it to the current DSH session. This performs no shell, subprocess, sample execution, or network access.',
    parameters: { relative_path: { type: 'string' }, case_id: { type: 'string' } }, output,
    async execute(args: { relative_path?: string; case_id?: string }, exec: SessionExecution) {
      const id = sessionIdOf(exec); const path = typeof args.relative_path === 'string' ? args.relative_path.trim() : ''
      if (!id || !path) return { state: 'UNBOUND', code: 'WORKSPACE_PATH_REQUIRED' }
      try { return await client.importWorkspaceArtifact(id, path, { caseId: args.case_id }) }
      catch (error) { return { state: 'WORKSPACE_IMPORT_FAILED', code: error instanceof Error ? error.message : String(error) } }
    },
    presentCall: (args: { relative_path?: string }) => ({ card: 'generic', title: 'Import selected workspace sample', kind: 'run', rawInput: { relative_path: args.relative_path || '' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_start_static_analysis',
    description: 'Explicitly start the bounded static analysis workflow for an artifact attached to the current DSH session. This never executes the sample or contacts its network.',
    parameters: { artifact_id: { type: 'string' } }, output,
    async execute(args: { artifact_id?: string }, exec: SessionExecution) {
      const id = sessionIdOf(exec); if (!id) return { code: 'NO_DSH_SESSION', state: 'UNBOUND' }
      return client.startAnalysis(id, args.artifact_id)
    },
    presentCall: (args: { artifact_id?: string }) => ({ card: 'generic', title: 'Start static analysis', kind: 'run', rawInput: { artifact_id: args.artifact_id || 'selected-session-artifact' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_analysis_status',
    description: 'Read the current session analysis state without accepting a task ID.',
    parameters: {}, output,
    async execute(_args: Record<string, never>, exec: SessionExecution) {
      const id = sessionIdOf(exec); if (!id) return { state: 'UNBOUND', code: 'NO_ACTIVE_ANALYSIS' }
      return client.analysisStatus(id)
    },
    presentCall: () => ({ card: 'generic', title: 'Read analysis status', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_wait_for_analysis_update',
    description: 'Wait for one meaningful server-side analysis event. This avoids repeated status, thread, and evidence polling.',
    parameters: { after_event_seq: { type: 'integer' }, timeout_seconds: { type: 'integer' } }, output,
    async execute(args: { after_event_seq?: number; timeout_seconds?: number } = {}, exec: SessionExecution) {
      const id = sessionIdOf(exec)
      if (!id) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', changed: false, events: [] }
      try { return await client.waitForAnalysisUpdate(id, args.after_event_seq ?? 0, args.timeout_seconds ?? 30) }
      catch (error) { return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error), changed: false, events: [] } }
    },
    presentCall: () => ({ card: 'generic', title: 'Wait for analysis progress', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_propose_static_action',
    description: 'Propose one bounded read-only static investigation action for the current session. The backend validates the catalog, target, policy, and evidence contract before execution.',
    parameters: {
      action_type: { type: 'string' }, target_artifact_id: { type: 'string' }, hypothesis_id: { type: 'string' },
      reason: { type: 'string' },
      // DSH's schema compiler requires object openness to be explicit. The
      // backend owns validation of selector keys, so preserve extensibility
      // here while keeping the tool contract JSON-schema compliant.
      target_selector: { type: 'object', additionalProperties: true },
      expected_evidence_kinds: { type: 'array', items: { type: 'string' } },
      success_condition: { type: 'string' }, failure_interpretation: { type: 'string' },
    }, output,
    async execute(args: Record<string, unknown>, exec: SessionExecution) {
      const id = sessionIdOf(exec)
      if (!id) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', accepted: false }
      try { return await client.proposeStaticAction(id, args) }
      catch (error) { return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error), accepted: false } }
    },
    presentCall: (args: Record<string, unknown>) => ({ card: 'generic', title: 'Propose static investigation action', kind: 'run', rawInput: { action_type: args.action_type, target_artifact_id: args.target_artifact_id } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_action_result',
    description: 'Read the bounded result of a previously accepted static action by action ID.',
    parameters: { action_id: { type: 'string' } }, output,
    async execute(args: { action_id?: string } = {}, exec: SessionExecution) {
      const id = sessionIdOf(exec); const actionId = typeof args.action_id === 'string' ? args.action_id.trim() : ''
      if (!id || !actionId) return { state: 'UNBOUND', code: 'ACTION_ID_REQUIRED' }
      try {
        await resolveTaskId(client, exec)
        return await client.action(actionId, id)
      } catch (error) { return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error) } }
    },
    presentCall: (args: { action_id?: string }) => ({ card: 'generic', title: 'Read static action result', kind: 'read', rawInput: { action_id: args.action_id || '' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_bind_existing_analysis',
    description: 'Explicitly bind a historical task selected by the user to the current DSH session.',
    parameters: { task_id: { type: 'string' } }, output,
    async execute(args: { task_id?: string }, exec: SessionExecution) {
      const id = sessionIdOf(exec); const taskId = typeof args.task_id === 'string' ? args.task_id.trim() : ''
      if (!id || !taskId) return { code: 'HISTORICAL_BIND_REQUIRED', state: 'UNBOUND' }
      return client.bindAnalysis(id, taskId)
    },
    presentCall: (args: { task_id?: string }) => ({ card: 'generic', title: 'Bind selected historical analysis', kind: 'run', rawInput: { task_id: args.task_id || '' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_unbind_analysis',
    description: 'Clear the active analysis binding and task-scoped views for the current DSH session.',
    parameters: {}, output,
    async execute(_args: Record<string, never>, exec: SessionExecution) {
      const id = sessionIdOf(exec); if (!id) return { state: 'UNBOUND', code: 'NO_ACTIVE_ANALYSIS' }
      return client.unbindAnalysis(id)
    },
    presentCall: () => ({ card: 'generic', title: 'Close current analysis', kind: 'run' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_thread_context',
    description: 'Read the bounded authoritative context for the current static-analysis task. The task is resolved from the DSH session and cannot be supplied by the model.',
    parameters: {},
    output,
    async execute(_args: TaskArgs = {}, exec: SessionExecution) {
      try { const sessionId = sessionIdOf(exec); return client.task(await resolveTaskId(client, exec), sessionId) }
      catch (error) { return { state: 'UNBOUND', code: error instanceof Error ? error.message : String(error), active_task_id: null } }
    },
    presentCall: () => ({ card: 'generic', title: 'Read threat investigation context', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_thread_summary',
    description: 'Read bounded summaries of investigation threads belonging to the current session analysis. Thread identity is selected from the server-bound task.',
    parameters: { thread_id: { type: 'string' } },
    output,
    async execute(args: { thread_id?: string } = {}, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', items: [] }
      try {
        const taskId = await resolveTaskId(client, exec)
        if (args.thread_id?.trim()) {
          const thread = await client.thread(args.thread_id.trim(), sessionId) as Record<string, unknown>
          return compactToolResult({ schema_version: 1, task_id: taskId, item: {
            id: thread.id, artifact_id: thread.artifact_id, state: thread.state,
            question: thread.question, seed_kind: thread.seed_kind,
            transition_count: thread.transition_count,
            hypotheses: Array.isArray(thread.hypotheses) ? thread.hypotheses.slice(-8) : [],
            actions: Array.isArray(thread.actions) ? thread.actions.slice(-8) : [],
          } })
        }
        const result = await client.threads(taskId, sessionId)
        const items = Array.isArray(result.items) ? result.items : []
        return compactToolResult({ schema_version: 1, task_id: taskId, items: items.slice(-32).map((item) => {
          const row = item && typeof item === 'object' ? item as Record<string, unknown> : {}
          return { id: row.id, artifact_id: row.artifact_id, state: row.state,
            question: row.question, seed_kind: row.seed_kind,
            transition_count: row.transition_count,
            hypothesis_count: Array.isArray(row.hypotheses) ? row.hypotheses.length : 0,
            action_count: Array.isArray(row.actions) ? row.actions.length : 0 }
        }), total: items.length })
      } catch (error) {
        return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error), items: [] }
      }
    },
    presentCall: (args: { thread_id?: string }) => ({ card: 'generic', title: 'Read investigation thread summary', kind: 'read', rawInput: { thread_id: args.thread_id || '' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_mechanism',
    description: 'Read bounded mechanism projections for the current session analysis. Candidate evidence remains distinct from verified mechanisms.',
    parameters: { mechanism_id: { type: 'string' } },
    output,
    async execute(args: { mechanism_id?: string } = {}, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', items: [] }
      try {
        const taskId = await resolveTaskId(client, exec)
        const result = await client.collection(taskId, 'mechanisms', sessionId)
        const items = Array.isArray(result.items) ? result.items : []
        const selected = args.mechanism_id?.trim()
          ? items.filter((item) => item && typeof item === 'object' && String((item as Record<string, unknown>).id ?? (item as Record<string, unknown>).mechanism_id ?? '') === args.mechanism_id!.trim())
          : items.slice(-32)
        return compactToolResult({ schema_version: 1, task_id: taskId, items: selected, total: items.length })
      } catch (error) {
        return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error), items: [] }
      }
    },
    presentCall: (args: { mechanism_id?: string }) => ({ card: 'generic', title: 'Read mechanism summary', kind: 'read', rawInput: { mechanism_id: args.mechanism_id || '' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_report_summary',
    description: 'Read the current task report delivery state and a bounded report preview. Failed tasks never expose intermediate Markdown as a final report.',
    parameters: {},
    output,
    async execute(_args: Record<string, never>, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', report_available: false }
      try {
        const taskId = await resolveTaskId(client, exec)
        const result = await client.report(taskId, sessionId)
        const row = result && typeof result === 'object' ? result as Record<string, unknown> : {}
        const report = typeof row.revision === 'object' && row.revision
          ? row.revision as Record<string, unknown>
          : (typeof row.report === 'object' && row.report ? row.report as Record<string, unknown> : row)
        return compactToolResult({ schema_version: 1, task_id: taskId,
          lifecycle: row.lifecycle ?? report.lifecycle, analysis_class: row.analysis_class ?? report.analysis_class,
          report_available: row.report_available ?? Boolean(report.markdown),
          report_revision_id: row.report_revision_id ?? report.id,
          summary: row.summary ?? report.summary,
          content: row.content ?? report.markdown,
        })
      } catch (error) {
        return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error), report_available: false }
      }
    },
    presentCall: () => ({ card: 'generic', title: 'Read final report status', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_query_current_analysis_evidence',
    description: 'Query bounded evidence for the current DSH session analysis. Task identity is injected by the server and cannot be supplied by the model.',
    parameters: {
      kind: { type: 'string' }, module: { type: 'string' },
      artifact_id: { type: 'string' }, limit: { type: 'integer' },
    }, output,
    async execute(args: { kind?: string; module?: string; artifact_id?: string; limit?: number } = {}, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', items: [] }
      try { return await client.currentEvidence(sessionId, { kind: args.kind, module: args.module, artifactId: args.artifact_id, limit: args.limit }) }
      catch (error) { return { state: 'UNBOUND', code: error instanceof Error ? error.message : String(error), items: [] } }
    },
    presentCall: (args: { kind?: string; module?: string }) => ({ card: 'generic', title: 'Query current static evidence', kind: 'search', rawInput: { kind: args.kind, module: args.module } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_capabilities',
    description: 'Read the backend closed catalog of allowed read-only static actions.',
    parameters: {}, output,
    async execute() { return client.capabilities() },
    presentCall: () => ({ card: 'generic', title: 'Read static action catalog', kind: 'read' }),
  }))
}

export function summarizeToolResult(value: unknown): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {}
  return { status: boundedText(row.status, 80), evidence_ids: boundedIds(row.evidence_ids), summary: boundedText(row.summary) }
}
