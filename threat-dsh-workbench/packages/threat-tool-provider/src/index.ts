import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
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
  // DSH sends output.render to the model, not execute()'s raw value.
  // Official leftover markdown lives in `content`; compacting it to 1200
  // chars is what made one chat round ask 再深入 after persist HOW existed.
  render: (_args: unknown, value: Record<string, unknown>) => [{
    type: 'text' as const,
    text: JSON.stringify(compactToolResult(value, { preserve: ['content'] })),
  }],
}

type TaskArgs = Record<string, never>
type SessionExecution = {
  readonly callId?: unknown
  readonly rootCallId?: unknown
  readonly planner_turn_id?: unknown
  readonly turn_id?: unknown
  readonly agent?: {
    readonly session?: {
      readonly id?: string
      readonly header?: Record<string, unknown>
    }
  }
}

function sessionIdOf(exec: SessionExecution): string {
  return typeof exec.agent?.session?.id === 'string' ? exec.agent.session.id.trim() : ''
}

function textValue(value: unknown, max = 200): string | undefined {
  if (typeof value !== 'string' && typeof value !== 'number') return undefined
  const text = String(value).trim()
  return text ? text.slice(0, max) : undefined
}

/**
 * DSH's ToolExecution carries call identity, not a backend task identity. Use
 * the root call as a deterministic planner correlation when the model did not
 * explicitly provide one, and keep the original call IDs in audit metadata.
 */
function plannerTurnIdOf(args: Record<string, unknown>, exec: SessionExecution): string {
  const header = exec.agent?.session?.header || {}
  const explicit = textValue(args.planner_turn_id) || textValue(exec.planner_turn_id) || textValue(exec.turn_id)
  if (explicit) return explicit
  const rootCall = textValue(exec.rootCallId) || textValue(exec.callId)
  if (rootCall) return `dsh-call-${rootCall}`
  const session = sessionIdOf(exec)
  const headerPlanner = textValue(header.planner_turn_id) || textValue(header.turn_id)
  if (headerPlanner) return headerPlanner
  if (session) return `dsh-session-${session}`
  return 'dsh-session-unresolved'
}

function coerceFailureInterpretation(payload: Record<string, unknown>): Record<string, unknown> {
  const raw = textValue(payload.failure_interpretation, 1200)
  if (!raw || raw === 'UNKNOWN' || raw === 'NO_NEW_EVIDENCE' || raw === 'STATIC_BOUNDARY') return payload
  const folded = raw.toUpperCase().replace(/[-\s]/g, '_')
  let token = 'UNKNOWN'
  if (folded.includes('NO_NEW_EVIDENCE') || raw.toUpperCase().includes('NO_NEW_EVIDENCE')) token = 'NO_NEW_EVIDENCE'
  else if (folded.includes('STATIC_BOUNDARY') || raw.toUpperCase().includes('STATIC_BOUNDARY')) token = 'STATIC_BOUNDARY'
  const next = { ...payload, failure_interpretation: token }
  const meaning = textValue(payload.failure_meaning, 1200) || ''
  if (raw !== token && !meaning.includes(raw)) {
    next.failure_meaning = (meaning ? `${meaning}; ${raw}` : raw).slice(0, 1200)
  }
  return next
}

const SELECTOR_ALIASES: Record<string, string> = {
  function_name: 'function',
  name: 'function',
  va: 'address',
  virtual_address: 'address',
  entry_point: 'function_entry',
  len: 'length',
  byte_count: 'length',
  byte_length: 'length',
  arg_index: 'argument_index',
}

const CATALOG_SELECTOR_KEYS = new Set([
  'target', 'api', 'function', 'function_entry', 'entry', 'rva', 'address',
  'length', 'size', 'offset', 'file_offset', 'argument_index', 'index',
  'callsite', 'max_instructions', 'formula', 'limit',
])

function coerceActionDialect(payload: Record<string, unknown>): Record<string, unknown> {
  const next = coerceFailureInterpretation(payload)
  const success = typeof next.success_condition === 'string' ? next.success_condition.trim() : ''
  if (success.length > 160) {
    next.success_condition = success.slice(0, 160)
    const leftover = success.slice(160).trim()
    const meaning = textValue(next.failure_meaning, 1200) || ''
    if (leftover && !meaning.includes(leftover)) {
      next.failure_meaning = (meaning ? `${meaning}; ${leftover}` : leftover).slice(0, 1200)
    }
  }
  const selector = next.target_selector
  if (selector && typeof selector === 'object' && !Array.isArray(selector)) {
    const normalized: Record<string, string | number> = {}
    for (const [key, value] of Object.entries(selector as Record<string, unknown>)) {
      if (typeof value !== 'string' && typeof value !== 'number') continue
      if (typeof value === 'number' && !Number.isFinite(value)) continue
      const mapped = SELECTOR_ALIASES[key] || key
      if (CATALOG_SELECTOR_KEYS.has(mapped)) normalized[mapped] = value as string | number
    }
    next.target_selector = normalized
  }
  return next
}

function modelActionPayload(args: Record<string, unknown>, exec: SessionExecution, sessionId: string): Record<string, unknown> {
  const payload = coerceActionDialect({ ...args })
  const plannerTurnId = plannerTurnIdOf(payload, exec)
  const header = exec.agent?.session?.header || {}
  payload.origin = 'model'
  payload.planner_turn_id = plannerTurnId
  const existing = payload.model_provenance && typeof payload.model_provenance === 'object'
    ? { ...(payload.model_provenance as Record<string, unknown>) }
    : {}
  existing.source = existing.source || 'threat-tool-provider'
  existing.session_id = sessionId
  const callId = textValue(exec.callId)
  const rootCallId = textValue(exec.rootCallId)
  if (callId) existing.call_id = callId
  if (rootCallId) existing.root_call_id = rootCallId
  existing.planner_turn_id = plannerTurnId
  for (const [source, target] of [
    ['model_call_id', 'model_call_id'],
    ['model_run_id', 'model_run_id'],
    ['model_provider', 'provider'],
    ['model_name', 'model'],
    ['provider', 'provider'],
    ['model', 'model'],
  ] as const) {
    const value = textValue(payload[source]) || textValue(header[source])
    if (value) existing[target] = value
  }
  // Preserve gateway metadata supplied by a host adapter on the session
  // header without exposing the complete DSH session object to the backend.
  for (const [source, target] of [
    ['model_call_id', 'model_call_id'],
    ['model_run_id', 'model_run_id'],
    ['model_provider', 'model_provider'],
    ['model_name', 'model_name'],
    ['provider', 'provider'],
    ['model', 'model'],
  ] as const) {
    if (payload[source] === undefined && textValue(header[source])) payload[source] = textValue(header[source])
    if (target === 'model_provider' || target === 'model_name') {
      const value = textValue(payload[source])
      if (value) existing[target === 'model_provider' ? 'provider' : 'model'] = value
    }
  }
  payload.model_provenance = existing
  return payload
}

async function resolveTaskId(client: ThreatApiClient, exec: SessionExecution): Promise<string> {
  const sessionId = sessionIdOf(exec)
  if (!sessionId) throw new Error('NO_DSH_SESSION')
  const context = await client.sessionContext(sessionId)
  const active = typeof context.active_task_id === 'string' ? context.active_task_id : ''
  if (!active) throw new Error('NO_ACTIVE_ANALYSIS')
  return active
}

const SESSION_NOTE_ID = /^[a-zA-Z0-9._-]{1,200}$/
const MAX_SESSION_NOTES = 32
const MAX_SESSION_NOTE_CHARS = 2000

function sha256Hex(text: string): string {
  return createHash('sha256').update(text).digest('hex')
}

function sessionNotesPath(sessionId: string): string | undefined {
  const home = typeof process.env.DSH_HOME === 'string' ? process.env.DSH_HOME.trim() : ''
  if (!home || !SESSION_NOTE_ID.test(sessionId)) return undefined
  return join(home, 'storages', 'threat-session-notes', `${sessionId}.json`)
}

async function readSessionNotes(sessionId: string): Promise<Record<string, unknown>> {
  const path = sessionNotesPath(sessionId)
  if (!path) return { state: 'NOTES_STORE_UNAVAILABLE', code: 'DSH_HOME_REQUIRED', items: [] }
  try {
    const raw = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>
    const items = Array.isArray(raw.items) ? raw.items : []
    return compactToolResult({ schema_version: 1, session_id: sessionId, items: items.slice(-MAX_SESSION_NOTES), total: items.length })
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? String((error as { code?: unknown }).code) : ''
    if (code === 'ENOENT') return { schema_version: 1, session_id: sessionId, items: [], total: 0 }
    return { state: 'NOTES_STORE_UNAVAILABLE', code: error instanceof Error ? error.message : String(error), items: [] }
  }
}

async function writeSessionNote(sessionId: string, text: string, replace = false): Promise<Record<string, unknown>> {
  const path = sessionNotesPath(sessionId)
  if (!path) return { state: 'NOTES_STORE_UNAVAILABLE', code: 'DSH_HOME_REQUIRED', accepted: false }
  const note = text.trim().slice(0, MAX_SESSION_NOTE_CHARS)
  if (!note) return { state: 'NOTE_REQUIRED', code: 'NOTE_REQUIRED', accepted: false }
  const current = await readSessionNotes(sessionId)
  const existing = Array.isArray(current.items) ? current.items : []
  const items = replace ? [note] : [...existing, note].slice(-MAX_SESSION_NOTES)
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, `${JSON.stringify({ schema_version: 1, session_id: sessionId, items }, null, 2)}\n`, 'utf8')
  return compactToolResult({ schema_version: 1, session_id: sessionId, accepted: true, items, total: items.length })
}

function compactToolResult(value: unknown, options: { preserve?: readonly string[] } = {}): Record<string, unknown> {
  const preserve = new Set(options.preserve ?? [])
  const row = value && typeof value === 'object' ? { ...(value as Record<string, unknown>) } : {}
  for (const key of ['value', 'message', 'reason', 'summary', 'content', 'note']) {
    if (preserve.has(key)) continue
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
  // DSH validates the returned object before rendering it. Optional values
  // assembled above may be undefined, which is not lossless JSON.
  return JSON.parse(JSON.stringify(row)) as Record<string, unknown>
}

function recordOf(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

/**
 * The official GET /api/v1/workbench/tasks/{id}/report payload nests the
 * revision under `revision.id`. Keep a dedicated citation field so chat
 * cannot treat a missing or aliased report_revision_id as optional.
 */
function authoritativeRevisionFromGetReport(row: Record<string, unknown>, report: Record<string, unknown>): string | undefined {
  const nested = recordOf(row.revision)
  const nestedReport = recordOf(row.report)
  return textValue(row.authoritative_revision_id, 80)
    || textValue(row.report_revision_id, 80)
    || textValue(nested.id, 80)
    || textValue(nested.revision_id, 80)
    || textValue(report.id, 80)
    || textValue(report.revision_id, 80)
    || textValue(nestedReport.id, 80)
    || textValue(nestedReport.revision_id, 80)
    || textValue(row.revision_id, 80)
}

/**
 * The one statement of the report-authoring obligation, shared by every
 * instruction that can observe CONVERGED.
 *
 * It lives in a single constant because it previously appeared only inside
 * ``citation_instruction``, which is returned exclusively by
 * ``threat_get_report_summary``. The CONVERGED "leftover dump" tells the agent
 * that the official markdown is already in ``content`` and that
 * ``threat_get_report_summary`` is only needed when it is missing -- so the
 * agent skipped that call, never saw the authoring step, and stopped with only
 * the deterministic revision published. Stating it here, in the CONVERGED
 * instructions themselves, removes that escape.
 */
const REPORT_AUTHORING_STEP =
  'The report is NOT finished yet, and the deliverable is a FILE. FIRST write the complete analyst report as markdown into the workspace with the file tools -- name it after the sample (<sample-name>.分析报告.md). That file is what an analyst reads, so make it read like an analyst wrote it: what each recovered module does, the order the behaviour happens in, what each recovered value MEANS, which countermeasures are present, and which indicators an operator can act on. Do not pad it with provenance narration or uncertainty boilerplate. THEN submit the same narrative with threat_submit_analyst_report so the gated revision records it, and reply in the conversation with only a short summary plus that file path -- never paste the whole report into the chat. Explain and prioritise only: never introduce an endpoint, IPv4, process image or creation-flags value the backend markdown does not contain, and never restate a CANDIDATE/UNKNOWN slot as established. The backend runs 报告合成门 (ADR-0036) and returns the exact violations on rejection, so fix exactly those and resubmit once. Having the markdown in the leftover dump is NOT a reason to skip this: that markdown is the fact base, not the finished report.'

function citationInstructionForRevision(taskId: string, revisionId: string | undefined): string {
  const authoring = REPORT_AUTHORING_STEP
  if (!revisionId) {
    return `Do not cite a report revision from memory. After the bound task is SUCCEEDED, FAILED, or CANCELLED, or wait returns CONVERGED, call threat_get_report_summary once to read the recovered facts. ${authoring} Then quote the authoritative_revision_id of the revision that is published after your submission. Then STOP. Do not call threat_propose_static_action. Do not read task_gaps to propose GET_DECOMPILE. Do not write to the desktop.`
  }
  return `Read the recovered facts from authoritative_revision_id ${revisionId} (GET /api/v1/workbench/tasks/${taskId}/report). ${authoring} The next user-visible reply MUST then quote the authoritative_revision_id published after your submission verbatim, together with the 分析结论 section of that revision's GET content (from '## 分析结论' until '## 调查附录'). Do not quote pipeline scores, Seed Map, Evidence UUIDs, or coverage dictionaries as the analyst conclusion. Do not ask 再深入 for HOW or UNKNOWN already written in this markdown. Do not summarize from memory if these tools were not called. CONVERGED: stop dispatch after the submission. Do not call threat_propose_static_action. Do not read task_gaps to propose GET_DECOMPILE. Do not write to the desktop. Gaps already in this revision stay UNKNOWN.`
}

function officialReportFields(taskId: string, row: Record<string, unknown>): Record<string, unknown> {
  const report = typeof row.revision === 'object' && row.revision
    ? row.revision as Record<string, unknown>
    : (typeof row.report === 'object' && row.report ? row.report as Record<string, unknown> : row)
  const authoritativeRevisionId = authoritativeRevisionFromGetReport(row, report)
  return {
    task_id: taskId,
    lifecycle: row.lifecycle ?? report.lifecycle,
    analysis_class: row.analysis_class ?? report.analysis_class,
    report_available: row.report_available ?? Boolean(report.markdown || authoritativeRevisionId),
    report_revision_id: authoritativeRevisionId,
    authoritative_revision_id: authoritativeRevisionId,
    citation_instruction: citationInstructionForRevision(taskId, authoritativeRevisionId),
    summary: row.summary ?? report.summary,
    content: row.content ?? report.markdown,
    stop_dispatch: Boolean(authoritativeRevisionId),
    convergence: authoritativeRevisionId ? 'CONVERGED' : undefined,
  }
}

const TERMINAL_TASK_LIFECYCLES = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED'])
const stopDispatch = new Map<string, { taskId?: string; revisionId?: string }>()

function isTerminalLifecycle(value: unknown): boolean {
  return TERMINAL_TASK_LIFECYCLES.has(String(value || '').trim().toUpperCase())
}

function markStopDispatch(sessionId: string, row: Record<string, unknown> = {}): void {
  if (!sessionId) return
  const previous = stopDispatch.get(sessionId) || {}
  stopDispatch.set(sessionId, {
    taskId: textValue(row.task_id, 80) || textValue(row.active_task_id, 80) || previous.taskId,
    revisionId: textValue(row.authoritative_revision_id, 80)
      || textValue(row.report_revision_id, 80)
      || previous.revisionId,
  })
}

function contextSaysStop(context: Record<string, unknown>): boolean {
  return isTerminalLifecycle(context.task_lifecycle)
    || isTerminalLifecycle(context.lifecycle)
    || String(context.convergence || '').trim().toUpperCase() === 'CONVERGED'
}

function stopDispatchResult(sessionId: string, extras: Record<string, unknown> = {}): Record<string, unknown> {
  const latch = stopDispatch.get(sessionId) || {}
  return compactToolResult({
    accepted: false,
    code: 'STOP_DISPATCH',
    convergence: 'CONVERGED',
    stop_dispatch: true,
    task_id: extras.task_id || latch.taskId,
    authoritative_revision_id: extras.authoritative_revision_id || latch.revisionId,
    instruction: `CONVERGED: stop dispatch. ${REPORT_AUTHORING_STEP} Then quote the authoritative_revision_id published after your submission and STOP. Do not read task_gaps to propose GET_DECOMPILE. Do not write to the desktop. Gaps already in the official revision stay UNKNOWN.`,
    ...extras,
  })
}

async function leftoverOfficialReportDump(
  client: ThreatApiClient,
  sessionId: string,
  waitRow: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  // Kunglao leftover dump: CONVERGED remainder is the official revision, not
  // another TRACE round. Attach markdown here so chat does not need a second
  // tool call (and a second 402 surface) after wait.
  if (waitRow.convergence !== 'CONVERGED' || waitRow.must_continue_waiting === true) return waitRow
  if (typeof waitRow.content === 'string' && waitRow.content.trim()) {
    const taskId = textValue(waitRow.task_id, 80) || ''
    const revisionId = textValue(waitRow.authoritative_revision_id, 80) || textValue(waitRow.report_revision_id, 80)
    const citation = typeof waitRow.citation_instruction === 'string' && waitRow.citation_instruction.trim()
      ? waitRow.citation_instruction
      : citationInstructionForRevision(taskId, revisionId)
    return compactToolResult({
      ...waitRow,
      citation_instruction: citation,
      instruction: waitRow.instruction || citation,
      stop_dispatch: true,
      convergence: 'CONVERGED',
    }, { preserve: ['content'] })
  }
  try {
    const context = await client.sessionContext(sessionId)
    const taskId = textValue(context.active_task_id, 80) || textValue(waitRow.task_id, 80) || ''
    const state = textValue(context.state, 80) || textValue(waitRow.state, 80) || ''
    if (!taskId || state === 'ANALYSIS_QUEUED' || state === 'ANALYSIS_RUNNING') return waitRow
    const dumped = officialReportFields(taskId, recordOf(await client.report(taskId, sessionId)))
    if (!dumped.content || dumped.report_available === false) return waitRow
    return compactToolResult({
      ...waitRow,
      ...dumped,
      instruction: dumped.citation_instruction,
      stop_dispatch: true,
      convergence: 'CONVERGED',
    }, { preserve: ['content'] })
  } catch {
    return waitRow
  }
}

function compactWaitResult(row: Record<string, unknown>): Record<string, unknown> {
  const context = recordOf(row.context)
  const progress = recordOf(row.progress)
  const lastMeaningful = row.last_meaningful_event && typeof row.last_meaningful_event === 'object'
    ? row.last_meaningful_event
    : null
  const mustContinue = row.must_continue_waiting === true
  const nextSeq = Number(row.next_after_event_seq ?? row.next_seq ?? 0) || 0
  const compact: Record<string, unknown> = {
    wait_status: textValue(row.wait_status, 40) || 'updated',
    must_continue_waiting: mustContinue,
    next_after_event_seq: nextSeq,
    convergence: textValue(row.convergence, 40) || (mustContinue ? 'SATURATED' : ''),
    instruction: boundedText(row.instruction, 400) || '',
    state: textValue(context.state, 80) || textValue(progress.state, 80) || '',
    changed: row.changed === true,
    event_counts: recordOf(row.event_counts),
    last_meaningful_event: lastMeaningful,
    progress: {
      stage: textValue(progress.stage, 80) || '',
      threads_active: progress.threads_active ?? 0,
      threads_total: progress.threads_total ?? 0,
      mechanisms_verified: progress.mechanisms_verified ?? 0,
      new_evidence_since_last: progress.new_evidence_since_last ?? 0,
      last_event_seq: progress.last_event_seq ?? 0,
    },
  }
  const leftover = typeof row.content === 'string' ? row.content : ''
  if (!mustContinue && leftover && compact.convergence === 'CONVERGED') {
    compact.content = leftover
    compact.task_id = textValue(row.task_id, 80) || textValue(context.active_task_id, 80)
    compact.report_available = true
    compact.report_revision_id = textValue(row.report_revision_id, 80) || textValue(row.authoritative_revision_id, 80)
    compact.authoritative_revision_id = textValue(row.authoritative_revision_id, 80) || compact.report_revision_id
    if (typeof row.citation_instruction === 'string' && row.citation_instruction.trim()) {
      compact.citation_instruction = row.citation_instruction
    }
  }
  return JSON.parse(JSON.stringify(compact))
}

type PresentedToolResult = {
  content?: Array<{ type?: string; text?: string }>
  isError?: boolean
}

function analystPrimaryMarkdown(markdown: string): string {
  const marker = '## 调查附录'
  const index = markdown.indexOf(marker)
  if (index < 0) return markdown
  return markdown.slice(0, index).trim()
}

function leftoverDumpPresentResult(
  _args: unknown,
  result: PresentedToolResult,
): { card: 'generic'; title?: string; content?: Array<{ type: 'text'; text: string }> } {
  // Kunglao leftover dump / NOTES_DUE: the official markdown is remainder
  // content. Put the analyst conclusion on the tool card so a chat 402 after
  // CONVERGED does not hide How / unique mechanisms / unknowns from the operator.
  if (result.isError) return { card: 'generic' }
  const raw = (result.content || []).map((block) => String(block?.text || '')).join('\n').trim()
  if (!raw) return { card: 'generic' }
  let markdown = ''
  let revision = ''
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    markdown = typeof parsed.content === 'string' ? parsed.content.trim() : ''
    revision = typeof parsed.authoritative_revision_id === 'string'
      ? parsed.authoritative_revision_id.trim()
      : ''
  } catch {
    markdown = raw
  }
  if (!markdown) return { card: 'generic' }
  const primary = analystPrimaryMarkdown(markdown)
  return {
    card: 'generic',
    title: revision ? `Official behavior report ${revision}` : 'Official behavior report',
    content: [{ type: 'text', text: primary }],
  }
}

const waitCursors = new Map<string, number>()

function floorWaitCursor(sessionId: string, requested?: number): number {
  const stored = waitCursors.get(sessionId) ?? 0
  const asked = Number.isFinite(Number(requested)) ? Math.max(0, Number(requested)) : 0
  return Math.max(stored, asked)
}

function rememberWaitCursor(sessionId: string, nextSeq: number): void {
  const current = waitCursors.get(sessionId) ?? 0
  if (nextSeq > current) waitCursors.set(sessionId, nextSeq)
}

export function apply(ctx: Context, config: Config): void {
  waitCursors.clear()
  stopDispatch.clear()
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
    description: 'Import one user-selected workspace-relative file as a static Artifact and attach it to the current DSH session. Omit case_id unless the session context already contains a real case UUID. Never invent default, current, test, or random IDs. This performs no shell, subprocess, sample execution, or network access.',
    parameters: { relative_path: { type: 'string' }, case_id: { type: 'string' } }, output,
    async execute(args: { relative_path?: string; case_id?: string }, exec: SessionExecution) {
      const id = sessionIdOf(exec); const path = typeof args.relative_path === 'string' ? args.relative_path.trim() : ''
      if (!id || !path) return { state: 'UNBOUND', code: 'WORKSPACE_PATH_REQUIRED' }
      const rawCase = typeof args.case_id === 'string' ? args.case_id.trim() : ''
      const caseId = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(rawCase) ? rawCase : undefined
      try { return await client.importWorkspaceArtifact(id, path, caseId ? { caseId } : {}) }
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
      stopDispatch.delete(id)
      waitCursors.delete(id)
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
    description: `Wait until analysis is terminal or the timeout elapses. SATURATED/must_continue_waiting=true means immediately call again with after_event_seq=next_after_event_seq and do not narrate. A timeout is not a report, not POLICY_DENIED, and not STATIC_BOUNDARY. CONVERGED means the loop exits -- but CONVERGED IS NOT THE END OF YOUR JOB: ${REPORT_AUTHORING_STEP} After the submission, quote the authoritative_revision_id published by it and STOP. Do not threat_propose_static_action after that.`,
    parameters: { after_event_seq: { type: 'integer' }, timeout_seconds: { type: 'integer' } }, output,
    async execute(args: { after_event_seq?: number; timeout_seconds?: number } = {}, exec: SessionExecution) {
      const id = sessionIdOf(exec)
      if (!id) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', changed: false, events: [] }
      try {
        const cursor = floorWaitCursor(id, args.after_event_seq)
        const compact = compactWaitResult(recordOf(await client.waitForAnalysisUpdate(id, cursor, args.timeout_seconds ?? 120)))
        rememberWaitCursor(id, Number(compact.next_after_event_seq) || 0)
        const dumped = await leftoverOfficialReportDump(client, id, compact)
        if (dumped.convergence === 'CONVERGED' && dumped.must_continue_waiting !== true) {
          markStopDispatch(id, dumped)
        }
        return dumped
      }
      catch (error) { return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error), changed: false, events: [] } }
    },
    presentCall: () => ({ card: 'generic', title: 'Wait for analysis progress', kind: 'read' }),
    presentResult: leftoverDumpPresentResult,
  }))
  ctx.tools.register(defineTool({
    name: 'threat_propose_static_action',
    description: 'Propose one bounded read-only static investigation action while the bound task is still PENDING or RUNNING. After CONVERGED or a terminal task plus threat_get_report_summary, this tool is forbidden (STOP_DISPATCH). Supply question, hypothesis, alternatives, missing_evidence, failure_meaning and existing evidence_ids at the top level. Preferred target_selector keys: target, api, function, function_entry, entry, rva, address, length, offset. Aliases such as function_name and length are accepted. After GET_DECOMPILE/READ_BYTES stalls, propose CONTROLLED_EMULATE so the isolated emu-worker can run granted bytes. Never self-authorize emu. Do not invent model provenance. The backend validates the plan, catalog, target, policy and evidence before execution.',
    parameters: {
      action_type: { type: 'string' }, target_artifact_id: { type: 'string' }, hypothesis_id: { type: 'string' },
      reason: { type: 'string' },
      question: { type: 'string', description: 'The falsifiable investigation question.' },
      hypothesis: { type: 'string', description: 'The mechanism hypothesis being tested.' },
      alternatives: { type: 'array', items: { type: 'string' }, description: 'Plausible competing explanations.' },
      missing_evidence: { type: 'array', items: { type: 'string' }, description: 'Evidence needed to distinguish the alternatives.' },
      failure_meaning: { type: 'string', description: 'What failure to obtain the evidence would mean; never equate it with absence.' },
      // DSH's schema compiler requires object openness to be explicit. The
      // backend owns validation of selector keys, so preserve extensibility
      // here while keeping the tool contract JSON-schema compliant.
      target_selector: { type: 'object', additionalProperties: true },
      expected_evidence_kinds: { type: 'array', items: { type: 'string' } },
      success_condition: { type: 'string' },
      failure_interpretation: {
        type: 'string',
        description: 'Exactly UNKNOWN, NO_NEW_EVIDENCE, or STATIC_BOUNDARY. Put any branching explanation in failure_meaning.',
      },
      evidence_ids: { type: 'array', items: { type: 'string' } },
      origin: { type: 'string' }, planner_turn_id: { type: 'string' },
      model_call_id: { type: 'string' }, model_run_id: { type: 'string' },
      model_provider: { type: 'string' }, model_name: { type: 'string' },
      provider: { type: 'string' }, model: { type: 'string' },
      prompt_sha256: { type: 'string' }, profile_digest: { type: 'string' },
      policy_digest: { type: 'string' }, action_validation_digest: { type: 'string' },
      action_validation: { type: 'object', additionalProperties: true },
      model_provenance: { type: 'object', additionalProperties: true },
    }, output,
    async execute(args: Record<string, unknown>, exec: SessionExecution) {
      const id = sessionIdOf(exec)
      if (!id) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', accepted: false }
      try {
        const context = recordOf(await client.sessionContext(id))
        if (stopDispatch.has(id) || contextSaysStop(context)) {
          markStopDispatch(id, { ...context, task_id: context.active_task_id })
          return stopDispatchResult(id, { task_id: context.active_task_id })
        }
        return await client.proposeStaticAction(id, modelActionPayload(args, exec, id))
      }
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
    description: `Read the official GET /api/v1/workbench/tasks/{id}/report revision after CONVERGED or a terminal task. The result always includes authoritative_revision_id equal to that GET revision. ${REPORT_AUTHORING_STEP} After the submission, the next user-visible reply MUST quote the authoritative_revision_id published by it, then STOP. Do not call threat_propose_static_action after this result. Do not read task_gaps to propose GET_DECOMPILE. Do not write to the desktop. Gaps already in this markdown stay UNKNOWN. Copy its facts and finding_status. Do not add APIs, constants, family names, or verification upgrades that are absent from this markdown. Do not summarize from memory if this tool was not called. Evidence query is for investigation, not a second report. Failed tasks never expose intermediate Markdown as a final report.`,
    parameters: {},
    output,
    async execute(_args: Record<string, never>, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', report_available: false }
      try {
        const context = await client.sessionContext(sessionId)
        const taskId = typeof context.active_task_id === 'string' ? context.active_task_id : ''
        if (!taskId) return { state: typeof context.state === 'string' ? context.state : 'UNBOUND', code: 'NO_ACTIVE_ANALYSIS', report_available: false }
        const state = typeof context.state === 'string' ? context.state : ''
        if (state === 'ANALYSIS_QUEUED' || state === 'ANALYSIS_RUNNING') {
          return compactToolResult({
            schema_version: 1,
            task_id: taskId,
            state,
            lifecycle: context.task_lifecycle,
            report_available: false,
            code: 'ANALYSIS_IN_PROGRESS',
            summary: 'The bound task has not reached a terminal state. Do not cite a previous task revision.',
            citation_instruction: 'The bound task is not terminal. Do not cite a report revision from memory or a previous task.',
          })
        }
        const result = await client.report(taskId, sessionId)
        const row = result && typeof result === 'object' ? result as Record<string, unknown> : {}
        const dumped = officialReportFields(taskId, row)
        if (dumped.authoritative_revision_id || isTerminalLifecycle(context.task_lifecycle) || isTerminalLifecycle(row.lifecycle)) {
          markStopDispatch(sessionId, { ...dumped, task_id: taskId })
        }
        return compactToolResult({ schema_version: 1, ...dumped }, { preserve: ['content'] })
      } catch (error) {
        return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error), report_available: false }
      }
    },
    presentCall: () => ({ card: 'generic', title: 'Read final report status', kind: 'read' }),
    presentResult: leftoverDumpPresentResult,
  }))
  ctx.tools.register(defineTool({
    name: 'threat_query_current_analysis_evidence',
    description: 'Query bounded evidence for the current DSH session analysis. Task identity is injected by the server and cannot be supplied by the model. Use filter_text to DRILL INTO ONE FUNCTION OR ADDRESS (0x140038ae0 / FUN_140038ae0 / 140038e2d) instead of paging a flat list: without it you can only read a kind in bulk, which is not enough to take a mechanism apart. Typical deep dives: kind=decompile_slice for a function body, kind=function_call or code_api_call for its calls, kind=xref for who reaches it, kind=api_argument_trace for what a call actually binds, kind=bytes_read/pcode_slice/data_reference for the underlying data. Read the evidence before concluding a slot is UNKNOWN.',
    parameters: {
      kind: { type: 'string' }, module: { type: 'string' },
      artifact_id: { type: 'string' }, limit: { type: 'integer' },
      filter_text: { type: 'string', description: 'Function entry or address to drill into, e.g. 0x140038ae0 or FUN_140038ae0.' },
    }, output,
    async execute(args: { kind?: string; module?: string; artifact_id?: string; limit?: number; filter_text?: string } = {}, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', items: [] }
      try { return await client.currentEvidence(sessionId, { kind: args.kind, module: args.module, artifactId: args.artifact_id, limit: args.limit, filterText: args.filter_text }) }
      catch (error) { return { state: 'UNBOUND', code: error instanceof Error ? error.message : String(error), items: [] } }
    },
    presentCall: (args: { kind?: string; filter_text?: string }) => ({ card: 'generic', title: 'Query current static evidence', kind: 'search', rawInput: { kind: args.kind, filter_text: args.filter_text } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_get_capabilities',
    description: 'Read the backend closed catalog of allowed read-only static actions.',
    parameters: {}, output,
    async execute() { return client.capabilities() },
    presentCall: () => ({ card: 'generic', title: 'Read static action catalog', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_read_session_notes',
    description: 'Read bounded investigation notes stored for the current DSH session. Notes live under the product DSH_HOME session store, never the sample workspace, and never execute a file.',
    parameters: {}, output,
    async execute(_args: Record<string, never>, exec: SessionExecution) {
      const id = sessionIdOf(exec)
      if (!id) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', items: [] }
      return readSessionNotes(id)
    },
    presentCall: () => ({ card: 'generic', title: 'Read session notes', kind: 'read' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_write_session_note',
    description: 'Append one bounded investigation note to the current DSH session store. This is not host malware execution, not a sample-workspace write, and not a substitute for threat_propose_static_action.',
    parameters: { note: { type: 'string' }, replace: { type: 'boolean' } }, output,
    async execute(args: { note?: string; replace?: boolean } = {}, exec: SessionExecution) {
      const id = sessionIdOf(exec)
      if (!id) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', accepted: false }
      return writeSessionNote(id, typeof args.note === 'string' ? args.note : '', Boolean(args.replace))
    },
    presentCall: (args: { note?: string }) => ({ card: 'generic', title: 'Write session note', kind: 'run', rawInput: { note: boundedText(args.note, 80) } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_workbench_model_complete',
    description: 'Ask the existing backend model gateway for one structured planning or claims completion on the already-bound task. Session, case, and task IDs are injected; this does not select a provider, open a shell, write the sample workspace, or contact sample network. It is not a second analysis-planner chat route and does not replace threat_propose_static_action.',
    parameters: {
      question: { type: 'string', description: 'The bounded planning or claims question.' },
      operation: { type: 'string', description: 'Exactly planning or claims.' },
    }, output,
    async execute(args: { question?: string; operation?: string } = {}, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION' }
      const question = typeof args.question === 'string' ? args.question.trim().slice(0, 4000) : ''
      if (!question) return { state: 'QUESTION_REQUIRED', code: 'QUESTION_REQUIRED' }
      const operation = args.operation === 'claims' ? 'claims' : 'planning'
      try {
        const context = await client.sessionContext(sessionId)
        const taskId = typeof context.active_task_id === 'string' ? context.active_task_id.trim() : ''
        const caseId = typeof context.case_id === 'string' ? context.case_id.trim() : ''
        if (!taskId || !caseId) return { state: typeof context.state === 'string' ? context.state : 'UNBOUND', code: 'NO_ACTIVE_ANALYSIS' }
        const plannerTurnId = plannerTurnIdOf({ ...args }, exec)
        return compactToolResult(await client.completeModel({
          operation, case_id: caseId, session_id: sessionId, task_id: taskId,
          turn_id: plannerTurnId, step_id: plannerTurnId, module: operation,
          prompt_id: 'dsh-workbench-complete', prompt_version: '1',
          prompt_sha256: sha256Hex(question),
          messages: [{ role: 'user', content: question }],
        }))
      } catch (error) {
        return { state: 'UNKNOWN', code: error instanceof Error ? error.message : String(error) }
      }
    },
    presentCall: (args: { operation?: string }) => ({ card: 'generic', title: 'Backend model complete', kind: 'run', rawInput: { operation: args.operation || 'planning' } }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_submit_analyst_report',
    description: 'Submit the analyst narrative for the bound task\'s current report revision. This is how the model writes the report: reorganise, explain and prioritise what the deterministic pass already recovered -- what each module does, the order the behaviour happens in, what each recovered value means for the analyst. It may NOT introduce an endpoint, IPv4, process image or creation-flags value that the backend fragments do not contain, and may not restate a CANDIDATE/UNKNOWN slot as established: the backend runs 报告合成门 (ADR-0036) and rejects such a draft, returning the exact violations so you can revise. A rejection is not an analysis failure -- the deterministic report stays published. This does not run the sample, does not write the sample workspace, and does not contact sample network.',
    parameters: {
      markdown: { type: 'string', description: 'The complete analyst narrative in markdown.' },
    }, output,
    async execute(args: { markdown?: string } = {}, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', accepted: false }
      const markdown = typeof args.markdown === 'string' ? args.markdown.trim() : ''
      if (!markdown) return { state: 'MARKDOWN_REQUIRED', code: 'MARKDOWN_REQUIRED', accepted: false }
      try {
        const result = await client.submitAnalystDraft(sessionId, markdown)
        return compactToolResult({ schema_version: 1, accepted: true, gate: 'report-compose-gate', ...result })
      } catch (error) {
        return {
          state: 'GATE_REJECTED',
          accepted: false,
          code: error instanceof Error ? error.message : String(error),
          guidance: 'The report compose gate rejected this draft. Read the violation list in code, remove every fact it names that the backend fragments do not contain (or the wording it flags as upgrading a CANDIDATE/UNKNOWN), then resubmit once. Do not retry the identical draft.',
        }
      }
    },
    presentCall: () => ({ card: 'generic', title: 'Submit analyst narrative', kind: 'run' }),
  }))
  ctx.tools.register(defineTool({
    name: 'threat_write_report_file',
    description: 'Write the analyst report document to disk. THIS IS YOUR DELIVERABLE: when the investigation converges, write the complete report as markdown here and then reply in the conversation with only a short summary plus the returned path -- never paste the whole report into the chat. Write it the way an analyst reads it: what each recovered module does, the order the behaviour happens in, what each recovered value MEANS, which countermeasures are present, and which indicators an operator can act on. Do not pad it with provenance narration or uncertainty boilerplate. The file name must be a plain markdown name (for example Resume.pdf.exe.VIR.分析报告.md); no directories, no traversal. The sample workspace is read-only and this does not execute the sample. Facts must come from the recovered evidence: never introduce an endpoint, IPv4, process image or creation-flags value the backend markdown does not contain, and never restate a CANDIDATE/UNKNOWN slot as established. You may also submit the same narrative with threat_submit_analyst_report so the gated revision records it.',
    parameters: {
      filename: { type: 'string', description: 'Plain markdown file name, e.g. sample.分析报告.md' },
      markdown: { type: 'string', description: 'The complete analyst report as markdown.' },
    }, output,
    async execute(args: { filename?: string; markdown?: string } = {}, exec: SessionExecution) {
      const sessionId = sessionIdOf(exec)
      if (!sessionId) return { state: 'UNBOUND', code: 'NO_DSH_SESSION', written: false }
      const filename = typeof args.filename === 'string' ? args.filename.trim() : ''
      const markdown = typeof args.markdown === 'string' ? args.markdown : ''
      if (!filename || !markdown.trim()) return { state: 'INPUT_REQUIRED', code: 'FILENAME_AND_MARKDOWN_REQUIRED', written: false }
      try {
        return compactToolResult({ schema_version: 1, ...(await client.writeReportFile(sessionId, filename, markdown)) })
      } catch (error) {
        return { state: 'WRITE_REJECTED', written: false, code: error instanceof Error ? error.message : String(error) }
      }
    },
    presentCall: (args: { filename?: string }) => ({ card: 'generic', title: 'Write analyst report file', kind: 'run', rawInput: { filename: args.filename } }),
  }))
}

export function summarizeToolResult(value: unknown): Record<string, unknown> {
  const row = value && typeof value === 'object' ? value as Record<string, unknown> : {}
  return { status: boundedText(row.status, 80), evidence_ids: boundedIds(row.evidence_ids), summary: boundedText(row.summary) }
}
