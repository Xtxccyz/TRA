import { ThreatApiClient } from '@threat-dsh/api-client'
import {
  boundedIds,
  boundedText,
  classifyModelFailure,
  firstRequestProtocolPacket,
  TEN_INVESTIGATION_QUESTIONS,
  type ThreatPluginManifest,
} from '@threat-dsh/plugin-sdk'
import type { Context } from '@deepseek-ai/cordis'

export const manifest: ThreatPluginManifest = {
  id: 'threat-context-provider', version: '1.0.0', plugin_api: 1,
  capabilities: ['context'], required_backend_api: '>=1,<2', required_event_schema: 1,
  security_profile: ['threat-static'],
}

export interface ContextProviderConfig {
  readonly backendUrl?: string
  readonly token?: string
}

interface SessionLike {
  readonly id?: string
  readonly events?: unknown
}
interface PromptAssemblyContext { readonly agent?: { readonly session?: SessionLike; readonly inbox?: unknown } }
interface PromptContextRow { name: string; text: string }
interface PromptAssemblyLike { contexts: PromptContextRow[] }
interface PromptAssemblyListenerContext {
  readonly agent?: { readonly session?: SessionLike; readonly inbox?: unknown }
  readonly scope?: unknown
  readonly prompt?: unknown
  readonly userPrompt?: unknown
  readonly question?: unknown
  readonly input?: unknown
  readonly messages?: unknown
  readonly inbox?: unknown
  readonly session?: SessionLike
}
interface SessionEventLike {
  readonly type?: unknown
  readonly data?: unknown
}

const ANALYSIS_INTENT_MARKERS = [
  '分析这个样本',
  '分析此样本',
  '分析样本',
  'analyze this sample',
  'analyse this sample',
  'start static analysis',
  '开始分析',
]

function contentText(value: unknown, limit = 1000): string {
  const direct = text(value, limit)
  if (direct) return direct
  if (!Array.isArray(value)) return ''
  const parts: string[] = []
  for (const block of value) {
    const row = objectValue(block)
    const piece = text(row.text) || contentText(row.content, limit)
    if (piece) parts.push(piece)
    if (parts.join('').length >= limit) break
  }
  return parts.join('').slice(0, limit)
}

function humanUserText(message: unknown): string {
  const row = objectValue(message)
  const source = objectValue(row.source)
  const kind = text(source.kind)
  if (kind && kind !== 'user') return ''
  const role = (text(row.role) || 'user').toLowerCase()
  if (role && role !== 'user') return ''
  return contentText(row.content)
}

function lastInboxUserQuestion(inbox: unknown): string {
  const row = objectValue(inbox)
  for (const key of ['nextTurn', 'nextStep', 'next-turn', 'next-step']) {
    const messages = Array.isArray(row[key]) ? row[key] : []
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const value = humanUserText(messages[index])
      if (value) return value
    }
  }
  return ''
}

function lastSessionUserQuestion(session: unknown): string {
  const events = Array.isArray(objectValue(session).events) ? objectValue(session).events as unknown[] : []
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const value = userQuestionFromEvent(events[index])
    if (value) return value
  }
  return ''
}

function userQuestionFromEvent(event: unknown): string {
  const row = objectValue(event)
  if ((text(row.type) || 'user/message') !== 'user/message') return ''
  return humanUserText(row.data && typeof row.data === 'object' ? row.data : row)
}

function userQuestionOf(assembly: unknown, raw: unknown): string {
  const bags = [objectValue(assembly), objectValue(raw)]
  for (const bag of bags) {
    for (const key of ['userPrompt', 'user_prompt', 'prompt', 'question', 'input', 'text']) {
      const value = text(bag[key], 1000)
      if (value) return value
    }
    const agent = objectValue(bag.agent)
    const nested = [agent.session, bag.session, bag.header, bag.scope]
    for (const item of nested) {
      const row = objectValue(item)
      for (const key of ['userPrompt', 'prompt', 'question', 'input', 'text']) {
        const value = text(row[key], 1000)
        if (value) return value
      }
    }
    const messages = Array.isArray(bag.messages) ? bag.messages : []
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const row = objectValue(messages[index])
      if ((text(row.role) || '').toLowerCase() !== 'user') continue
      const value = contentText(row.content, 1000)
      if (value) return value
    }
    const pending = lastInboxUserQuestion(agent.inbox) || lastInboxUserQuestion(bag.inbox)
    if (pending) return pending
    const fromSession = lastSessionUserQuestion(agent.session)
      || lastSessionUserQuestion(objectValue(bag.scope).session)
      || lastSessionUserQuestion(bag.session)
    if (fromSession) return fromSession
  }
  return ''
}

function isAnalysisIntent(question: string): boolean {
  const blob = question.toLowerCase()
  return ANALYSIS_INTENT_MARKERS.some((marker) => blob.includes(marker.toLowerCase()))
}
interface CachedContext {
  readonly fetchedAt: number
  readonly sessionId: string
  readonly context: Record<string, unknown>
}

const CACHE_TTL_MS = 2_000
const MAX_ITEMS = 64
const MAX_TEXT = 1_200

function sessionIdOf(value: PromptAssemblyContext | undefined): string {
  const id = value?.agent?.session?.id
  return typeof id === 'string' ? id.trim().slice(0, 200) : ''
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function text(value: unknown, limit = MAX_TEXT): string | undefined {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') return undefined
  const output = String(value).trim()
  return output ? output.slice(0, limit) : undefined
}

function ids(value: unknown): string[] {
  return boundedIds(Array.isArray(value) ? value : [])
}

const IN_FLIGHT_LIFECYCLES = new Set(['PENDING', 'RUNNING'])
const TERMINAL_LIFECYCLES = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED'])

function reportRevisionId(report: Record<string, unknown>, taskRow: Record<string, unknown>): string | undefined {
  const nested = objectValue(report.revision)
  return text(report.revision_id)
    || text(report.report_revision_id)
    || text(report.authoritative_revision_id)
    || text(nested.id)
    || text(report.id)
    || text(taskRow.authoritative_report_revision_id)
    || text(taskRow.latest_report_revision_id)
}

function inFlightReport(taskRow: Record<string, unknown>, report: Record<string, unknown>): Record<string, unknown> {
  const lifecycle = text(taskRow.lifecycle)
  if (lifecycle === 'PENDING' || lifecycle === 'RUNNING') {
    return {
      revision_id: undefined,
      available: false,
      status: lifecycle,
      this_turn_ready: false,
      do_not_cite_prior_revisions: true,
    }
  }
  const revisionId = reportRevisionId(report, taskRow)
  return {
    revision_id: revisionId,
    authoritative_revision_id: revisionId,
    available: Boolean(report.available) || Boolean(report.markdown) || Boolean(revisionId),
    status: text(report.status),
    this_turn_ready: true,
    do_not_cite_prior_revisions: false,
  }
}

/**
 * Official GET /api/v1/workbench/tasks/{id}/report nests the revision under
 * `revision.id`. Use that UUID as the only terminal citation.
 */
export function revisionIdFromGetReport(payload: unknown): string | undefined {
  const row = objectValue(payload)
  const revision = objectValue(row.revision)
  const nested = objectValue(row.report)
  return text(row.authoritative_revision_id)
    || text(row.report_revision_id)
    || text(revision.id)
    || text(revision.revision_id)
    || text(nested.id)
    || text(nested.revision_id)
    || text(row.revision_id)
}

export function overlayAuthoritativeGetReport(
  projected: Record<string, unknown>,
  getPayload: unknown,
): Record<string, unknown> {
  const taskRow = objectValue(projected.task)
  const lifecycle = text(taskRow.lifecycle)
  if (IN_FLIGHT_LIFECYCLES.has(lifecycle || '')) return attachOfficialRevision(projected)
  const revisionId = revisionIdFromGetReport(getPayload)
  const report = objectValue(projected.report)
  return attachOfficialRevision({
    ...projected,
    task: revisionId ? {
      ...taskRow,
      latest_report_revision_id: revisionId,
      authoritative_report_revision_id: revisionId,
    } : taskRow,
    report: {
      ...report,
      revision_id: revisionId,
      authoritative_revision_id: revisionId,
      available: Boolean(revisionId) || Boolean(report.available),
      this_turn_ready: TERMINAL_LIFECYCLES.has(lifecycle || '') ? true : report.this_turn_ready,
      do_not_cite_prior_revisions: false,
    },
  })
}

function compactRow(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const source = objectValue(value)
  const row: Record<string, unknown> = {}
  for (const field of fields) {
    const candidate = source[field]
    if (Array.isArray(candidate)) {
      row[field] = candidate.slice(-MAX_ITEMS).map((item) => text(item) ?? item).filter((item) => item !== undefined)
    } else if (candidate && typeof candidate === 'object') {
      row[field] = compactRow(candidate, Object.keys(candidate).slice(0, 16))
    } else {
      const valueText = text(candidate)
      if (valueText !== undefined) row[field] = valueText
    }
  }
  return row
}

/**
 * The ten question slots are the canonical protocol list, not a local copy:
 * ``unanswered_ten_question_slots`` and the model-facing protocol packet must
 * never disagree about which questions the investigation owes.
 */
const TEN_QUESTION_SLOTS: readonly [string, string][] = TEN_INVESTIGATION_QUESTIONS
  .map((item) => [item.slot, item.question] as [string, string])

const ANSWERED_SLOT = new Set(['ANSWERED', 'N/A', 'NA', 'NOT_APPLICABLE'])
const SKIP_THREAD_STATES = new Set(['REJECTED', 'CONTRADICTED', 'NOT_APPLICABLE'])
const READY_THREAD_STATES = new Set(['CLAIM_READY', 'MECHANISM_READY', 'CLOSED'])
// Kunglao leftover remainder: recorded HOW / honest static boundary is report
// content. TRACE cannot invent WinHTTP or module_input; do not keep these as
// planner tickets that make chat ask 再深入 after one round.
const RECORDED_REMAINDER_STATES = new Set([
  ...SKIP_THREAD_STATES,
  ...READY_THREAD_STATES,
  'UNKNOWN', 'CANDIDATE', 'PARTIAL', 'UNSUPPORTED', 'STATIC_BOUNDARY',
  'VERIFIED', 'SUPPORTED', 'CONFIRMED',
])

function isPersistHowSkip(row: Record<string, unknown>): boolean {
  const status = upper(row.status) || upper(row.result_status)
  if (status !== 'CANCELLED' && status !== 'FAILED') return false
  const blob = `${text(row.error) || ''} ${text(row.reason) || ''}`.toUpperCase()
  return blob.includes('PERSIST_HOW_SKIP')
}

function plannerVisibleActions(actions: unknown[]): Record<string, unknown>[] {
  return actions.map((item) => objectValue(item)).filter((row) => !isPersistHowSkip(row))
}

const OS_THREAD_SEEDS = new Set(['create_thread', 'thread_callback', 'tls_callback', 'apc', 'thread_pool', 'timer_callback', 'os_thread'])
const OS_THREAD_RE = /createthread|createremotethread|queueuserapc|ntqueueapcthread|tpallocwork|rtlregisterwait|tls.?callback|thread.?pool|start_routine|lpstartaddress|ntcreatethread/i
const DECODE_RE = /decode|decrypt|xor|crypt/i
const SLOT_ALIASES: Record<string, string> = {
  initiator: 'initiator', input: 'input', state: 'state_config', config: 'state_config',
  state_config: 'state_config', transformation: 'transformation', condition: 'condition',
  side_effect: 'side_effect', side_effects: 'side_effect', output: 'output', outputs: 'output',
  consumer: 'consumer', consumers: 'consumer', loop: 'loop', failure: 'failure_fallback',
  failure_fallback: 'failure_fallback', fallback: 'failure_fallback',
}

function upper(value: unknown): string {
  return (text(value) || '').toUpperCase()
}

function isOsInvestigationThread(row: Record<string, unknown>): boolean {
  const seed = (text(row.seed_kind) || '').toLowerCase()
  if (seed && OS_THREAD_SEEDS.has(seed)) return true
  return OS_THREAD_RE.test(text(row.question) || '') || OS_THREAD_RE.test(text(row.seed_kind) || '')
}

function isDecodeRow(row: Record<string, unknown>): boolean {
  const blob = [row.type, row.category, row.kind, row.seed_kind, row.mechanism_id].map((item) => text(item) || '').join(' ')
  return DECODE_RE.test(blob)
}

function plannerOpenThread(row: Record<string, unknown>): boolean {
  const state = upper(row.state)
  return Boolean(state) && !RECORDED_REMAINDER_STATES.has(state)
}

function slotName(field: string): string | undefined {
  return SLOT_ALIASES[field.trim().toLowerCase()]
}

function unansweredFromProtocol(thread: Record<string, unknown>): Record<string, unknown>[] {
  if (RECORDED_REMAINDER_STATES.has(upper(thread.state))) return []
  const protocol = objectValue(thread.protocol)
  const threadId = text(thread.id)
  const evidenceIds = ids(thread.evidence_ids)
  const rows: Record<string, unknown>[] = []
  if (!Object.keys(protocol).length) return rows
  for (const [slot, question] of TEN_QUESTION_SLOTS) {
    if (!(slot in protocol)) continue
    const current = objectValue(protocol[slot])
    if (ANSWERED_SLOT.has(upper(current.status))) continue
    rows.push({
      investigation_thread_id: threadId,
      slot,
      status: 'UNKNOWN',
      reason: text(current.reason) || 'not recovered from available static evidence',
      evidence_ids: ids(current.evidence_ids).length ? ids(current.evidence_ids) : evidenceIds,
      question: text(current.question) || question,
    })
  }
  return rows
}

function unansweredFromMissingFields(thread: Record<string, unknown>, mechanisms: unknown[]): Record<string, unknown>[] {
  const threadId = text(thread.id)
  const seen = new Set<string>()
  const rows: Record<string, unknown>[] = []
  for (const item of mechanisms) {
    const row = objectValue(item)
    const missing = Array.isArray(row.missing_fields) ? row.missing_fields : Array.isArray(row.unknowns) ? row.unknowns : []
    for (const field of missing) {
      const slot = slotName(String(field || ''))
      if (!slot || seen.has(slot)) continue
      seen.add(slot)
      rows.push({
        investigation_thread_id: threadId,
        slot,
        status: 'UNKNOWN',
        reason: text(row.status) ? `${text(row.type) || text(row.category) || 'mechanism'} missing ${slot}` : `missing ${slot}`,
        evidence_ids: ids(row.evidence_ids).length ? ids(row.evidence_ids) : ids(thread.evidence_ids),
        question: TEN_QUESTION_SLOTS.find(([name]) => name === slot)?.[1],
      })
    }
  }
  return rows
}

function s4Row(thread: Record<string, unknown>, actions: unknown[]): Record<string, unknown> {
  const threadId = text(thread.id)
  const state = upper(thread.state)
  const ladder = objectValue(thread.s_ladder)
  const actionIds = ids(thread.action_ids)
  const evidenceIds = ids(thread.evidence_ids)
  if (SKIP_THREAD_STATES.has(state)) {
    return { investigation_thread_id: threadId, status: 'NOT_APPLICABLE', reason: 'thread was rejected or explicitly marked not applicable' }
  }
  if (READY_THREAD_STATES.has(state)) {
    return {
      investigation_thread_id: threadId,
      status: 'CLOSED',
      reason: 'persist/verifier-ready HOW is leftover remainder; isolated emu is not another TRACE round',
    }
  }
  if (RECORDED_REMAINDER_STATES.has(state)) {
    return {
      investigation_thread_id: threadId,
      status: 'RECORDED',
      reason: 'honest static boundary is report UNKNOWN/CANDIDATE content, not a planner ticket',
    }
  }
  const attempted = Array.isArray(ladder.attempted_action_types) ? ladder.attempted_action_types : []
  const s1 = upper(ladder.s1_context)
  const s2 = upper(ladder.s2_dataflow)
  const s3 = upper(ladder.s3_consumer)
  const s4 = upper(ladder.s4_orchestration)
  const familyNa = [s1, s2, s3].every((item) => item === 'NOT_APPLICABLE' || item === 'UNSUPPORTED')
  if (s4 === 'CLOSED') {
    if (attempted.length || familyNa) {
      return { investigation_thread_id: threadId, status: 'CLOSED', reason: 'S1-S3 were attempted or marked N/A/unsupported; S4 is recorded closed' }
    }
    return {
      investigation_thread_id: threadId, status: 'BLOCKED',
      reason: 'S4 CLOSED with empty attempts is not an auditable S1-S3 trail; retain BLOCKED until attempts or an explicit family N/A reason exist',
    }
  }
  const failed = actions.some((item) => {
    const row = objectValue(item)
    if (isPersistHowSkip(row)) return false
    return actionIds.includes(text(row.id) || '') && ['FAILED', 'BLOCKED', 'CANCELLED'].includes(upper(row.status))
  })
  return {
    investigation_thread_id: threadId,
    status: 'BLOCKED',
    reason: failed
      ? 'thread has a recorded failed/boundary action'
      : (s4 ? 'S4 remains open because S1-S3 are incomplete or blocked' : 'S4 orchestration closure was not reached; retain the frontier and unknowns'),
  }
}

function uniqueOsThreadStarts(task: Record<string, unknown>, threads: unknown[], mechanisms: unknown[], evidence: unknown[]): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = []
  const seen = new Set<string>()
  const push = (row: Record<string, unknown>) => {
    const key = `${row.investigation_thread_id || ''}|${row.os_object || ''}|${row.start_routine || ''}`
    if (seen.has(key)) return
    seen.add(key)
    rows.push(row)
  }
  const openOsThreads = threads.map((item) => objectValue(item)).filter((thread) => (
    isOsInvestigationThread(thread) && plannerOpenThread(thread)
  ))
  const listed = [
    ...(Array.isArray(task.unique_execution_threads) ? task.unique_execution_threads : []),
    ...(Array.isArray(objectValue(task.report).unique_execution_threads) ? objectValue(task.report).unique_execution_threads as unknown[] : []),
  ]
  for (const item of listed) {
    if (!openOsThreads.length) continue
    const row = objectValue(item)
    const start = text(row.start_routine) || 'UNKNOWN(start_routine)'
    if (!start.startsWith('UNKNOWN')) continue
    const osObject = text(row.api) || text(row.os_object) || 'CreateThread'
    const match = openOsThreads[0]
    push({
      investigation_thread_id: match ? text(match.id) : undefined,
      os_object: osObject,
      start_routine: start.startsWith('UNKNOWN') ? 'UNKNOWN' : start,
      reason: text(row.reason) || 'OS thread start routine was listed but the entry was not recovered',
      evidence_ids: ids(row.evidence_ids),
    })
  }
  for (const item of threads) {
    const thread = objectValue(item)
    if (!isOsInvestigationThread(thread) || !plannerOpenThread(thread)) continue
    const initiator = objectValue(objectValue(thread.protocol).initiator)
    const startUnknown = !ANSWERED_SLOT.has(upper(initiator.status)) || START_ROUTINE_UNKNOWN(initiator)
    if (!startUnknown && upper(initiator.status) === 'ANSWERED') continue
    push({
      investigation_thread_id: text(thread.id),
      os_object: text(thread.seed_kind) === 'create_thread' ? 'CreateThread' : (text(thread.seed_kind) || 'CreateThread'),
      start_routine: 'UNKNOWN',
      reason: text(initiator.reason) || 'OS thread start routine not recovered from static evidence',
      evidence_ids: ids(thread.evidence_ids),
    })
  }
  for (const item of mechanisms) {
    const row = objectValue(item)
    if (RECORDED_REMAINDER_STATES.has(upper(row.status)) && !openOsThreads.length) continue
    const missing = Array.isArray(row.missing_fields) ? row.missing_fields.map((value) => String(value)) : []
    if (!missing.some((field) => /start_routine|lpstartaddress/i.test(field))) continue
    push({
      investigation_thread_id: text(row.thread_id),
      os_object: text(row.type) === 'os_thread' ? 'CreateThread' : (text(row.type) || 'CreateThread'),
      start_routine: 'UNKNOWN',
      reason: 'mechanism is missing the OS thread start routine',
      evidence_ids: ids(row.evidence_ids),
    })
  }
  for (const item of evidence) {
    if (!openOsThreads.length) continue
    const row = objectValue(item)
    if (!['tls_callback', 'thread_callback'].includes((text(row.kind) || '').toLowerCase())) continue
    const value = objectValue(row.value)
    const start = text(value.start_routine) || text(value.lpStartAddress) || text(value.entry)
    if (start && !start.startsWith('UNKNOWN')) continue
    push({
      investigation_thread_id: undefined,
      os_object: text(row.kind) === 'tls_callback' ? 'TlsCallback' : 'CreateThread',
      start_routine: 'UNKNOWN',
      reason: 'callback/thread start was observed without a recovered start routine',
      evidence_ids: ids([row.id]),
    })
  }
  return rows.slice(0, 16)
}

function START_ROUTINE_UNKNOWN(initiator: Record<string, unknown>): boolean {
  const value = text(initiator.value) || ''
  return !value || value.startsWith('UNKNOWN')
}

function decodeConsumers(threads: unknown[], mechanisms: unknown[], evidence: unknown[]): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = []
  const seen = new Set<string>()
  const push = (row: Record<string, unknown>) => {
    const key = `${row.mechanism_id || ''}|${row.investigation_thread_id || ''}|${row.consumer || ''}`
    if (seen.has(key)) return
    seen.add(key)
    rows.push(row)
  }
  const openDecodeThreads = threads.map((item) => objectValue(item)).filter((thread) => (
    plannerOpenThread(thread) && (isDecodeRow(thread) || DECODE_RE.test(text(thread.question) || ''))
  ))
  for (const item of mechanisms) {
    const row = objectValue(item)
    if (RECORDED_REMAINDER_STATES.has(upper(row.status)) && !openDecodeThreads.length) continue
    const missing = Array.isArray(row.missing_fields) ? row.missing_fields.map((value) => String(value)) : []
    const unknowns = Array.isArray(row.unknowns) ? row.unknowns.map((value) => String(value)) : []
    const consumerText = text(row.consumer)
    const consumerUnknown = missing.some((field) => slotName(field) === 'consumer')
      || unknowns.some((field) => /consumer/i.test(field))
      || (consumerText ? consumerText.startsWith('UNKNOWN') : false)
    if (!(consumerUnknown || (isDecodeRow(row) && (!consumerText || consumerText.startsWith('UNKNOWN'))))) continue
    push({
      mechanism_id: text(row.mechanism_id) || text(row.id),
      producer: text(row.output) || text(row.what),
      consumer: 'UNKNOWN',
      reason: 'decoded output has no recovered consumer',
      evidence_ids: ids(row.evidence_ids),
    })
  }
  for (const item of threads) {
    const thread = objectValue(item)
    if (!plannerOpenThread(thread)) continue
    const consumer = objectValue(objectValue(thread.protocol).consumer)
    if (!isDecodeRow(thread) && !DECODE_RE.test(text(thread.question) || '')) continue
    if (ANSWERED_SLOT.has(upper(consumer.status))) continue
    if (!Object.keys(objectValue(thread.protocol)).length && !isDecodeRow(thread)) continue
    push({
      investigation_thread_id: text(thread.id),
      mechanism_id: undefined,
      producer: text(objectValue(objectValue(thread.protocol).output).value),
      consumer: 'UNKNOWN',
      reason: text(consumer.reason) || 'decoded output has no recovered consumer',
      evidence_ids: ids(thread.evidence_ids),
    })
  }
  for (const item of evidence) {
    if (!openDecodeThreads.length) continue
    const row = objectValue(item)
    if ((text(row.kind) || '').toLowerCase() !== 'decode_result') continue
    if (rows.some((existing) => ids(existing.evidence_ids).includes(text(row.id) || ''))) continue
    push({
      mechanism_id: undefined,
      producer: text(objectValue(row.value).output_buffer) || text(objectValue(row.value).plaintext) || text(row.id),
      consumer: 'UNKNOWN',
      reason: 'decode_result evidence has no recovered consumer',
      evidence_ids: ids([row.id]),
    })
  }
  return rows.slice(0, 16)
}

function nextBoundedMethods(actions: unknown[], threads: unknown[] = []): Record<string, unknown>[] {
  if (!threads.map((item) => objectValue(item)).some(plannerOpenThread)) return []
  const rows: Record<string, unknown>[] = []
  const seen = new Set<string>()
  for (const item of plannerVisibleActions(actions)) {
    const actionType = upper(item.action_type)
    const status = upper(item.status) || upper(item.result_status)
    if (!['GET_CALLEES', 'GET_FUNCTION'].includes(actionType) || status !== 'NO_NEW_EVIDENCE') continue
    if (seen.has(actionType)) continue
    seen.add(actionType)
    rows.push({
      after: actionType,
      result: 'NO_NEW_EVIDENCE',
      propose: ['GET_DECOMPILE', 'CONTROLLED_EMULATE'],
      self_authorized: false,
      note: 'Isolated granted-window Unicorn/Speakeasy/Qiling is static analysis on the emu-worker, not sandbox/dynamic execution. Propose CONTROLLED_EMULATE; never self-authorize.',
    })
  }
  return rows.slice(0, 8)
}

const MODEL_TRANSPORT_CODES = new Set(['MODEL_FAILURE', 'TIMEOUT_FAILURE', 'WORKER_FAILURE'])
const MODEL_TRANSPORT_HTTP = new Set(['401', '402', '403', '408', '429', '500', '502', '503', '504'])

/**
 * Keep model 402/timeout/empty reply, policy denial, and STATIC_BOUNDARY as
 * three separate classes. Pass-through of backend fields is not enough if the
 * packet never names the distinction.
 *
 * The sub-kind (402 vs timeout vs empty reply vs auth vs rate limit) comes from
 * the shared classifier so the workbench and the tool layer cannot drift apart
 * about what a failed model call was.
 */
function failureKindDistinction(taskRow: Record<string, unknown>, actions: unknown[] = []): Record<string, unknown> {
  const failure = objectValue(taskRow.failure)
  const modelStatus = objectValue(taskRow.model_status)
  const code = upper(failure.failure_code) || upper(failure.code)
  const kind = upper(modelStatus.kind)
  const http = String(modelStatus.http_status ?? failure.http_status ?? '').trim()
  const last = upper(modelStatus.last_status) || upper(failure.last_status)
  const errorType = upper(modelStatus.error_type) || upper(failure.error_type)
  const actionBlob = plannerVisibleActions(actions)
    .map((row) => `${upper(row.status)} ${upper(row.reason)} ${upper(row.result_status)} ${upper(row.stop_reason)}`)
    .join(' ')
  const modelFailure = classifyModelFailure({
    status: modelStatus.status ?? taskRow.status,
    kind: modelStatus.kind,
    http_status: modelStatus.http_status ?? failure.http_status,
    error_type: modelStatus.error_type ?? failure.error_type,
    error_detail: modelStatus.error_detail ?? failure.error_detail,
    last_status: modelStatus.last_status ?? failure.last_status,
    failure_code: failure.failure_code ?? failure.code,
    error: modelStatus.error ?? failure.error,
  })
  const modelFailed = modelFailure.observed === 'MODEL_OR_TRANSPORT'
  let observed = 'NONE'
  if (
    kind === 'MODEL_OR_TRANSPORT'
    || MODEL_TRANSPORT_CODES.has(code)
    || MODEL_TRANSPORT_HTTP.has(http)
    || last === 'TIMEOUT'
    || errorType.includes('TIMEOUT')
    || last === 'EMPTY_REPLY'
    || last === 'EMPTY_RESPONSE'
    || modelFailed
  ) observed = 'MODEL_OR_TRANSPORT'
  else if (code === 'POLICY_DENIED' || actionBlob.includes('POLICY_DENIED')) observed = 'POLICY_DENIED'
  else if (code === 'STATIC_BOUNDARY') observed = 'STATIC_BOUNDARY'
  return {
    model_or_transport: '402/timeout',
    policy_denied: 'POLICY_DENIED',
    static_boundary: 'STATIC_BOUNDARY',
    observed,
    do_not_collapse: true,
    failure_kind: modelFailure.kind,
    model_failure: modelFailure,
  }
}

/**
 * Compact, evidence-backed gaps for the first analysis turn. This is not a
 * second report and must not dump raw investigation ledgers.
 */
export function buildTaskGapPacket(task: Record<string, unknown>): Record<string, unknown> {
  const taskRow = objectValue(task.task)
  const terminal = TERMINAL_LIFECYCLES.has(upper(taskRow.lifecycle))
  const threads = Array.isArray(task.threads) ? task.threads : []
  const mechanisms = Array.isArray(task.mechanisms) ? task.mechanisms : []
  const evidence = Array.isArray(task.evidence) ? task.evidence : []
  const actions = plannerVisibleActions(Array.isArray(task.actions) ? task.actions : [])
  const unanswered: Record<string, unknown>[] = []
  const seenSlots = new Set<string>()
  for (const item of threads) {
    const thread = objectValue(item)
    for (const row of unansweredFromProtocol(thread)) {
      const key = `${row.investigation_thread_id}:${row.slot}`
      if (seenSlots.has(key)) continue
      seenSlots.add(key)
      unanswered.push(row)
    }
  }
  if (!unanswered.length) {
    for (const item of threads) {
      const thread = objectValue(item)
      if (RECORDED_REMAINDER_STATES.has(upper(thread.state))) continue
      for (const row of unansweredFromMissingFields(thread, mechanisms)) {
        const key = `${row.investigation_thread_id}:${row.slot}`
        if (seenSlots.has(key)) continue
        seenSlots.add(key)
        unanswered.push(row)
      }
    }
  }
  return {
    kind_distinction: {
      investigation_thread: 'question work unit',
      os_thread: 'CreateThread/APC/TLS/timer execution object in the sample',
    },
    failure_kind_distinction: failureKindDistinction(taskRow, actions),
    unanswered_ten_question_slots: unanswered.slice(0, 32),
    unique_os_thread_starts: uniqueOsThreadStarts(task, threads, mechanisms, evidence),
    decode_consumers: decodeConsumers(threads, mechanisms, evidence),
    s4: threads.map((item) => s4Row(objectValue(item), actions)).slice(0, 32),
    next_bounded_methods: terminal ? [] : nextBoundedMethods(actions, threads),
    do_not_invent_second_report: true,
    ...(terminal ? {
      stop_dispatch: true,
      convergence: 'CONVERGED',
      remainder_unknowns_stay_unknown: true,
      stop_instruction: 'CONVERGED: cite official_report_revision_id and STOP. Do not propose GET_DECOMPILE from these gaps. UNKNOWN slots already in the official revision stay UNKNOWN.',
    } : {}),
  }
}

function attachOfficialRevision(projected: Record<string, unknown>): Record<string, unknown> {
  const report = objectValue(projected.report)
  const hide = report.do_not_cite_prior_revisions === true || report.this_turn_ready === false
  const revision = hide ? undefined : (text(report.authoritative_revision_id) || text(report.revision_id))
  const gaps = objectValue(projected.task_gaps)
  return {
    ...projected,
    task_gaps: {
      ...gaps,
      official_report_revision_id: revision,
      chat_must_cite_this_revision: Boolean(revision),
      do_not_invent_second_report: true,
    },
  }
}

function modelFacingContext(projected: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: projected.schema_version,
    session_id: projected.session_id,
    state: projected.state,
    context_status: projected.context_status,
    active_task_id: projected.active_task_id,
    investigation_protocol: projected.investigation_protocol,
    task: projected.task,
    artifacts: projected.artifacts,
    task_gaps: projected.task_gaps,
    investigation_frontier: projected.investigation_frontier,
    analysis_planner: projected.analysis_planner,
    report: projected.report,
  }
}

/**
 * Keep the model-facing packet small and semantic. Raw evidence values are
 * intentionally omitted; the model must use the session-bound evidence tool
 * when it needs a source row. Every value remains explicitly untrusted.
 */
export function projectInvestigationContext(task: Record<string, unknown>, sessionId = ''): Record<string, unknown> {
  const taskRow = objectValue(task.task)
  const artifacts = Array.isArray(task.artifacts) ? task.artifacts : []
  const threads = Array.isArray(task.threads) ? task.threads : []
  const hypotheses = Array.isArray(task.hypotheses) ? task.hypotheses : []
  const actions = plannerVisibleActions(Array.isArray(task.actions) ? task.actions : [])
  const mechanisms = Array.isArray(task.mechanisms) ? task.mechanisms : []
  const evidence = Array.isArray(task.evidence) ? task.evidence : []
  const report = objectValue(task.report)
  const frontier: Record<string, unknown> = {
    open_questions: [],
    missing_evidence: [],
    recent_actions: actions.slice(-16).map((item) => compactRow(item, [
      'id', 'action_type', 'target_artifact_id', 'target_selector', 'status',
      'result_status', 'reason', 'evidence_ids', 'new_evidence_ids', 'planner_turn_id',
    ])),
    deferred: [],
  }
  const openQuestions = frontier.open_questions as unknown[]
  const missingEvidence = frontier.missing_evidence as unknown[]
  const closedThreadStates = new Set([
    'CLOSED', 'CLAIM_READY', 'MECHANISM_READY', 'CANDIDATE', 'UNKNOWN',
    'REJECTED', 'CONTRADICTED', 'VERIFIED', 'SUPPORTED', 'CONFIRMED',
    'PARTIAL', 'UNSUPPORTED', 'STATIC_BOUNDARY',
  ])
  for (const item of threads.slice(-MAX_ITEMS)) {
    const row = objectValue(item)
    const state = text(row.state)
    const question = text(row.question)
    if (question && !closedThreadStates.has(state || '')) openQuestions.push({
      thread_id: text(row.id), question, state,
      evidence_ids: ids(row.evidence_ids),
    })
  }
  for (const item of mechanisms.slice(-MAX_ITEMS)) {
    const row = objectValue(item)
    if (RECORDED_REMAINDER_STATES.has(upper(row.status))) continue
    const missing = Array.isArray(row.missing_fields)
      ? row.missing_fields.map((value) => text(value)).filter(Boolean)
      : Array.isArray(row.unknowns) ? row.unknowns.map((value) => text(value)).filter(Boolean) : []
    if (missing.length) {
      missingEvidence.push({
        mechanism_id: text(row.mechanism_id) || text(row.id),
        type: text(row.type) || text(row.category),
        status: text(row.status),
        missing_fields: missing.slice(0, 16),
        evidence_ids: ids(row.evidence_ids),
      })
    }
  }
  const strategy = objectValue(taskRow.strategy_snapshot)
  const investigation = objectValue(strategy.investigation)
  const deferred = Array.isArray(investigation.deferred_frontier) ? investigation.deferred_frontier : []
  const closedDeferredReasons = new Set([
    'INVESTIGATION_BUDGET_EXHAUSTED', 'INVESTIGATION_ROUND_LIMIT', 'TIMEBOX',
  ])
  frontier.deferred = deferred.filter((item) => {
    const row = objectValue(item)
    const action = (text(row.action_type) || '').toUpperCase()
    const reason = (text(row.reason) || '').toUpperCase()
    if (action === 'CONTROLLED_EMULATE') return false
    if (closedDeferredReasons.has(reason)) return false
    return true
  }).slice(0, MAX_ITEMS).map((item) => compactRow(item, [
    'artifact_id', 'question', 'reason', 'missing_evidence', 'action_type', 'target_selector',
  ]))
  frontier.open_questions = openQuestions.slice(0, MAX_ITEMS)
  frontier.missing_evidence = missingEvidence.slice(0, MAX_ITEMS)

    const plannerSource = objectValue(task.analysis_planner)
    const planner = Object.keys(plannerSource).length
      ? plannerSource
      : objectValue(taskRow.analysis_planner)
    return attachOfficialRevision({
    schema_version: 2,
    session_id: sessionId || undefined,
    task: compactRow(taskRow, [
      'id', 'case_id', 'case_title', 'lifecycle', 'outcome', 'analysis_class',
      'target_granularity', 'actual_granularity', 'limitations', 'elapsed_ms',
      'latest_report_revision_id', 'authoritative_report_revision_id', 'started_at', 'finished_at',
      'failure', 'model_status',
    ]),
    artifacts: artifacts.slice(0, MAX_ITEMS).map((item) => compactRow(item, [
      'id', 'logical_path', 'sha256', 'detected_type', 'role', 'parent_artifact_id',
    ])),
    threads: threads.slice(-MAX_ITEMS).map((item) => compactRow(item, [
      'id', 'artifact_id', 'state', 'question', 'seed_kind', 'evidence_ids',
      'hypothesis_ids', 'action_ids', 'transition_count', 'protocol', 's_ladder',
    ])),
    hypotheses: hypotheses.slice(-MAX_ITEMS).map((item) => compactRow(item, [
      'id', 'thread_id', 'statement', 'dimension', 'status', 'confidence',
      'evidence_ids', 'required_evidence',
    ])),
    actions: actions.slice(-MAX_ITEMS).map((item) => compactRow(item, [
      'id', 'action_type', 'target_artifact_id', 'target_selector', 'status',
      'result_status', 'reason', 'evidence_ids', 'new_evidence_ids', 'planner_turn_id',
    ])),
    mechanisms: mechanisms.slice(-MAX_ITEMS).map((item) => compactRow(item, [
      'id', 'mechanism_id', 'type', 'category', 'status', 'confidence',
      'what', 'how', 'target', 'condition', 'output', 'consumer',
      'missing_fields', 'unknowns', 'evidence_ids', 'claim_ids',
    ])),
    evidence_index: evidence.slice(-MAX_ITEMS).map((item) => compactRow(item, [
      'id', 'artifact_id', 'module', 'kind', 'nature', 'anchor',
    ])),
    // The versioned first-request instruction (B04/M03). It is the same
    // protocol threat_workbench_model_complete sends as its system message, so
    // the conversation driver and the backend planner work from one version.
    investigation_protocol: firstRequestProtocolPacket(),
    investigation_frontier: frontier,
    analysis_planner: compactRow(planner, [
        'role', 'source', 'distinct_from_dsh_chat', 'dsh_chat_note', 'enabled',
        'user_action', 'last_status', 'http_status', 'configured', 'kind',
      ]),
    report: inFlightReport(taskRow, report),
    task_gaps: buildTaskGapPacket(task),
  })
}

const MAX_CONTEXT_CHARS = 24_000
// Keys whose arrays carry the instruction itself and must never be trimmed.
const UNCAPPED_CONTEXT_KEYS = new Set(['investigation_protocol', 'failure_kind_distinction', 'kind_distinction', 'model_failure'])

/**
 * Cap every array in the packet, newest-last (the projections slice from the
 * tail, so the most recent rows survive), and count what was dropped.
 */
function capContextArrays(value: unknown, cap: number, omitted: Record<string, number>, key = ''): unknown {
  if (Array.isArray(value)) {
    const kept = value.length > cap ? value.slice(value.length - cap) : value
    if (value.length > cap) omitted[key] = (omitted[key] || 0) + (value.length - cap)
    return kept.map((item) => capContextArrays(item, cap, omitted, key))
  }
  if (value && typeof value === 'object') {
    const source = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const [name, item] of Object.entries(source)) {
      out[name] = UNCAPPED_CONTEXT_KEYS.has(name) ? item : capContextArrays(item, cap, omitted, name)
    }
    return out
  }
  return value
}

function wrapContext(json: string): string {
  return `<threat_analysis_context untrusted="true">${json}</threat_analysis_context>`
}

/**
 * Render the model-facing packet inside its bound WITHOUT cutting bytes.
 *
 * MEASURED: `boundedText(json, 24_000)` on a large task produced a truncated
 * object -- invalid JSON the model cannot parse, with the ten-question gap set
 * and the versioned protocol sliced off the end. A packet that does not parse is
 * worse than a smaller packet that does, so an oversized packet is now degraded
 * semantically: array tails are capped, the protocol and the failure
 * distinction are never trimmed, and `context_budget` records exactly what was
 * dropped.
 */
function renderContext(value: Record<string, unknown>): string {
  // Compact gaps plus frontier/report only. Raw ledgers stay on the tools.
  const facing = modelFacingContext(value)
  const full = JSON.stringify(facing)
  if (full.length <= MAX_CONTEXT_CHARS) return wrapContext(full)
  const fullChars = full.length
  const budget = (cap: number, omitted: Record<string, number>): Record<string, unknown> => ({
    max_chars: MAX_CONTEXT_CHARS,
    full_chars: fullChars,
    degraded: true,
    array_cap: cap,
    omitted_counts: omitted,
    note: 'The packet exceeded its bound and was reduced by capping array tails; the versioned investigation_protocol and the failure classification are never trimmed. Re-read the specific rows with the session-bound tools.',
  })
  for (const cap of [24, 8, 4, 2, 0]) {
    const omitted: Record<string, number> = {}
    const degraded = { ...capContextArrays(facing, cap, omitted) as Record<string, unknown>, context_budget: budget(cap, omitted) }
    const json = JSON.stringify(degraded)
    if (json.length <= MAX_CONTEXT_CHARS) return wrapContext(json)
  }
  // Last resort: keep only what the investigation protocol needs to be usable.
  const omitted: Record<string, number> = {}
  const minimal = {
    schema_version: facing.schema_version,
    session_id: facing.session_id,
    state: facing.state,
    context_status: facing.context_status,
    active_task_id: facing.active_task_id,
    investigation_protocol: facing.investigation_protocol,
    task: capContextArrays(facing.task, 0, omitted),
    task_gaps: {
      kind_distinction: (facing.task_gaps as Record<string, unknown>)?.kind_distinction,
      failure_kind_distinction: (facing.task_gaps as Record<string, unknown>)?.failure_kind_distinction,
      official_report_revision_id: (facing.task_gaps as Record<string, unknown>)?.official_report_revision_id,
      do_not_invent_second_report: true,
    },
    investigation_frontier: capContextArrays(facing.investigation_frontier, 0, omitted),
    report: facing.report,
    context_budget: budget(0, omitted),
  }
  const json = JSON.stringify(minimal)
  if (json.length <= MAX_CONTEXT_CHARS) return wrapContext(json)
  return wrapContext(JSON.stringify({
    schema_version: facing.schema_version,
    session_id: facing.session_id,
    state: facing.state,
    investigation_protocol: facing.investigation_protocol,
    context_budget: { ...budget(0, omitted), note: 'the task projection itself exceeded the bound; read it with threat_get_session_analysis_context' },
  }))
}

/**
 * Mount the actual Cordis prompt hook. The context is refreshed from durable
 * session events and projected synchronously on every model assembly; this
 * keeps the request cache-safe while still making the latest frontier visible.
 */
export function apply(ctx: Context, config: ContextProviderConfig = {}): void {
  const env = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process?.env
  const client = new ThreatApiClient({
    baseUrl: config.backendUrl || env?.THREAT_BACKEND_URL || 'http://127.0.0.1:8000',
    token: config.token || env?.THREAT_BACKEND_TOKEN,
  })
  const cache = new Map<string, CachedContext>()
  const pending = new Map<string, Promise<void>>()

  const refresh = (sessionId: string): Promise<void> => {
    const id = sessionId.trim()
    if (!id) return Promise.resolve()
    const existing = pending.get(id)
    if (existing) return existing
    const request = (async () => {
      try {
        const session = await client.sessionContext(id)
        const activeTaskId = text(session.active_task_id, 200)
        if (!activeTaskId) {
          cache.set(id, { fetchedAt: Date.now(), sessionId: id, context: {
            schema_version: 2, session_id: id, state: text(session.state) || 'UNBOUND',
            // The first-request protocol must survive the unbound state: the
            // user's first message is exactly the turn that has no task yet.
            investigation_protocol: firstRequestProtocolPacket(),
            task: {}, investigation_frontier: { open_questions: [], missing_evidence: [], recent_actions: [], deferred: [] },
            analysis_planner: compactRow(objectValue(session.analysis_planner), [
              'role', 'source', 'distinct_from_dsh_chat', 'dsh_chat_note', 'enabled',
              'user_action', 'last_status', 'http_status', 'configured', 'kind',
            ]),
            report: { revision_id: undefined, available: false },
            task_gaps: { do_not_invent_second_report: true, official_report_revision_id: undefined },
          } })
          return
        }
        const built = await buildContext(client, activeTaskId, 'session-analysis', {
          sessionId: id,
          analysisPlanner: session.analysis_planner,
        })
        cache.set(id, { fetchedAt: Date.now(), sessionId: id, context: {
          ...built.context,
          state: text(session.state),
          active_task_id: activeTaskId,
        } })
      } catch {
        // Keep the model request usable while making the missing server
        // context explicit. This is a transport limitation, not a static
        // analysis boundary and must never be rendered as one.
        cache.set(id, { fetchedAt: Date.now(), sessionId: id, context: {
          schema_version: 2, session_id: id, state: 'BACKEND_UNAVAILABLE',
          context_status: 'BACKEND_UNAVAILABLE',
          investigation_protocol: firstRequestProtocolPacket(),
          investigation_frontier: { open_questions: [], missing_evidence: [], recent_actions: [], deferred: [] },
          report: { revision_id: undefined, available: false },
        } })
      } finally {
        pending.delete(id)
      }
    })()
    pending.set(id, request)
    return request
  }

  ctx.inject(['systemPrompt'], (scope: Context) => {
    scope.systemPrompt.context({
      name: 'threat:analysis-context',
      order: 125,
      text: (rawAssembly: unknown) => {
        const id = sessionIdOf(rawAssembly as PromptAssemblyContext)
        if (!id) return '<threat_analysis_context state="UNBOUND" />'
        const current = cache.get(id)
        if (!current || Date.now() - current.fetchedAt > CACHE_TTL_MS) void refresh(id)
        if (!current) return `<threat_analysis_context state="LOADING" session_id="${id}" />`
        return renderContext(current.context)
      },
    })
  })
  // DSH assembles prompt contexts synchronously, but exposes an async
  // waterfall immediately before the model call. Refresh there so the first
  // analysis request receives the durable task/frontier packet instead of a
  // speculative LOADING placeholder. The static provider above remains a
  // compatibility fallback for hosts that do not expose the waterfall.
  if (typeof (ctx as unknown as { on?: unknown }).on === 'function') {
    ;(ctx as unknown as {
      on: (name: string, listener: (
        assembly: PromptAssemblyLike,
        context: PromptAssemblyListenerContext,
        next: () => Promise<PromptAssemblyLike>,
      ) => Promise<PromptAssemblyLike>, options?: Record<string, unknown>) => unknown
    }).on('system-prompt/assemble', async (assembly, rawAssembly, next) => {
      const id = sessionIdOf(rawAssembly as PromptAssemblyContext)
      if (!id) return next()
      const question = userQuestionOf(assembly, rawAssembly)
      if (isAnalysisIntent(question)) {
        try {
          await client.dispatchAnalysisIntent(id, question)
        } catch {
          // Keep the model request usable. Mechanical start is an
          // acceleration; the model can still call threat_start_static_analysis.
        }
      }
      await refresh(id)
      const current = cache.get(id)
      if (current) {
        const rendered = renderContext(current.context)
        const existing = assembly.contexts.filter((item) => item.name !== 'threat:analysis-context')
        assembly.contexts = [...existing, { name: 'threat:analysis-context', text: rendered }]
      }
      return next()
    }, { prepend: true })
  }
  // Session events are the invalidation signal. No interval polling is used;
  // each event schedules at most one bounded refresh per session. Human
  // analysis intent is dispatched here so a 402 on the first model call
  // cannot prevent import+start: DSH publishes user/message before assemble.
  if (typeof (ctx as unknown as { on?: unknown }).on === 'function') {
    ;(ctx as unknown as {
      on: (name: string, listener: (session: SessionLike, event?: SessionEventLike) => void) => unknown
    }).on(
      'session/event', (session, event) => {
        const id = sessionIdOf({ agent: { session } })
        if (!id) return
        const question = userQuestionFromEvent(event)
        if (isAnalysisIntent(question)) {
          void client.dispatchAnalysisIntent(id, question).catch(() => {
            // Same fallback as assemble: the model can still start analysis.
          })
        }
        void refresh(id)
      },
    )
  }
}

export interface ThreatContext { readonly task_id: string; readonly question: string; readonly context: Record<string, unknown> }

export async function buildContext(
  client: ThreatApiClient,
  taskId: string,
  question: string,
  options: { sessionId?: string; analysisPlanner?: unknown } = {},
): Promise<ThreatContext> {
  const task = await client.task(taskId, options.sessionId)
  let context = projectInvestigationContext({
    ...objectValue(task),
    analysis_planner: options.analysisPlanner ?? objectValue(task).analysis_planner,
  }, options.sessionId || '')
  const lifecycle = text(objectValue(context.task).lifecycle)
  if (!IN_FLIGHT_LIFECYCLES.has(lifecycle || '')) {
    try {
      context = overlayAuthoritativeGetReport(context, await client.report(taskId, options.sessionId))
    } catch {
      // Same GET overlay as the prompt hook; missing report is not a
      // fabricated revision.
    }
  }
  const evidenceIndex = Array.isArray(context.evidence_index) ? context.evidence_index : []
  return {
    task_id: taskId,
    question: boundedText(question, 1000),
    context: {
      ...context,
      evidence_ids: ids(evidenceIndex.map((row) => objectValue(row).id)),
    },
  }
}
