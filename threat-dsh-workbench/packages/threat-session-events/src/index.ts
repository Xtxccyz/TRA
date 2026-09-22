import type { Context } from '@deepseek-ai/cordis'
import { KNOWN_SESSION_EVENT_TYPES, type Session } from '@deepseek-ai/dsh-session'
import { ThreatApiClient, type EventPage } from '@threat-dsh/api-client'
import { boundedIds, boundedText, type ThreatPluginManifest, type ThreatSessionEvent } from '@threat-dsh/plugin-sdk'

export const name = 'threat-session-events'
export const inject = ['sessions']
export const manifest: ThreatPluginManifest = {
  id: 'threat-session-events', version: '1.0.0', plugin_api: 1,
  capabilities: ['event-projector'], required_backend_api: '>=1,<2', required_event_schema: 1,
  security_profile: ['threat-static'],
}

const BACKEND_EVENT_TYPES: Readonly<Record<string, string>> = Object.freeze({
  'artifact.registered': 'artifact-attached',
  'artifact.selected': 'artifact-selected',
  'workbench.analysis_started': 'analysis-started',
  'workbench.analysis_queued': 'analysis-queued',
  'workbench.analysis_running': 'analysis-running',
  'workbench.analysis_completed': 'analysis-completed',
  'workbench.analysis_failed': 'analysis-failed',
  'workbench.analysis_cancelled': 'analysis-cancelled',
  'orchestration.plan_created': 'plan-created',
  'orchestration.plan_proposed': 'model-action-proposed',
  'orchestration.action_dequeued': 'action-dequeued',
  'policy.action_decision': 'action-decision',
  'agent.run.started': 'agent-run-started',
  'agent.context.checked': 'context-checked',
  'agent.run.completed': 'agent-run-completed',
  'model_call.completed': 'model-call-completed',
  'investigation.thread_seeded': 'thread-created',
  'investigation.thread_completed': 'thread-completed',
  'investigation.claim_gate_unknown': 'claim-gate-unknown',
  'investigation.claim_gate_supported': 'claim-gate-supported',
  'investigation.questions_recompiled': 'questions-recompiled',
  'investigation.action_no_new_evidence': 'action-no-new-evidence',
  'tool_run.started': 'tool-run-started',
  'tool_run.completed': 'tool-run-completed',
  'evidence.recorded': 'evidence-added',
  'evidence.delivery_traced': 'evidence-delivered',
  'claim.created': 'claim-created',
  'claim.rejected': 'claim-rejected',
  'mechanism.created': 'mechanism-candidate-created',
  'mechanism.verified': 'mechanism-verified',
  'mechanism.rejected': 'mechanism-rejected',
  'report.started': 'report-started',
  'report.ready': 'report-ready',
  'methodology.profile_generated': 'methodology-profile-generated',
  'report.generated': 'report-ready',
  'analysis_task.succeeded': 'analysis-completed',
  'analysis_task.failed': 'analysis-failed',
  'analysis_task.cancelled': 'analysis-cancelled',
})

const LEGACY_EVENT_TYPES = new Set([
  'case-linked', 'task-started', 'task-status', 'thread-created', 'thread-updated',
  'hypothesis-created', 'hypothesis-updated', 'action-proposed', 'action-started',
  'action-completed', 'action-rejected', 'evidence-summary', 'mechanism-created',
  'mechanism-verified', 'mechanism-rejected', 'claim-created', 'claim-rejected',
  'relation-created', 'sample-timeline-updated', 'report-started', 'report-ready',
  'task-completed', 'plugin-test',
])

const THREAT_SESSION_EVENT_TYPES = new Set([
  ...Object.values(BACKEND_EVENT_TYPES),
  ...LEGACY_EVENT_TYPES,
])

/**
 * Register this plugin's closed event vocabulary with the DSH persistence
 * reader. DSH intentionally rejects unknown non-ignorable events on cold
 * restore; adding only these fixed `threat/*` names keeps that invariant while
 * allowing the out-of-tree product event stream to survive a restart.
 */
export function registerThreatSessionEventTypes(): void {
  const known = KNOWN_SESSION_EVENT_TYPES as Set<string>
  for (const type of THREAT_SESSION_EVENT_TYPES) known.add(`threat/${type}`)
}

registerThreatSessionEventTypes()

const SAFE_PAYLOAD_FIELDS = [
  'reason', 'tool_name', 'action_type', 'phase', 'module', 'status', 'state',
  'gate_status', 'hypothesis_status', 'scheduler', 'thread_id', 'model',
  'provider', 'error_type', 'allowed', 'priority', 'action_count',
  'rejected_action_count', 'missing', 'contradictions',
] as const

function safePayloadSummary(payload: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const key of SAFE_PAYLOAD_FIELDS) {
    const value = payload[key]
    if (typeof value === 'string') result[key] = boundedText(value, 300)
    else if (typeof value === 'boolean') result[key] = value
    else if (typeof value === 'number' && Number.isSafeInteger(value)) result[key] = value
    else if (key === 'missing' || key === 'contradictions') result[key] = boundedIds(value, 16)
  }
  return result
}

export function projectBackendEvent(event: Record<string, unknown>): ThreatSessionEvent | undefined {
  const source = boundedText(event.type, 120)
  if (!source) return undefined
  const suffix = source.startsWith('investigation.') ? source.slice('investigation.'.length) : source
  const normalized = BACKEND_EVENT_TYPES[source] ?? (LEGACY_EVENT_TYPES.has(suffix) ? suffix : 'task-status')
  const payload = event.payload_summary && typeof event.payload_summary === 'object' ? event.payload_summary as Record<string, unknown> : {}
  const data: Record<string, unknown> = {
    seq: Number(event.seq ?? 0),
    task_id: boundedText(event.task_id, 80),
    entity_id: boundedText(event.entity_id, 120),
    source_type: source,
    status: boundedText(payload.status, 80),
    state: boundedText(payload.state, 80),
    evidence_ids: boundedIds(payload.evidence_ids),
  }
  Object.assign(data, safePayloadSummary(payload))
  if (typeof payload.evidence_count === 'number') data.evidence_count = payload.evidence_count
  return { type: `threat/${normalized}`, data }
}

export interface SessionEventAppender { append(type: string, data: Record<string, unknown>): unknown }

/** Durable cursor contract. DSH owns the actual Session persistence; the
 * bridge only stores the last backend sequence that was successfully appended.
 */
export interface EventCursorStore {
  load(): number | Promise<number>
  save(sequence: number): void | Promise<void>
}

export interface ThreatSessionEventBridgeOptions {
  readonly initialSeq?: number
  readonly cursorStore?: EventCursorStore
  /** Optional DSH session identity used to enforce server-side scoping. */
  readonly sessionId?: string
  /** Stop appending when the owning Session has been disposed or detached. */
  readonly isActive?: () => boolean
}

/**
 * Pulls the monotonic backend stream into a DSH Session.  The cursor is only
 * advanced after an event is appended, so a failed append can be retried
 * without silently losing a domain event.
 */
export class ThreatSessionEventBridge {
  private cursor: number
  private readonly cursorStore?: EventCursorStore
  private readonly sessionId?: string
  private readonly isActive?: () => boolean
  constructor(
    private readonly client: ThreatApiClient,
    private readonly session: SessionEventAppender,
    options: ThreatSessionEventBridgeOptions = {},
  ) {
    if (options.initialSeq !== undefined && (!Number.isSafeInteger(options.initialSeq) || options.initialSeq < 0)) {
      throw new Error('initialSeq must be a non-negative safe integer')
    }
    this.cursor = options.initialSeq ?? 0
    this.cursorStore = options.cursorStore
    this.sessionId = options.sessionId?.trim() || undefined
    this.isActive = options.isActive
  }
  get afterSeq(): number { return this.cursor }
  async restoreCursor(): Promise<number> {
    if (!this.cursorStore) return this.cursor
    const restored = await this.cursorStore.load()
    if (!Number.isSafeInteger(restored) || restored < 0) throw new Error('persisted event cursor is invalid')
    this.cursor = Math.max(this.cursor, restored)
    return this.cursor
  }
  async sync(taskId: string, limit = 500): Promise<{ appended: number; nextSeq: number }> {
    if (this.isActive && !this.isActive()) return { appended: 0, nextSeq: this.cursor }
    const page: EventPage = await this.client.events(taskId, this.cursor, limit, this.sessionId)
    const reportedNext = Number(page.next_seq)
    if (!Number.isSafeInteger(reportedNext) || reportedNext < this.cursor) {
      throw new Error(`backend next_seq is invalid: ${String(page.next_seq)}`)
    }
    if (page.events.length === 0 && reportedNext !== this.cursor) {
      throw new Error(`empty page advanced backend cursor: expected ${this.cursor}, got ${reportedNext}`)
    }
    let appended = 0
    for (const event of page.events) {
      if (this.isActive && !this.isActive()) return { appended, nextSeq: this.cursor }
      const seq = Number(event.seq ?? 0)
      if (!Number.isSafeInteger(seq) || seq <= this.cursor) continue
      if (seq !== this.cursor + 1) throw new Error(`backend event gap: expected ${this.cursor + 1}, got ${seq}`)
      const projected = projectBackendEvent(event)
      // A malformed/unknown event still consumes its backend sequence. The
      // projection function intentionally returns undefined for empty types;
      // skipping the cursor would make every later valid event look like a gap.
      if (projected) {
        this.session.append(projected.type, { ...projected.data, backend_seq: seq })
        appended += 1
      }
      this.cursor = seq
      if (this.cursorStore) await this.cursorStore.save(this.cursor)
    }
    if (reportedNext < this.cursor) {
      throw new Error(`backend next_seq moved backwards: ${reportedNext}`)
    }
    // A non-empty page must report the last sequence it returned. If it
    // reports a later value, the next page would silently skip events.
    const lastReturned = page.events.reduce((last, event) => {
      const seq = Number(event.seq ?? 0)
      return Number.isSafeInteger(seq) && seq > last ? seq : last
    }, this.cursor)
    if (page.events.length > 0 && reportedNext !== lastReturned) {
      throw new Error(`backend next_seq does not match page: expected ${lastReturned}, got ${reportedNext}`)
    }
    return { appended, nextSeq: this.cursor }
  }
}

interface HostSession {
  readonly id: string
  readonly events?: readonly Record<string, unknown>[]
  append(type: string, data: Record<string, unknown>): unknown
}

interface HostContext {
  readonly sessions: { list(): HostSession[] }
  on(name: string, listener: (...args: any[]) => unknown, options?: { global?: boolean }): () => void
  effect?(factory: () => (() => void), label?: string): unknown
}

interface CoordinatorRecord {
  readonly session: HostSession
  readonly bridges: Map<string, ThreatSessionEventBridge>
  taskId: string
  cursor: number
  waiter?: AbortController
  inFlight: boolean
}

export interface ThreatSessionEventCoordinatorOptions {
  readonly backendUrl?: string
  readonly token?: string
  /** @deprecated retained for source compatibility; event wait controls pacing. */
  readonly intervalMs?: number
  readonly client?: ThreatApiClient
  readonly logger?: Pick<Console, 'warn'>
}

function persistedBackendCursor(session: HostSession, taskId: string): number {
  let cursor = 0
  for (const event of session.events ?? []) {
    const data = event.data && typeof event.data === 'object' ? event.data as Record<string, unknown> : {}
    if (boundedText(data.task_id, 80) !== taskId) continue
    const sequence = Number(data.backend_seq ?? 0)
    if (Number.isSafeInteger(sequence) && sequence > cursor) cursor = sequence
  }
  return cursor
}

/**
 * Production host adapter for the backend event stream.
 *
 * DSH owns the durable Session log; this coordinator only reads the
 * server-authoritative context/events APIs and appends projected, bounded
 * `threat/*` events to that log. Every timer and listener is tied to the host
 * context, and a task cursor is reconstructed from the persisted Session on
 * restart so a browser refresh cannot duplicate backend events.
 */
export class ThreatSessionEventCoordinator {
  private readonly records = new Map<string, CoordinatorRecord>()
  private readonly logger: Pick<Console, 'warn'>
  private disposed = false
  readonly client: ThreatApiClient

  constructor(private readonly ctx: HostContext, options: ThreatSessionEventCoordinatorOptions = {}) {
    this.logger = options.logger ?? console
    const runtimeEnv = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process?.env
    this.client = options.client ?? new ThreatApiClient({
      baseUrl: options.backendUrl ?? runtimeEnv?.THREAT_BACKEND_URL ?? 'http://127.0.0.1:8000',
      token: options.token ?? runtimeEnv?.THREAT_BACKEND_TOKEN,
    })
  }

  attach(session: HostSession): void {
    if (this.disposed || !session?.id || this.records.has(session.id)) return
    for (const id of [...this.records.keys()]) this.detach(id)
    const record: CoordinatorRecord = { session, bridges: new Map(), taskId: '', cursor: 0, inFlight: false }
    this.records.set(session.id, record)
    // One cancellable server-side wait owns the lifecycle. There is no host
    // timer: the backend returns only on an event, a state change, or timeout.
    void this.watch(record)
  }

  detach(session: HostSession | string): void {
    const id = typeof session === 'string' ? session : session.id
    const record = this.records.get(id)
    if (!record) return
    record.waiter?.abort()
    this.records.delete(id)
  }

  private async watch(record: CoordinatorRecord): Promise<void> {
    if (this.disposed || this.records.get(record.session.id) !== record) return
    record.inFlight = true
    const waiter = new AbortController()
    record.waiter = waiter
    try {
      while (!waiter.signal.aborted && !this.disposed && this.records.get(record.session.id) === record) {
        const context = await this.client.sessionContext(record.session.id)
        const taskId = typeof context.active_task_id === 'string' ? context.active_task_id.trim() : ''
        if (taskId !== record.taskId) {
          record.taskId = taskId
          record.cursor = taskId ? persistedBackendCursor(record.session, taskId) : 0
        }
        const value = await this.client.waitForAnalysisUpdate(record.session.id, record.cursor, 120)
        if (waiter.signal.aborted || this.records.get(record.session.id) !== record) return
        const returnedContext = value.context && typeof value.context === 'object'
          ? value.context as Record<string, unknown>
          : context
        const returnedTask = typeof returnedContext.active_task_id === 'string' ? returnedContext.active_task_id.trim() : ''
        if (returnedTask !== record.taskId) {
          // Session rebinding is authoritative. Rebase the cursor to the new
          // task before consuming any events from it.
          record.taskId = returnedTask
          record.cursor = returnedTask ? persistedBackendCursor(record.session, returnedTask) : 0
          continue
        }
        const events = Array.isArray(value.events) ? value.events : []
        for (const event of events) {
          const seq = Number(event?.seq ?? 0)
          if (!Number.isSafeInteger(seq) || seq <= record.cursor) continue
          if (seq !== record.cursor + 1) throw new Error(`backend event gap: expected ${record.cursor + 1}, got ${seq}`)
          const projected = projectBackendEvent(event)
          if (projected) record.session.append(projected.type, { ...projected.data, backend_seq: seq })
          record.cursor = seq
        }
        // A timeout with no event is expected. The next iteration issues a
        // fresh bounded wait, never a client-side interval or busy poll.
      }
    } catch (error) {
      if (!waiter.signal.aborted) {
        this.logger.warn(`[threat-session-events] wait failed for ${record.session.id}: ${error instanceof Error ? error.message : String(error)}`)
        // Back off once before re-entering the same bounded wait. This path is
        // only for transport failures and cannot fabricate domain events.
        await new Promise<void>((resolve) => setTimeout(resolve, 1_000))
        if (!waiter.signal.aborted && this.records.get(record.session.id) === record) void this.watch(record)
      }
    } finally {
      if (record.waiter === waiter) record.waiter = undefined
      record.inFlight = false
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    for (const record of this.records.values()) record.waiter?.abort()
    this.records.clear()
  }
}

/** Coalesce a restore burst of `session/created` onto one live waiter. */
const ATTACH_DEBOUNCE_MS = 50

/** Register the coordinator in the real DSH host lifecycle. */
export function installThreatSessionEventCoordinator(
  ctx: Context | HostContext,
  options: ThreatSessionEventCoordinatorOptions = {},
): ThreatSessionEventCoordinator {
  const host = ctx as unknown as HostContext
  const coordinator = new ThreatSessionEventCoordinator(host, options)
  let pending: HostSession | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  const flushAttach = () => {
    timer = undefined
    const session = pending
    pending = undefined
    if (session) coordinator.attach(session)
  }
  const queueAttach = (session: HostSession) => {
    pending = session
    if (timer !== undefined) return
    timer = setTimeout(flushAttach, ATTACH_DEBOUNCE_MS)
  }
  // Do not sweep host.sessions.list(). Restored history must stay listable
  // without one long-poll per session; that storm stalls sidebar hydration.
  const offCreated = host.on('session/created', queueAttach, { global: true })
  const offDisposed = host.on('session/disposed', (session: HostSession) => {
    if (pending?.id === session.id) pending = undefined
    coordinator.detach(session)
  }, { global: true })
  const dispose = () => {
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
    pending = undefined
    offCreated?.(); offDisposed?.(); coordinator.dispose()
  }
  if (typeof host.effect === 'function') host.effect(() => dispose, 'threat-session-events')
  return coordinator
}

export function apply(ctx: Context): void {
  installThreatSessionEventCoordinator(ctx)
}

export { findReusableBlankSession, installThreatSessionReuseGuard, terminalContextStates } from './session-scope.ts'
export type { Session }
