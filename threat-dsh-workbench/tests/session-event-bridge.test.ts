import assert from 'node:assert/strict'
import test from 'node:test'
import { installThreatSessionEventCoordinator, projectBackendEvent, ThreatSessionEventBridge, type EventCursorStore, type SessionEventAppender } from '../packages/threat-session-events/src/index.ts'

function client(events: readonly Record<string, unknown>[]) {
  return { events: async (_task: string, after: number) => ({ schema_version: 1, task_id: 'task-1', events: events.filter((event) => Number(event.seq) > after), next_seq: Number(events.at(-1)?.seq ?? after), has_more: false }) }
}

test('bridge appends ordered projected events and persists its cursor', async () => {
  const appended: Record<string, unknown>[] = []
  const saved: number[] = []
  const session: SessionEventAppender = { append: (type, data) => appended.push({ type, ...data }) }
  const store: EventCursorStore = { load: () => saved.at(-1) ?? 0, save: (seq) => { saved.push(seq) } }
  const bridge = new ThreatSessionEventBridge(client([
    { seq: 1, type: 'task-started', task_id: 'task-1', payload_summary: { status: 'RUNNING' } },
    { seq: 2, type: 'evidence-summary', task_id: 'task-1', payload_summary: { evidence_count: 3 } },
  ]), session, { cursorStore: store })
  assert.deepEqual(await bridge.sync('task-1'), { appended: 2, nextSeq: 2 })
  assert.deepEqual(appended.map((row) => row.backend_seq), [1, 2])
  assert.deepEqual(saved, [1, 2])
  const restarted = new ThreatSessionEventBridge(client([
    { seq: 1, type: 'task-started', task_id: 'task-1', payload_summary: {} },
    { seq: 2, type: 'evidence-summary', task_id: 'task-1', payload_summary: {} },
    { seq: 3, type: 'task-completed', task_id: 'task-1', payload_summary: { status: 'SUCCEEDED' } },
  ]), session, { cursorStore: store })
  await restarted.restoreCursor()
  assert.deepEqual(await restarted.sync('task-1'), { appended: 1, nextSeq: 3 })
  assert.deepEqual(appended.map((row) => row.backend_seq), [1, 2, 3])
})

test('backend event projection preserves canonical semantics and bounded safe fields', () => {
  const projected = projectBackendEvent({
    seq: 7,
    type: 'orchestration.plan_proposed',
    task_id: 'task-1',
    entity_id: 'task-1',
    payload_summary: { status: 'MODEL_PLAN_APPLIED', phase: 'initial', reason: 'choose static parser', request_body: 'must not cross boundary' },
  })
  assert.deepEqual(projected, {
    type: 'threat/model-action-proposed',
    data: {
      seq: 7,
      task_id: 'task-1',
      entity_id: 'task-1',
      source_type: 'orchestration.plan_proposed',
      status: 'MODEL_PLAN_APPLIED',
      state: '',
      evidence_ids: [],
      phase: 'initial',
      reason: 'choose static parser',
      missing: [],
      contradictions: [],
    },
  })
})

test('bridge rejects a sequence gap and does not advance or append the gapped event', async () => {
  const appended: Record<string, unknown>[] = []
  const bridge = new ThreatSessionEventBridge(client([
    { seq: 1, type: 'task-started', task_id: 'task-1', payload_summary: {} },
    { seq: 3, type: 'task-completed', task_id: 'task-1', payload_summary: {} },
  ]), { append: (_type, data) => appended.push(data) })
  await assert.rejects(() => bridge.sync('task-1'), /backend event gap/)
  assert.equal(bridge.afterSeq, 1)
  assert.deepEqual(appended.map((row) => row.backend_seq), [1])
})

test('bridge rejects a first page that starts after sequence one', async () => {
  const appended: Record<string, unknown>[] = []
  const bridge = new ThreatSessionEventBridge(client([
    { seq: 3, type: 'task-completed', task_id: 'task-1', payload_summary: {} },
  ]), { append: (_type, data) => appended.push(data) })
  await assert.rejects(() => bridge.sync('task-1'), /backend event gap: expected 1, got 3/)
  assert.equal(bridge.afterSeq, 0)
  assert.deepEqual(appended, [])
})

test('bridge rejects a backend page whose next_seq moves backwards', async () => {
  const bridge = new ThreatSessionEventBridge({
    events: async () => ({
      schema_version: 1,
      task_id: 'task-1',
      events: [],
      next_seq: -1,
      has_more: false,
    }),
  }, { append: () => undefined })
  await assert.rejects(() => bridge.sync('task-1'), /backend next_seq is invalid/)
  assert.equal(bridge.afterSeq, 0)
})

test('bridge rejects an empty page that advances the backend cursor', async () => {
  const bridge = new ThreatSessionEventBridge({
    events: async () => ({
      schema_version: 1,
      task_id: 'task-1',
      events: [],
      next_seq: 4,
      has_more: false,
    }),
  }, { append: () => undefined })
  await assert.rejects(() => bridge.sync('task-1'), /empty page advanced backend cursor/)
  assert.equal(bridge.afterSeq, 0)
})

test('bridge consumes malformed events without creating a false gap', async () => {
  const appended: Record<string, unknown>[] = []
  const bridge = new ThreatSessionEventBridge(client([
    { seq: 1, type: '', task_id: 'task-1', payload_summary: {} },
    { seq: 2, type: 'task-completed', task_id: 'task-1', payload_summary: {} },
  ]), { append: (_type, data) => appended.push(data) })
  assert.deepEqual(await bridge.sync('task-1'), { appended: 1, nextSeq: 2 })
  assert.deepEqual(appended.map((row) => row.backend_seq), [2])
})

test('coordinator wires DSH session lifecycle to the server event stream', async () => {
  const created: Array<(session: any) => unknown> = []
  const disposed: Array<(session: any) => unknown> = []
  const ticks: Array<() => void> = []
  const appended: any[] = []
  const session = {
    id: 'session-live',
    events: appended,
    append(type: string, data: Record<string, unknown>) {
      appended.push({ type, seq: appended.length, data })
    },
  }
  const requests: Array<{ task: string; after: number; sessionId?: string }> = []
  let eventDelivered = false
  const coordinator = installThreatSessionEventCoordinator({
    sessions: { list: () => [] },
    on(name: string, listener: (...args: any[]) => unknown) {
      if (name === 'session/created') created.push(listener as (session: any) => unknown)
      if (name === 'session/disposed') disposed.push(listener as (session: any) => unknown)
      return () => undefined
    },
    interval(callback: () => void) { ticks.push(callback); return () => undefined },
  }, {
    intervalMs: 250,
    client: {
      sessionContext: async (id: string) => ({ session_id: id, active_task_id: 'task-live', state: 'ANALYSIS_RUNNING' }),
      events: async (task: string, after: number, _limit: number, sessionId?: string) => {
        requests.push({ task, after, sessionId })
        if (eventDelivered) return { schema_version: 1, task_id: task, events: [], next_seq: after, has_more: false }
        eventDelivered = true
        return { schema_version: 1, task_id: task, events: [{ seq: 1, type: 'task-started', task_id: task, payload_summary: { status: 'RUNNING' } }], next_seq: 1, has_more: false }
      },
    } as any,
    logger: { warn: () => undefined },
  })

  assert.equal(created.length, 1)
  await created[0](session)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(appended.some((event) => event.type === 'threat/task-started'), true)
  assert.deepEqual(requests[0], { task: 'task-live', after: 0, sessionId: 'session-live' })
  assert.equal(ticks.length, 1)

  await disposed[0](session)
  ticks[0]?.()
  assert.equal(requests.length, 1)
  coordinator.dispose()
})
