import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import vm from 'node:vm'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

function createHarness() {
  const calls = []
  const intervalHandlers = []
  const storage = new Map()
  const localStorage = {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: (key) => storage.delete(key),
  }
  const window = {
    localStorage,
    __ModuleLoader__: { load: ({ factory }) => factory() },
    setInterval: (handler) => { intervalHandlers.push(handler); return intervalHandlers.length },
    clearInterval: () => {},
    __THREAT_BACKEND_URL__: 'http://backend',
  }
  const fetch = (url, init = {}) => new Promise((resolve, reject) => {
    calls.push({ url, init, resolve, reject })
  })
  const context = vm.createContext({ window, fetch, AbortController, URLSearchParams, setTimeout, clearTimeout })
  return {
    calls,
    intervalHandlers,
    window,
    async load() {
      const source = await readFile(resolve(root, 'packages/threat-context-store/client.js'), 'utf8')
      vm.runInContext(source, context, { filename: 'threat-context-store/client.js' })
      return window.__THREAT_ANALYSIS_CONTEXT_STORE__
    },
    respond(index, body) {
      calls[index].resolve({ ok: true, json: async () => body })
    },
  }
}

test('context refresh discards a slow response from the previous session', async () => {
  const harness = createHarness()
  const store = await harness.load()
  const first = store.refresh('session-a')
  assert.equal(harness.calls.length, 1)
  const second = store.refresh('session-b')
  assert.equal(harness.calls.length, 2)
  harness.respond(1, { session_id: 'session-b', state: 'UNBOUND', active_task_id: null })
  await second
  harness.respond(0, { session_id: 'session-a', state: 'ANALYSIS_READY', active_task_id: 'task-a' })
  await first
  assert.equal(store.snapshot().sessionId, 'session-b')
  assert.equal(store.snapshot().context.active_task_id, null)
  assert.equal(store.snapshot().context.state, 'UNBOUND')
})

test('task resource response is discarded after a context revision changes', async () => {
  const harness = createHarness()
  const store = await harness.load()
  const contextRequest = store.refresh('session-a')
  harness.respond(0, { session_id: 'session-a', state: 'ANALYSIS_READY', active_task_id: 'task-a' })
  await contextRequest

  const reportRequest = store.request('report', '/api/v1/workbench/tasks/task-a/report')
  assert.equal(harness.calls.length, 2)
  const switchRequest = store.refresh('session-b')
  assert.equal(harness.calls.length, 3)
  harness.respond(2, { session_id: 'session-b', state: 'UNBOUND', active_task_id: null })
  await switchRequest
  harness.respond(1, { task_id: 'task-a', revision: { id: 'old-report' } })
  assert.equal(await reportRequest, null)
  assert.equal(store.snapshot().sessionId, 'session-b')
  assert.equal(store.snapshot().context.active_task_id, null)
})

test('session wait refreshes queued/running context for the shared UI store', async () => {
  const harness = createHarness()
  const store = await harness.load()
  const updates = []
  store.subscribe({ sessionId: 'session-a' }, (next) => updates.push(next.context.state))
  assert.equal(harness.calls.length, 1)
  harness.respond(0, { session_id: 'session-a', state: 'ANALYSIS_RUNNING', active_task_id: 'task-a' })
  await new Promise((resolve) => setTimeout(resolve, 0))
  assert.equal(harness.intervalHandlers.length, 0)
  assert.equal(harness.calls.length, 2)
  harness.respond(1, { session_id: 'session-a', state: 'ANALYSIS_READY', active_task_id: 'task-a' })
  await new Promise((resolve) => setTimeout(resolve, 0))
  assert.equal(store.snapshot().context.state, 'ANALYSIS_READY')
  assert.ok(updates.includes('ANALYSIS_RUNNING'))
  assert.ok(updates.includes('ANALYSIS_READY'))
})
