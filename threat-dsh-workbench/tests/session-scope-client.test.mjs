import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import vm from 'node:vm'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

function createHarness(contextState) {
  const calls = []
  const effects = []
  let started = 0
  const workspaceTarget = {
    list: { getSnapshot: () => ({ items: [{ workspaceId: 'workspace-a', path: 'D:/workspace-a', sessionIds: ['session-history'] }], archivedSessionIds: [], recentWorkspaceId: 'workspace-a' }) },
    startSession() { started += 1 },
  }
  // Match Cordis' traceable service behavior: a plain assignment can be
  // captured by a shadow receiver, while defineProperty must reach the
  // service target used by later UI reads.
  const workspaces = new Proxy(workspaceTarget, { set: () => true })
  const sessions = {
    list: { getSnapshot: () => ({ current: 'session-history', ids: ['session-history'], byId: { 'session-history': { id: 'session-history', blank: true, cwd: 'D:/workspace-a' } } }) },
  }
  const fetch = async (url, init = {}) => {
    calls.push({ url, init })
    if (url.endsWith('/analysis-context')) return { ok: true, json: async () => ({ state: contextState, active_task_id: contextState === 'UNBOUND' ? null : 'task-history' }) }
    if (url.endsWith('/analysis/unbind')) return { ok: true, json: async () => ({ state: 'UNBOUND' }) }
    throw new Error(`unexpected URL ${url}`)
  }
  const window = {
    __ModuleLoader__: { load: ({ factory }) => { window.__plugin = factory() } },
    __THREAT_BACKEND_URL__: 'http://backend',
    location: { protocol: 'http:', hostname: 'localhost' },
  }
  const context = vm.createContext({ window, fetch, console: { warn: () => undefined } })
  return {
    workspaces,
    calls,
    get started() { return started },
    async load() {
      const source = await readFile(resolve(root, 'packages/threat-context-store/client.js'), 'utf8')
      vm.runInContext(source, context, { filename: 'threat-context-store/client.js' })
      window.__plugin.apply({
        inject: (_names, callback) => callback({ workspaces, sessions, effect: (factory) => effects.push(factory()) }),
      })
    },
    dispose() { effects.forEach((dispose) => dispose?.()) },
  }
}

test('loaded DSH client guard unbinds terminal context before native reuse', async () => {
  const harness = createHarness('ANALYSIS_READY')
  await harness.load()
  harness.workspaces.startSession()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(harness.started, 1)
  assert.deepEqual(harness.calls.map((call) => [call.url, call.init.method]), [
    ['http://backend/api/v1/workbench/sessions/session-history/analysis-context', undefined],
    ['http://backend/api/v1/workbench/sessions/session-history/analysis/unbind', 'POST'],
  ])
  assert.equal(JSON.parse(harness.calls[1].init.body).discard_staged, true)
  harness.dispose()
})

test('loaded DSH client guard keeps running context attached', async () => {
  const harness = createHarness('ANALYSIS_RUNNING')
  await harness.load()
  harness.workspaces.startSession()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(harness.started, 1)
  assert.equal(harness.calls.length, 1)
  harness.dispose()
})
