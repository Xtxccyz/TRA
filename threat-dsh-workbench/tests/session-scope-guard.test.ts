import assert from 'node:assert/strict'
import test from 'node:test'
import { installThreatSessionReuseGuard } from '../packages/threat-session-events/src/session-scope.ts'

function state() {
  return {
    items: [{ workspaceId: 'workspace-a', path: 'D:/workspace-a', sessionIds: ['session-history'] }],
    archivedSessionIds: [],
    recentWorkspaceId: 'workspace-a',
  }
}

test('new session clears a historical binding before reusing a blank DSH session', async () => {
  const calls: string[] = []
  const workspaces = {
    list: { getSnapshot: () => state() },
    startSession(workspaceId?: string) { calls.push(`start:${workspaceId ?? 'recent'}`) },
  }
  const sessions = {
    list: { getSnapshot: () => ({ current: 'session-history', ids: ['session-history'], byId: {
      'session-history': { id: 'session-history', blank: true, cwd: 'D:/workspace-a' },
    } }) },
  }
  const api = {
    sessionContext: async (id: string) => { calls.push(`context:${id}`); return { state: 'ANALYSIS_READY', active_task_id: 'task-history' } },
    unbindAnalysis: async (id: string) => { calls.push(`unbind:${id}`); return { state: 'UNBOUND' } },
  }

  const dispose = installThreatSessionReuseGuard(workspaces as never, sessions as never, api, { warn: () => undefined })
  workspaces.startSession()
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(calls, ['context:session-history', 'unbind:session-history', 'start:recent'])
  dispose()
})

test('new session does not unbind a running analysis', async () => {
  const calls: string[] = []
  const workspaces = {
    list: { getSnapshot: () => state() },
    startSession() { calls.push('start') },
  }
  const sessions = {
    list: { getSnapshot: () => ({ current: 'session-history', ids: ['session-history'], byId: {
      'session-history': { id: 'session-history', blank: true, cwd: 'D:/workspace-a' },
    } }) },
  }
  const api = {
    sessionContext: async () => ({ state: 'ANALYSIS_RUNNING', active_task_id: 'task-live' }),
    unbindAnalysis: async () => { calls.push('unbind'); return { state: 'UNBOUND' } },
  }
  const dispose = installThreatSessionReuseGuard(workspaces as never, sessions as never, api, { warn: () => undefined })
  workspaces.startSession()
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(calls, ['start'])
  dispose()
})

