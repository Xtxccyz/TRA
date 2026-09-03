window.__ModuleLoader__.load({
  id: '@threat-dsh/session-events',
  factory: () => {
    const TERMINAL_CONTEXT_STATES = new Set([
      'HISTORICAL_ANALYSIS_BOUND', 'ANALYSIS_READY', 'ANALYSIS_FAILED', 'ANALYSIS_CANCELLED',
    ])
    const GUARD_KEY = '__threatSessionReuseGuardV1'

    function targetWorkspaceId(snapshot, sessions, explicit) {
      if (explicit) return explicit
      const current = sessions.current
      if (current) {
        const owner = snapshot.items.find((workspace) => workspace.sessionIds.includes(current))
        if (owner) return owner.workspaceId
      }
      return snapshot.recentWorkspaceId
    }

    function findCandidate(workspaces, sessions, explicit) {
      const snapshot = workspaces.list.getSnapshot()
      const sessionsSnapshot = sessions.list.getSnapshot()
      const workspaceId = targetWorkspaceId(snapshot, sessionsSnapshot, explicit)
      if (!workspaceId) return null
      const workspace = snapshot.items.find((item) => item.workspaceId === workspaceId)
      if (!workspace) return null
      const archived = new Set(snapshot.archivedSessionIds || [])
      for (const id of sessionsSnapshot.ids) {
        const summary = sessionsSnapshot.byId[id]
        if (summary && summary.blank && summary.cwd === workspace.path
          && workspace.sessionIds.includes(summary.id) && !archived.has(summary.id)) return summary
      }
      return null
    }

    const backend = () => window.__THREAT_BACKEND_URL__ || `${window.location.protocol}//${window.location.hostname}:8000`
    const request = async (path, init = {}) => {
      const headers = { Accept: 'application/json', ...(init.headers || {}) }
      const token = window.__THREAT_BACKEND_TOKEN__
      if (token) headers.Authorization = `Bearer ${token}`
      const response = await fetch(`${backend()}${path}`, { ...init, headers })
      if (!response.ok) throw new Error(`backend request failed (${response.status})`)
      return response.json()
    }

    function install(ctx) {
      ctx.inject(['workspaces', 'sessions'], (scope) => {
        const workspaces = scope.workspaces
        const sessions = scope.sessions
        if (!workspaces || !sessions || typeof workspaces.startSession !== 'function') return
        const existing = workspaces[GUARD_KEY]
        if (existing && typeof existing.dispose === 'function') return
        const original = workspaces.startSession
        const wrapped = (workspaceId) => {
          const candidate = findCandidate(workspaces, sessions, workspaceId)
          if (!candidate) {
            original.call(workspaces, workspaceId)
            return
          }
          // Fail closed if the server cannot establish the candidate's state:
          // opening it could display a previous task in a new DSH turn.
          void request(`/api/v1/workbench/sessions/${encodeURIComponent(candidate.id)}/analysis-context`).then((context) => {
            const active = typeof context.active_task_id === 'string' ? context.active_task_id.trim() : ''
            const state = typeof context.state === 'string' ? context.state : ''
            if (!active || !TERMINAL_CONTEXT_STATES.has(state)) return undefined
            return request(`/api/v1/workbench/sessions/${encodeURIComponent(candidate.id)}/analysis/unbind`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ discard_staged: true }),
            })
          }).then(() => {
            original.call(workspaces, workspaceId)
          }).catch((error) => {
            console.warn(`[threat-session-scope] refused blank-session reuse for ${candidate.id}: ${error?.message || String(error)}`)
          })
        }
        workspaces.startSession = wrapped
        const dispose = () => {
          if (workspaces.startSession === wrapped) Object.defineProperty(workspaces, 'startSession', { configurable: true, enumerable: false, writable: true, value: original })
          if (workspaces[GUARD_KEY]?.dispose === dispose) delete workspaces[GUARD_KEY]
        }
        Object.defineProperty(workspaces, GUARD_KEY, { configurable: true, value: { dispose } })
        if (typeof scope.effect === 'function') scope.effect(() => dispose, 'threat-session-events: blank-session isolation')
      })
    }

    return { name: 'threat-session-events-client', inject: [], apply: install }
  },
})
