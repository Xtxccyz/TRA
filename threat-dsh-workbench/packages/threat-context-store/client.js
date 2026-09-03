window.__ModuleLoader__.load({
  id: '@threat-dsh/context-store',
  factory: () => {
  if (window.__THREAT_ANALYSIS_CONTEXT_STORE__) return { name: 'threat-context-store-client', inject: [], apply: () => {} }
  const backend = () => window.__THREAT_BACKEND_URL__ || `${window.location.protocol}//${window.location.hostname}:8000`
  const empty = (state = 'UNBOUND', code = state === 'UNBOUND' ? 'NO_ACTIVE_ANALYSIS' : undefined) => ({ state, code, active_task_id: null, attached_artifact_ids: [], attached_artifacts: [] })
  let current = { sessionId: '', context: empty(), revision: 0, requestId: 0 }
  let controller = null
    const resourceControllers = new Map()
    const TERMINAL_CONTEXT_STATES = new Set([
      'HISTORICAL_ANALYSIS_BOUND', 'ANALYSIS_READY', 'ANALYSIS_FAILED', 'ANALYSIS_CANCELLED',
    ])
    const GUARD_KEY = '__threatSessionReuseGuardV1'
  let watcher = null
  let observedSession = ''
  let waitController = null
  let waitSession = ''
  let waitTask = ''
  let waitCursor = 0
  const listeners = new Set()
  const eventListeners = new Set()
  const notify = () => listeners.forEach((listener) => listener(current))
  const emitEvent = (sessionId, event) => {
    const detail = { sessionId, event }
    eventListeners.forEach((listener) => { try { listener(detail) } catch {} })
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function' && typeof window.CustomEvent === 'function') {
      window.dispatchEvent(new CustomEvent('threat:session-event', { detail }))
    }
  }
  const sessionIdOf = (props = {}) => {
    if (typeof props.sessionId === 'string' && props.sessionId.trim()) return props.sessionId.trim()
    if (typeof props.session?.id === 'string' && props.session.id.trim()) return props.session.id.trim()
    if (typeof props.id === 'string' && props.id.trim()) return props.id.trim()
    // Session identity is host-owned. This fallback is only for older DSH
    // hosts that do not inject the standard slot prop; it never stores or
    // restores a business task id.
    try { return JSON.parse(localStorage.getItem('dsh.sessions.current') || '{}').sessionId || '' } catch { return '' }
  }
  const refresh = async (sessionId) => {
    const id = String(sessionId || '').trim()
    // A manual refresh (upload/start/session switch) supersedes the current
    // bounded wait. This prevents a previous task's waiter from surviving a
    // same-session task binding change.
    if (waitSession) stopWait()
    const requestId = current.requestId + 1
    const sameSession = current.sessionId === id
    current = { sessionId: id, context: sameSession ? current.context : (id ? empty('LOADING') : empty()), revision: current.revision + 1, requestId }
    if (controller) controller.abort()
    notify()
    if (!id) return current
    controller = new AbortController()
    const revision = current.revision
    try {
      const response = await fetch(`${backend()}/api/v1/workbench/sessions/${encodeURIComponent(id)}/analysis-context`, { headers: { Accept: 'application/json' }, signal: controller.signal })
      if (!response.ok) throw new Error(`${response.status}`)
      const context = await response.json()
      if (current.sessionId !== id || current.revision !== revision || current.requestId !== requestId) return current
      current = { sessionId: id, context, revision, requestId }; notify(); return current
    } catch (error) {
      if (error?.name === 'AbortError') return current
      if (current.sessionId === id && current.revision === revision && current.requestId === requestId) {
        current = { sessionId: id, context: empty('UNBOUND', 'CONTEXT_UNAVAILABLE'), revision, requestId }; notify()
      }
      return current
    }
  }
  const stopWait = () => { if (waitController) waitController.abort(); waitController = null; waitSession = ''; waitTask = ''; waitCursor = 0 }
  const waitForUpdates = async (id) => {
    if (!id) return
    const task = active()
    if (waitSession === id && waitTask === task && waitController && !waitController.signal.aborted) return
    stopWait(); waitSession = id; waitTask = task; const controllerForLoop = new AbortController(); waitController = controllerForLoop
    while (!controllerForLoop.signal.aborted && current.sessionId === id && waitSession === id) {
    const taskId = active()
      if (taskId !== waitTask) {
        stopWait()
        void waitForUpdates(id)
        return
      }
      const params = new URLSearchParams({ after_seq: String(waitCursor), timeout_seconds: '30' })
      try {
        const response = await fetch(`${backend()}/api/v1/workbench/sessions/${encodeURIComponent(id)}/analysis/wait?${params}`, { headers: { Accept: 'application/json', 'X-DSH-Session-ID': id }, signal: controllerForLoop.signal })
        if (!response.ok) throw new Error(`${response.status}`)
        const value = await response.json()
        if (current.sessionId !== id || waitSession !== id) return
        const context = value.context && typeof value.context === 'object'
          ? value.context
          // Keep compatibility with the compact analysis/status projection
          // used by older local backends and test doubles.
          : (value && typeof value.state === 'string' ? value : null)
        if (context) { current = { ...current, context, revision: current.revision + 1 }; notify() }
        const events = Array.isArray(value.events) ? value.events : []
        for (const event of events) {
          const seq = Number(event?.seq)
          if (Number.isSafeInteger(seq) && seq > waitCursor) waitCursor = seq
          emitEvent(id, event)
        }
        if (context && ['ANALYSIS_READY', 'ANALYSIS_FAILED', 'ANALYSIS_CANCELLED'].includes(String(context.state))) return
        // If the backend has not bound a task yet, the wait endpoint itself
        // provides the next wake-up opportunity without a client-side timer.
        if (!taskId && !events.length && value.changed === false) continue
      } catch (error) {
        if (error?.name === 'AbortError') return
        // Retry only through the bounded wait endpoint. A transient outage
        // must not create a fast polling loop or fabricate a state update.
        await new Promise((resolve) => setTimeout(resolve, 1000))
      }
    }
  }
  const ensureWatcher = () => {
    if (watcher || typeof window === 'undefined') return
    watcher = true
    const onStorage = () => {
      const next = sessionIdOf({}) || current.sessionId
      if (next !== observedSession) { observedSession = next; stopWait(); void refresh(next) }
    }
    window.addEventListener?.('storage', onStorage)
    window.addEventListener?.('dsh:session-changed', onStorage)
    watcher = () => { window.removeEventListener?.('storage', onStorage); window.removeEventListener?.('dsh:session-changed', onStorage); stopWait(); watcher = null }
  }
  const subscribe = (props, listener) => {
    const id = sessionIdOf(props)
    if (id !== observedSession) { observedSession = id; stopWait() }
    listeners.add(listener)
    ensureWatcher()
    refresh(id).then(() => { if (current.sessionId === id) void waitForUpdates(id) })
    listener(current)
    return () => { listeners.delete(listener) }
  }
  const active = () => current.context && current.context.active_task_id ? String(current.context.active_task_id) : ''
    const state = () => String(current.context?.state || 'UNBOUND')

    function targetWorkspaceId(snapshot, sessions, explicit) {
      if (explicit) return explicit
      const currentId = sessions.current
      if (currentId) {
        const owner = snapshot.items.find((workspace) => workspace.sessionIds.includes(currentId))
        if (owner) return owner.workspaceId
      }
      return snapshot.recentWorkspaceId
    }

    function findReusableBlankSession(workspaces, sessions, explicit) {
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

    function installSessionReuseGuard(ctx) {
      ctx.inject(['workspaces', 'sessions'], (scope) => {
        const workspaces = scope.workspaces
        const sessions = scope.sessions
        if (!workspaces || !sessions || typeof workspaces.startSession !== 'function') {
          return
        }
        const existing = workspaces[GUARD_KEY]
        if (existing && typeof existing.dispose === 'function') {
          return
        }
        const original = workspaces.startSession
        const wrapped = (workspaceId) => {
          const candidate = findReusableBlankSession(workspaces, sessions, workspaceId)
          if (!candidate) {
            original.call(workspaces, workspaceId)
            return
          }
          const requestContext = (path, init = {}) => {
            const responseHeaders = { Accept: 'application/json', ...(init.headers || {}) }
            const token = window.__THREAT_BACKEND_TOKEN__
            if (token) responseHeaders.Authorization = `Bearer ${token}`
            return fetch(`${backend()}${path}`, { ...init, headers: responseHeaders }).then((response) => {
              if (!response.ok) throw new Error(`backend request failed (${response.status})`)
              return response.json()
            })
          }
          // Fail closed if the server cannot establish the candidate's state:
          // opening it could display a previous task in a new DSH turn.
          void requestContext(`/api/v1/workbench/sessions/${encodeURIComponent(candidate.id)}/analysis-context`).then((context) => {
            const active = typeof context.active_task_id === 'string' ? context.active_task_id.trim() : ''
            const contextState = typeof context.state === 'string' ? context.state : ''
            if (!active || !TERMINAL_CONTEXT_STATES.has(contextState)) return undefined
            return requestContext(`/api/v1/workbench/sessions/${encodeURIComponent(candidate.id)}/analysis/unbind`, {
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
        // Injected services are Cordis traceable proxies. Use defineProperty
        // so the wrapper lands on the WorkspaceRuntime target rather than a
        // transient shadow receiver used by ordinary assignment.
        Object.defineProperty(workspaces, 'startSession', { configurable: true, enumerable: false, writable: true, value: wrapped })
        const dispose = () => {
          if (workspaces.startSession === wrapped) Object.defineProperty(workspaces, 'startSession', { configurable: true, enumerable: false, writable: true, value: original })
          if (workspaces[GUARD_KEY]?.dispose === dispose) delete workspaces[GUARD_KEY]
        }
        Object.defineProperty(workspaces, GUARD_KEY, { configurable: true, value: { dispose } })
        if (typeof scope.effect === 'function') scope.effect(() => dispose, 'threat-context-store: blank-session isolation')
      })
    }
  const request = async (resourceType, path, init = {}) => {
    const snapshot = current
    const taskId = active()
    if (!snapshot.sessionId || !taskId) return null
    const key = `${snapshot.sessionId}:${taskId}:${String(resourceType || path)}`
    resourceControllers.get(key)?.abort()
    const aborter = new AbortController()
    resourceControllers.set(key, aborter)
    const response = await fetch(`${backend()}${path}`, { ...init, headers: { ...(init.headers || {}), Accept: 'application/json', 'X-DSH-Session-ID': snapshot.sessionId }, signal: aborter.signal })
    if (!response.ok) throw new Error(`${response.status}`)
    const value = await response.json()
    if (current.sessionId !== snapshot.sessionId || current.revision !== snapshot.revision || active() !== taskId) return null
    return value
  }
  const onEvent = (listener) => { eventListeners.add(listener); return () => eventListeners.delete(listener) }
  const apply = (ctx) => {
    installSessionReuseGuard(ctx)
    if (typeof ctx?.on === 'function') ctx.on('session/event', (session, event) => {
      const id = typeof session?.id === 'string' ? session.id : ''
      if (id && id === current.sessionId) emitEvent(id, event)
    }, { global: true })
  }
  window.__THREAT_ANALYSIS_CONTEXT_STORE__ = Object.freeze({ sessionIdOf, refresh, subscribe, request, onEvent, snapshot: () => current, taskId: active, state })
    return { name: 'threat-context-store-client', inject: [], apply }
  },
})
