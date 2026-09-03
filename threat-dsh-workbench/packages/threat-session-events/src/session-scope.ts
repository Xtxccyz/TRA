/**
 * Product-side guard for DSH's blank-session reuse.
 *
 * DSH intentionally reuses a blank session for New Session. A Threat
 * Workbench session can be blank from DSH's point of view while the backend
 * still has a terminal analysis bound to it. Before allowing that reuse, the
 * guard clears only terminal/history bindings. Running work is left attached
 * so a user cannot accidentally detach an in-flight analysis.
 */

export interface ThreatSessionContextApi {
  sessionContext(sessionId: string): Promise<Record<string, unknown>>
  unbindAnalysis(sessionId: string): Promise<Record<string, unknown>>
}

export interface ThreatSessionScopeLogger {
  warn(message: string): void
}

interface WorkspaceSnapshot {
  readonly items: readonly {
    readonly workspaceId: string
    readonly path: string
    readonly sessionIds: readonly string[]
  }[]
  readonly archivedSessionIds?: readonly string[]
  readonly recentWorkspaceId?: string
}

interface SessionSummary {
  readonly id: string
  readonly blank?: boolean
  readonly cwd?: string
}

interface SessionsSnapshot {
  readonly current?: string
  readonly ids: readonly string[]
  readonly byId: Readonly<Record<string, SessionSummary | undefined>>
}

export interface ThreatWorkspacesService {
  readonly list: { getSnapshot(): WorkspaceSnapshot }
  startSession(workspaceId?: string): void
}

export interface ThreatSessionsService {
  readonly list: { getSnapshot(): SessionsSnapshot }
}

const TERMINAL_CONTEXT_STATES = new Set([
  'HISTORICAL_ANALYSIS_BOUND',
  'ANALYSIS_READY',
  'ANALYSIS_FAILED',
  'ANALYSIS_CANCELLED',
])

const installed = new WeakMap<object, () => void>()

function targetWorkspaceId(snapshot: WorkspaceSnapshot, sessions: SessionsSnapshot, explicit?: string): string | undefined {
  if (explicit) return explicit
  const current = sessions.current
  if (current) {
    const owner = snapshot.items.find((workspace) => workspace.sessionIds.includes(current))
    if (owner) return owner.workspaceId
  }
  return snapshot.recentWorkspaceId
}

/** Mirror the upstream reuse predicate so the guard clears the exact session
 * that DSH's connectWorkspace() would otherwise return. */
export function findReusableBlankSession(
  workspaces: WorkspaceSnapshot,
  sessions: SessionsSnapshot,
  explicitWorkspaceId?: string,
): SessionSummary | undefined {
  const workspaceId = targetWorkspaceId(workspaces, sessions, explicitWorkspaceId)
  if (!workspaceId) return undefined
  const workspace = workspaces.items.find((item) => item.workspaceId === workspaceId)
  if (!workspace) return undefined
  const archived = new Set(workspaces.archivedSessionIds ?? [])
  for (const id of sessions.ids) {
    const summary = sessions.byId[id]
    if (summary?.blank && summary.cwd === workspace.path
      && workspace.sessionIds.includes(summary.id) && !archived.has(summary.id)) return summary
  }
  return undefined
}

async function clearTerminalBinding(
  api: ThreatSessionContextApi,
  sessionId: string,
): Promise<void> {
  const context = await api.sessionContext(sessionId)
  const activeTask = typeof context.active_task_id === 'string' ? context.active_task_id.trim() : ''
  const state = typeof context.state === 'string' ? context.state : ''
  if (activeTask && TERMINAL_CONTEXT_STATES.has(state)) await api.unbindAnalysis(sessionId)
}

/**
 * Install an unload-safe wrapper around the native New Session action.
 * Returns a disposer so Cordis/HMR can remove the wrapper without leaving the
 * native service in a patched state.
 */
export function installThreatSessionReuseGuard(
  workspaces: ThreatWorkspacesService,
  sessions: ThreatSessionsService,
  api: ThreatSessionContextApi,
  logger: ThreatSessionScopeLogger = console,
): () => void {
  const service = workspaces as unknown as object
  const previousDisposer = installed.get(service)
  if (previousDisposer) return previousDisposer
  const original = workspaces.startSession
  if (typeof original !== 'function') throw new Error('Threat session guard requires workspaces.startSession')

  const wrapped = (workspaceId?: string): void => {
    const candidate = findReusableBlankSession(workspaces.list.getSnapshot(), sessions.list.getSnapshot(), workspaceId)
    if (!candidate) {
      original.call(workspaces, workspaceId)
      return
    }
    // Fail closed on a backend error: opening the reused session would risk
    // displaying a task from a previous analysis under a new DSH turn.
    void clearTerminalBinding(api, candidate.id).then(
      () => { original.call(workspaces, workspaceId) },
      (error: unknown) => {
        logger.warn(`[threat-session-scope] refused blank-session reuse for ${candidate.id}: ${error instanceof Error ? error.message : String(error)}`)
      },
    )
  }
  // Cordis exposes injected services through a traceable Proxy. A normal
  // assignment uses the proxy's shadow receiver and can leave the override
  // on a transient scope instead of the WorkspaceRuntime instance that the
  // UI resolves on the next click. defineProperty forwards to the proxy
  // target and makes the interception durable for every consumer.
  Object.defineProperty(workspaces, 'startSession', {
    configurable: true,
    enumerable: false,
    writable: true,
    value: wrapped,
  })
  const dispose = (): void => {
    if (workspaces.startSession === wrapped) {
      Object.defineProperty(workspaces, 'startSession', {
        configurable: true,
        enumerable: false,
        writable: true,
        value: original,
      })
    }
    installed.delete(service)
  }
  installed.set(service, dispose)
  return dispose
}

export const terminalContextStates = TERMINAL_CONTEXT_STATES
