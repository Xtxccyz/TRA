import { boundedText } from '@threat-dsh/plugin-sdk'

export interface WorkbenchClientOptions {
  readonly baseUrl: string
  readonly token?: string
  readonly fetchImpl?: typeof fetch
}

export interface EventPage {
  readonly schema_version: number
  readonly task_id: string
  readonly events: readonly Record<string, unknown>[]
  readonly next_seq: number
  readonly has_more: boolean
}

export class ThreatApiClient {
  readonly baseUrl: string
  private readonly token: string | undefined
  private readonly fetchImpl: typeof fetch

  constructor(options: WorkbenchClientOptions) {
    const url = new URL(options.baseUrl)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('backend URL must use HTTP(S)')
    this.baseUrl = url.toString().replace(/\/$/, '')
    this.token = options.token
    this.fetchImpl = options.fetchImpl ?? fetch
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    if (!path.startsWith('/api/v1/workbench/')) throw new Error('request outside workbench API')
    const headers = new Headers(init.headers)
    headers.set('Accept', 'application/json')
    if (this.token) headers.set('Authorization', `Bearer ${this.token}`)
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, { ...init, headers })
    if (!response.ok) throw new Error(`backend request failed (${response.status}): ${boundedText(await response.text(), 300)}`)
    return response.json() as Promise<T>
  }

  private scopedInit(sessionId: string | undefined, init: RequestInit = {}): RequestInit {
    const headers = new Headers(init.headers)
    if (sessionId?.trim()) headers.set('X-DSH-Session-ID', sessionId.trim())
    return { ...init, headers }
  }

  sessionTask(sessionId: string): Promise<{ link: Record<string, unknown> | null }> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/task`)
  }

  sessionContext(sessionId: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis-context`)
  }

  sessionArtifacts(sessionId: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/artifacts`)
  }

  workspaceArtifacts(sessionId: string, relativeDir = '.'): Promise<Record<string, unknown>> {
    const query = new URLSearchParams({ relative_dir: relativeDir })
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/workspace-artifacts?${query}`)
  }

  importWorkspaceArtifact(sessionId: string, relativePath: string, options: { caseId?: string; workspaceId?: string } = {}): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/workspace-artifacts/import`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ relative_path: relativePath, case_id: options.caseId, workspace_id: options.workspaceId }),
    })
  }

  async attachArtifacts(sessionId: string, files: readonly File[], options: { caseId?: string; workspaceId?: string } = {}): Promise<Record<string, unknown>> {
    const body = new FormData()
    for (const file of files) body.append('sample', file)
    if (options.caseId) body.append('case_id', options.caseId)
    if (options.workspaceId) body.append('workspace_id', options.workspaceId)
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/artifacts`, { method: 'POST', body })
  }

  startAnalysis(sessionId: string, artifactId?: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/start`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ artifact_id: artifactId }),
    })
  }

  dispatchAnalysisIntent(sessionId: string, question: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/intent`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    })
  }

  analysisStatus(sessionId: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/status`)
  }

  waitForAnalysisUpdate(sessionId: string, afterSeq = 0, timeoutSeconds = 120): Promise<Record<string, unknown>> {
    const params = new URLSearchParams({ after_seq: String(Math.max(0, afterSeq)), timeout_seconds: String(Math.min(180, Math.max(0, timeoutSeconds))) })
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/wait?${params}`, this.scopedInit(sessionId))
  }

  proposeStaticAction(sessionId: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/actions`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    })
  }

  currentEvidence(sessionId: string, filters: { kind?: string; module?: string; artifactId?: string; limit?: number; filterText?: string } = {}): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/evidence/query`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind: filters.kind, module: filters.module, artifact_id: filters.artifactId, limit: filters.limit ?? 100, filter_text: filters.filterText }),
    })
  }

  /**
   * Write the analyst report document into the deployment's report root.
   *
   * The deliverable is a file, so the agent writes one; the chat reply carries
   * only a summary. Bounded by the backend to a flat markdown file name under a
   * dedicated writable mount -- the sample workspace stays read-only.
   */
  async writeReportFile(sessionId: string, filename: string, markdown: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/report/file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, markdown }),
    })
  }

  bindAnalysis(sessionId: string, taskId: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/bind`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ task_id: taskId }),
    })
  }

  unbindAnalysis(sessionId: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/unbind`, { method: 'POST' })
  }

  capabilities(): Promise<Record<string, unknown>> {
    return this.request('/api/v1/workbench/capabilities/static-actions')
  }

  task(taskId: string, sessionId?: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/tasks/${encodeURIComponent(taskId)}`, this.scopedInit(sessionId))
  }

  events(taskId: string, afterSeq = 0, limit = 500, sessionId?: string): Promise<EventPage> {
    const params = new URLSearchParams({ after_seq: String(Math.max(0, afterSeq)), limit: String(Math.min(1000, Math.max(1, limit))) })
    return this.request(`/api/v1/workbench/tasks/${encodeURIComponent(taskId)}/events?${params}`, this.scopedInit(sessionId))
  }

  /**
   * Session-bound compatibility alias. Evidence ownership is resolved by the
   * backend from the DSH session; callers must never send a task id in the
   * query body because that would bypass the active-session contract.
   */
  evidence(sessionId: string, filters: { kind?: string; module?: string; artifactId?: string; limit?: number } = {}): Promise<Record<string, unknown>> {
    return this.currentEvidence(sessionId, filters)
  }

  report(taskId: string, sessionId?: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/tasks/${encodeURIComponent(taskId)}/report`, this.scopedInit(sessionId))
  }

  /**
   * Submit an agent-authored analyst narrative for the session's bound task.
   *
   * Session-scoped on purpose: this client refuses any path outside
   * ``/api/v1/workbench/``, and the backend admits the narrative only through
   * 报告合成门 (ADR-0036) -- it may reorganise and explain the recovered facts
   * but may not introduce an endpoint, IPv4, process image or creation-flags
   * value the deterministic fragments do not contain.  A rejection surfaces as
   * a thrown error whose message carries the gate violations, so the agent can
   * revise rather than believe it published.
   */
  async submitAnalystDraft(sessionId: string, markdown: string): Promise<Record<string, unknown>> {
    return this.request(
      `/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/report/analyst-draft`,
      this.scopedInit(sessionId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ markdown }),
      }),
    )
  }

  action(actionId: string, sessionId?: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/actions/${encodeURIComponent(actionId)}`, this.scopedInit(sessionId))
  }

  thread(threadId: string, sessionId?: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/threads/${encodeURIComponent(threadId)}`, this.scopedInit(sessionId))
  }

  threads(taskId: string, sessionId?: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/tasks/${encodeURIComponent(taskId)}/threads`, this.scopedInit(sessionId))
  }

  collection(taskId: string, name: 'mechanisms' | 'claims' | 'relations' | 'sample-timeline', sessionId?: string): Promise<Record<string, unknown>> {
    return this.request(`/api/v1/workbench/tasks/${encodeURIComponent(taskId)}/${name}`, this.scopedInit(sessionId))
  }

  async completeModel(request: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request('/api/v1/workbench/model/complete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
    })
  }
}
