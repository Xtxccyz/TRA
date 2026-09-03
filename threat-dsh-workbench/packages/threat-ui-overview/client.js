window.__ModuleLoader__.load({
  id: '@threat-dsh/ui-overview',
  factory: (require) => {
    const module = { exports: {} }
    const React = require('react')
    const { useEffect, useMemo, useRef, useState } = React
    const h = React.createElement
    const backend = () => window.__THREAT_BACKEND_URL__ || `${window.location.protocol}//${window.location.hostname}:8000`
    const json = async (path, init, sessionId = '') => {
      const response = await fetch(`${backend()}${path}`, { ...init, headers: { ...(init && init.headers ? init.headers : {}), Accept: 'application/json', ...(sessionId ? { 'X-DSH-Session-ID': sessionId } : {}) } })
      if (!response.ok) throw new Error(`${response.status}: ${(await response.text()).slice(0, 240)}`)
      return response.json()
    }
    const contextStore = () => window.__THREAT_ANALYSIS_CONTEXT_STORE__
    // Legacy task key marker retained only for migration diagnostics. It is
    // never read or written as business state.
    const LEGACY_TASK_KEY = 'threat.workbench.taskId:'
    const DSH_SESSION_KEY = 'dsh.sessions.current'
    // API payload contract: dsh_session_id: owner (the server, not a local
    // task key, owns the active task binding).
    const activeSessionId = (props = {}) => contextStore()?.sessionIdOf?.(props) || ''
    const pill = (text, tone = 'neutral') => h('span', { style: { display: 'inline-block', padding: '3px 8px', borderRadius: 5, fontSize: 12, background: tone === 'good' ? '#dcfce7' : tone === 'bad' ? '#fee2e2' : '#e5e7eb', color: tone === 'good' ? '#166534' : tone === 'bad' ? '#991b1b' : '#374151' } }, text)
    const row = (label, value) => h('div', { style: { display: 'flex', justifyContent: 'space-between', gap: 12, padding: '6px 0', borderBottom: '1px solid #eef0f2' } }, h('span', { style: { color: '#667085' } }, label), h('strong', null, String(value ?? '-')))
    const card = (title, children) => h('section', { style: { border: '1px solid #e4e7ec', borderRadius: 8, padding: 14, background: '#fff' } }, h('h3', { style: { margin: '0 0 10px', fontSize: 15 } }, title), children)
    const Intake = (props = {}) => {
      const contextSource = contextStore()
      const sessionId = activeSessionId(props)
      const [files, setFiles] = useState([])
      const [context, setContext] = useState(() => contextSource?.snapshot?.()?.context || null)
      const [busy, setBusy] = useState(false)
      const [error, setError] = useState('')
      useEffect(() => {
        if (!contextSource) return undefined
        let alive = true
        const stop = contextSource.subscribe(props, (next) => { if (alive) setContext(next.context || null) })
        return () => { alive = false; stop?.() }
      }, [props.sessionId, props.session?.id])
      const submit = async () => {
        if (!sessionId || !files.length) { setError('请先选择一个或多个样本文件'); return }
        setBusy(true); setError('')
        try {
          const form = new FormData(); files.forEach((file) => form.append('sample', file))
          await json(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/artifacts`, { method: 'POST', body: form }, sessionId)
          setFiles([]); contextSource?.refresh(sessionId)
        } catch (e) { setError(e.message || String(e)) } finally { setBusy(false) }
      }
      const start = async () => {
        const artifactId = context?.selected_artifact_id || context?.attached_artifact_ids?.[0]
        if (!artifactId) { setError('请先附加样本文件'); return }
        setBusy(true); setError('')
        try { await json(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ artifact_id: artifactId }) }, sessionId); contextSource?.refresh(sessionId) }
        catch (e) { setError(e.message || String(e)) } finally { setBusy(false) }
      }
      if (!sessionId) return null
      const state = context?.state || 'UNBOUND'
      return h('div', { 'data-threat-intake': 'hero', 'data-threat-session-id': sessionId, style: { margin: '8px auto 0', maxWidth: 760, padding: '8px 12px', border: '1px solid #e4e7ec', borderRadius: 8, background: '#fff', fontSize: 13 } },
        h('div', { style: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
          h('strong', null, '静态样本入口'),
          h('span', { style: { color: '#667085' } }, state === 'ARTIFACT_READY' ? '样本已就绪，尚未开始分析' : state === 'UNBOUND' ? '当前会话尚未选择样本' : `分析状态：${state}`),
          h('input', { type: 'file', multiple: true, onChange: (e) => setFiles(Array.from(e.target.files || [])), disabled: busy, 'aria-label': '选择静态样本' }),
          h('button', { type: 'button', onClick: submit, disabled: busy || !files.length }, busy ? '提交中…' : '附加样本'),
          state === 'ARTIFACT_READY' ? h('button', { type: 'button', onClick: start, disabled: busy }, '开始静态分析') : null,
        ),
        error ? h('div', { role: 'alert', style: { color: '#b42318', marginTop: 6 } }, error) : null,
      )
    }
    const View = (props = {}) => {
      // Session-scoped slot props are the authoritative DSH selection. The
      // localStorage fallback only supports older hosts that did not inject
      // the standard session kit.
      const providedSessionId = typeof props.sessionId === 'string' ? props.sessionId : ''
      const runtimeSessionId = providedSessionId || activeSessionId(props)
      const owner = runtimeSessionId
      const [cases, setCases] = useState([])
      const [caseId, setCaseId] = useState('')
      const [title, setTitle] = useState('静态分析任务')
      const [files, setFiles] = useState([])
      const [password, setPassword] = useState('')
      const [sessionId, setSessionId] = useState(runtimeSessionId)
      const [taskId, setTaskId] = useState('')
      const [context, setContext] = useState(null)
      const sessionIdRef = useRef(sessionId)
      const [task, setTask] = useState(null)
      const [report, setReport] = useState(null)
      const [error, setError] = useState('')
      const [busy, setBusy] = useState(false)
      const eventCursorRef = useRef(0)
      const fullLoadedRef = useRef(false)
      const loadingRef = useRef(false)
      const refreshCases = () => json('/api/v1/cases').then(setCases).catch((e) => setError(e.message))
      useEffect(() => { refreshCases() }, [])
      useEffect(() => {
        const source = contextStore()
        if (!source) { setError('Threat Context Store 未加载'); return undefined }
        let alive = true
        const stop = source.subscribe(props, (next) => {
          if (!alive) return
          setSessionId(next.sessionId || '')
          setContext(next.context || null)
          setTaskId(next.context?.active_task_id || '')
          if (!next.context?.active_task_id) { setTask(null); setReport(null) }
        })
        return () => { alive = false; stop?.() }
      }, [props.sessionId])
      useEffect(() => {
        if (!taskId) return undefined
        // React may render the new session before the session-sync effect has
        // cleared the previous task. Do not persist that stale value under
        // the new session key during the transition frame.
        if (sessionIdRef.current !== sessionId) {
          sessionIdRef.current = sessionId
          return undefined
        }
        let cancelled = false
        const source = contextStore()
        const load = async () => {
          // The shared context store wakes this loader from the bounded
          // session event stream. The full workbench projection includes
          // every Evidence/Claim row and is loaded once at terminal state.
          if (loadingRef.current) return
          loadingRef.current = true
          try {
            const status = await source.request('status', `/api/v1/tasks/${encodeURIComponent(taskId)}/status`)
            if (!status) return
            const afterSeq = eventCursorRef.current
            const eventPage = await source.request('events', `/api/v1/workbench/tasks/${encodeURIComponent(taskId)}/events?after_seq=${afterSeq}&limit=100`).catch(() => ({ events: [] }))
            const events = eventPage.events || []
            if (events.length) eventCursorRef.current = Math.max(eventCursorRef.current, ...events.map((item) => Number(item.seq) || 0))
            if (!cancelled) setTask((previous) => ({ ...(previous || {}), ...status, events: [...(previous?.events || []), ...events].slice(-200) }))
            const lifecycle = String(status.lifecycle || '')
            if (!cancelled && ['SUCCEEDED', 'FAILED', 'CANCELLED'].includes(lifecycle) && !fullLoadedRef.current) {
              fullLoadedRef.current = true
              const [value, evidencePage, reportValue] = await Promise.all([
                source.request('task', `/api/v1/workbench/tasks/${encodeURIComponent(taskId)}`),
                source.request('evidence', `/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/evidence/query`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ limit: 100 }) }).catch(() => ({ items: [] })),
                source.request('report', `/api/v1/workbench/tasks/${encodeURIComponent(taskId)}/report`).catch(() => null),
              ])
              if (!cancelled) {
                setTask({ ...value, events: [...(value.events || []), ...events].slice(-200), evidence: evidencePage.items || [], evidence_total: evidencePage.total ?? (evidencePage.items || []).length })
                setReport(reportValue)
              }
            }
          } catch (e) { if (!cancelled) setError(e.message) } finally { loadingRef.current = false }
        }
        eventCursorRef.current = 0
        fullLoadedRef.current = false
        const offEvent = source.onEvent?.((detail) => {
          if (cancelled || detail?.sessionId !== source.snapshot().sessionId) return
          const eventTask = detail?.event?.task_id || detail?.event?.data?.task_id
          if (eventTask && String(eventTask) !== String(taskId)) return
          void load()
        })
        void load()
        return () => { cancelled = true; offEvent?.() }
      }, [taskId, sessionId])
      const summary = useMemo(() => {
        const t = task?.task || task || {}
        return { lifecycle: t.lifecycle || 'NOT_STARTED', outcome: t.outcome || '-', artifacts: task?.artifacts?.length || 0, evidence: task?.evidence_total || task?.evidence?.length || 0, mechanisms: task?.mechanisms?.length || 0, claims: task?.claims?.length || 0, threads: task?.threads?.length || 0, actions: task?.actions?.length || 0 }
      }, [task])
      const refreshContext = () => contextStore()?.refresh(sessionId)
      const submit = async () => {
        if (!files.length) return setError('请先选择一个或多个样本文件')
        setBusy(true); setError(''); setTask(null); setReport(null)
        try {
          const form = new FormData(); files.forEach((file) => form.append('sample', file)); if (caseId) form.append('case_id', caseId); void LEGACY_TASK_KEY; void DSH_SESSION_KEY; void owner
          const result = await json(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/artifacts`, { method: 'POST', body: form }, sessionId)
          setContext(result.context || result); setTaskId(''); contextStore()?.refresh(sessionId)
        } catch (e) { setError(e.message) } finally { setBusy(false) }
      }
      const startAnalysis = async () => {
        const artifactId = context?.selected_artifact_id || context?.attached_artifact_ids?.[0]
        if (!artifactId) return setError('请先附加样本文件')
        setBusy(true); setError('')
        try {
          const result = await json(`/api/v1/workbench/sessions/${encodeURIComponent(sessionId)}/analysis/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ artifact_id: artifactId }) }, sessionId)
          setContext(result); setTaskId(result.active_task_id || result.task_id || ''); contextStore()?.refresh(sessionId)
        } catch (e) { setError(e.message) } finally { setBusy(false) }
      }
      const data = task || {}
      const summaryCards = h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginTop: 12 } },
        card('生命周期', h('div', null, h('div', { style: { fontSize: 20, fontWeight: 700 } }, summary.lifecycle), h('div', { style: { marginTop: 4 } }, pill(summary.outcome)))),
        card('调查规模', h('div', null, row('Threads', summary.threads), row('Hypotheses', data.hypotheses?.length || 0), row('Actions', summary.actions))),
        card('证据与结论', h('div', null, row('Evidence', summary.evidence), row('Claims', summary.claims), row('Mechanisms', summary.mechanisms))),
        card('报告', h('div', null, row('Revision', report?.revision?.id ? String(report.revision.id).slice(0, 12) : '生成中'), row('状态', report?.revision?.status || '等待完成')))
      )
      const eventCard = taskId && data.events ? card('当前调查轨迹', h('div', { style: { maxHeight: 260, overflow: 'auto' } }, data.events.slice(-20).map((event, index) => {
        const status = event.payload_summary?.status || event.payload_summary?.state || ''
        return h('div', { key: `${event.seq || index}`, style: { padding: '7px 0', borderBottom: '1px solid #eef0f2', fontSize: 13 } }, h('strong', null, event.type || 'event'), h('span', { style: { marginLeft: 8, color: '#667085' } }, status), h('div', { style: { color: '#98a2b3' } }, event.seq ? `seq ${event.seq}` : ''))
      }))) : null
      const mechanismCard = taskId && data.mechanisms?.length ? card('已验证机制', h('div', null, data.mechanisms.slice(0, 12).map((item) => h('div', { key: item.id, style: { padding: '8px 0', borderBottom: '1px solid #eef0f2' } }, h('strong', null, item.type || item.dimension || '机制'), h('span', { style: { marginLeft: 8 } }, pill(item.status || 'UNKNOWN', String(item.status).toUpperCase() === 'VERIFIED' ? 'good' : 'neutral')), h('div', { style: { marginTop: 4 } }, item.statement || item.mechanism || item.target || ''))))) : null
      return h('section', { 'data-threat-view': 'overview', 'data-threat-session-id': sessionId, style: { fontFamily: 'system-ui, sans-serif', color: '#101828', maxWidth: 980, margin: '0 auto', padding: 18, background: '#f8fafc' } },
        h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 } }, h('div', null, h('h2', { style: { margin: 0, fontSize: 22 } }, '威胁分析工作台'), h('p', { style: { margin: '5px 0 0', color: '#667085' } }, '静态只读 · 证据驱动调查 · 全程可追溯')), taskId ? pill(`任务 ${taskId.slice(0, 8)}`, 'good') : pill('等待上传')),
        card('提交静态分析', h('div', null,
          h('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 } },
            h('label', null, '已有 Case', h('select', { value: caseId, onChange: (e) => setCaseId(e.target.value), style: { width: '100%', marginTop: 4, padding: 8 } }, h('option', { value: '' }, '自动创建新 Case'), cases.slice(0, 30).map((item) => h('option', { key: item.id, value: item.id }, `${item.title} · ${item.id.slice(0, 8)}`)))),
            h('label', null, '新 Case 标题', h('input', { value: title, onChange: (e) => setTitle(e.target.value), style: { width: '100%', marginTop: 4, padding: 8, boxSizing: 'border-box' } })),
          ),
          h('label', { style: { display: 'block', marginTop: 10 } }, '样本文件（支持批量及压缩包）', h('input', { type: 'file', multiple: true, onChange: (e) => setFiles(Array.from(e.target.files || [])), style: { display: 'block', marginTop: 5 } })),
          files.length ? h('div', { style: { marginTop: 6, color: '#475467', fontSize: 13 } }, files.map((file) => h('div', { key: `${file.name}:${file.size}` }, `${file.name} (${Math.ceil(file.size / 1024)} KB)`))) : null,
          h('label', { style: { display: 'block', marginTop: 10 } }, '压缩包密码（如需要）', h('input', { type: 'password', value: password, onChange: (e) => setPassword(e.target.value), placeholder: '仅在输入 Gate 时提交', name: 'archive_password', style: { width: '100%', marginTop: 4, padding: 8, boxSizing: 'border-box' } })),
          h('button', { type: 'button', disabled: busy, onClick: submit, style: { marginTop: 12, padding: '9px 16px', border: 0, borderRadius: 6, background: busy ? '#98a2b3' : '#175cd3', color: '#fff', cursor: busy ? 'wait' : 'pointer', fontWeight: 600 } }, busy ? '提交中...' : '附加样本'),
          context?.state === 'ARTIFACT_READY' ? h('button', { type: 'button', disabled: busy, onClick: startAnalysis, style: { marginTop: 12, marginLeft: 8, padding: '9px 16px', border: 0, borderRadius: 6, background: busy ? '#98a2b3' : '#039855', color: '#fff', cursor: busy ? 'wait' : 'pointer', fontWeight: 600 } }, '开始静态分析') : null,
          error ? h('div', { role: 'alert', style: { marginTop: 10, color: '#b42318', whiteSpace: 'pre-wrap' } }, error) : null,
        )),
        summaryCards,
        eventCard,
        mechanismCard,
      )
    }
    module.exports.name = 'threat-ui-overview-client'
    module.exports.inject = ['slots']
    module.exports.apply = (ctx) => {
      ctx.slots.inject('conversation.view', () => ctx.slots.register({ name: 'conversation.view', id: 'threat-overview', order: 20, label: 'Overview' }, View))
      // DSH hides the view ring for a blank session. Keep a compact intake in
      // the native composer dock so upload-only and explicit-start workflows
      // remain reachable without creating a chat turn.
      ctx.slots.inject('conversation.input.dock', () => ctx.slots.register({ name: 'conversation.input.dock', id: 'threat-intake', order: -20 }, Intake))
    }
    return module.exports
  },
})
