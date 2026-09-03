window.__ModuleLoader__.load({
  id: '@threat-dsh/ui-investigation',
  factory: (require) => {
    const module = { exports: {} }
    const React = require('react')
    const { useEffect, useState } = React
    const h = React.createElement
    const CONTEXT_PATH = '/api/v1/workbench/sessions/'
    const store = () => window.__THREAT_ANALYSIS_CONTEXT_STORE__
    // Resource requests are routed through the Store's guarded fetch( layer.
    const View = (props = {}) => {
      const [snapshot, setSnapshot] = useState(() => store()?.snapshot?.() || { context: { state: 'UNBOUND' }, revision: 0 })
      const [data, setData] = useState({ threads: [], hypotheses: [], actions: [] })
      const [error, setError] = useState('')
      useEffect(() => {
        const contextStore = store()
        if (!contextStore) { setError('Threat Context Store 未加载'); return undefined }
        let alive = true
        const onContext = (next) => {
          if (!alive) return
          setSnapshot(next)
          if (!next.context?.active_task_id) setData({ threads: [], hypotheses: [], actions: [] })
        }
        const stop = contextStore.subscribe(props, onContext)
        const load = async () => {
          try {
            const id = contextStore.taskId()
            if (!id) return
            const rows = await Promise.all(['threads', 'hypotheses', 'actions'].map((name) => contextStore.request(name, `/api/v1/workbench/tasks/${encodeURIComponent(id)}/${name}`)))
            if (!alive || rows.some((row) => row == null)) return
            setData({ threads: rows[0]?.items || [], hypotheses: rows[1]?.items || [], actions: rows[2]?.items || [] })
            setError('')
          } catch (e) { if (alive && e?.name !== 'AbortError') setError(e.message || String(e)) }
        }
        const offEvent = contextStore.onEvent?.((detail) => {
          if (!alive || detail?.sessionId !== contextStore.snapshot().sessionId) return
          const taskId = contextStore.taskId(); const eventTask = detail?.event?.task_id || detail?.event?.data?.task_id
          if (eventTask && taskId && String(eventTask) !== String(taskId)) return
          void load()
        })
        void load()
        return () => { alive = false; offEvent?.(); stop?.() }
      }, [props.sessionId])
      const context = snapshot.context || {}
      const list = (items, fields) => items.length ? items.slice(-40).map((item, i) => h('article', { key: item.id || i, style: { padding: '9px 0', borderBottom: '1px solid var(--dsw-color-border-subtle, #eaecf0)' } }, h('strong', null, item.question || item.action_type || item.type || item.name || `记录 ${i + 1}`), h('span', { style: { marginLeft: 8, color: 'var(--dsw-alias-label-secondary, #667085)' } }, item.state || item.status || item.result_status || ''), fields.map((field) => item[field] != null ? h('div', { key: field, style: { fontSize: 13, color: 'var(--dsw-alias-label-secondary, #475467)', marginTop: 3 } }, `${field}: ${typeof item[field] === 'object' ? JSON.stringify(item[field]) : item[field]}`) : null))) : [h('p', { key: 'empty' }, context.state === 'UNBOUND' ? '当前会话尚未选择样本。' : context.state === 'ARTIFACT_READY' ? '样本已就绪，尚未开始静态分析。' : '暂无调查记录。')]
      return h('section', { 'data-threat-view': 'investigation', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 980, margin: '0 auto', padding: 18, color: 'var(--dsw-alias-label-primary, #101828)' } }, h('h2', null, '调查轨迹'), h('p', { style: { color: 'var(--dsw-alias-label-secondary, #667085)' } }, context.state === 'UNBOUND' ? '当前会话尚未选择样本。' : context.state === 'ARTIFACT_READY' ? '样本已就绪，尚未开始静态分析。' : context.active_task_id ? `当前任务：${String(context.active_task_id).slice(0, 12)}` : '正在解析分析上下文...'), error ? h('p', { style: { color: '#b42318' } }, error) : null, h('h3', null, `调查线程 (${data.threads.length})`), list(data.threads, ['question', 'state']), h('h3', null, `假设 (${data.hypotheses.length})`), list(data.hypotheses, ['statement', 'confidence']), h('h3', null, `模型动作 (${data.actions.length})`), list(data.actions, ['action_type', 'reason']))
    }
    module.exports.name = 'threat-ui-investigation-client'
    module.exports.inject = ['slots']
    module.exports.apply = (ctx) => ctx.slots.inject('conversation.view', () => ctx.slots.register({ name: 'conversation.view', id: 'threat-investigation', order: 30, label: 'Investigation' }, View))
    return module.exports
  },
})
