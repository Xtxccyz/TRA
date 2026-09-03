window.__ModuleLoader__.load({
  id: '@threat-dsh/ui-evidence',
  factory: (require) => {
    const module = { exports: {} }
    const React = require('react')
    const { useEffect, useState } = React
    const h = React.createElement
    const CONTEXT_PATH = '/api/v1/workbench/sessions/'
    const store = () => window.__THREAT_ANALYSIS_CONTEXT_STORE__
    // Resource requests are routed through the Store's guarded fetch( layer.
    const displayValue = (value) => { if (value == null) return ''; if (typeof value === 'string') return value; try { return JSON.stringify(value, null, 2).slice(0, 4000) } catch { return String(value) } }
    const View = (props = {}) => {
      const [snapshot, setSnapshot] = useState(() => store()?.snapshot?.() || { context: { state: 'UNBOUND' } })
      const [items, setItems] = useState([]); const [query, setQuery] = useState(''); const [error, setError] = useState('')
      useEffect(() => {
        const contextStore = store(); if (!contextStore) { setError('Threat Context Store 未加载'); return undefined }
        let alive = true
        const stop = contextStore.subscribe(props, (next) => { if (!alive) return; setSnapshot(next); if (!next.context?.active_task_id) setItems([]) })
        const load = async () => {
          try {
            const id = contextStore.taskId(); if (!id) return
            const sessionId = contextStore.snapshot().sessionId
            const value = await contextStore.request(`evidence:${query}`, `${CONTEXT_PATH}${encodeURIComponent(sessionId)}/evidence/query`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind: query || undefined, limit: 120 }) })
            if (alive && value) { setItems(Array.isArray(value.items) ? value.items : []); setError('') }
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
      }, [props.sessionId, query])
      const context = snapshot.context || {}
      const empty = context.state === 'UNBOUND' ? '当前会话尚未选择样本。' : context.state === 'ARTIFACT_READY' ? '样本已就绪，尚未开始静态分析。' : '暂无可展示的支撑证据'
      return h('section', { 'data-threat-view': 'evidence', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 980, margin: '0 auto', padding: 18, color: 'var(--dsw-alias-label-primary, #101828)' } }, h('h2', null, '证据链'), h('div', { style: { display: 'flex', gap: 8 } }, h('input', { value: query, onChange: (e) => setQuery(e.target.value), placeholder: '按 kind 筛选', style: { flex: 1, padding: 8 } })), h('p', { style: { color: 'var(--dsw-alias-label-secondary, #667085)' } }, context.active_task_id ? '每条记录都应可回溯到 Artifact/ToolRun。' : empty), error ? h('p', { style: { color: '#b42318' } }, error) : null, items.map((item, i) => h('article', { key: item.id || i, style: { padding: '10px 0', borderBottom: '1px solid var(--dsw-color-border-subtle, #eaecf0)', fontSize: 13 } }, h('strong', null, displayValue(item.kind || item.module || 'evidence')), h('span', { style: { marginLeft: 8, color: '#667085' } }, displayValue(item.nature || item.stage || '')), h('div', { style: { whiteSpace: 'pre-wrap' } }, displayValue(item.summary ?? item.anchor ?? item.statement ?? item)), item.id ? h('div', { style: { color: '#175cd3', marginTop: 4 } }, `Evidence ${item.id}`) : null)))
    }
    module.exports.name = 'threat-ui-evidence-client'
    module.exports.inject = ['slots']
    module.exports.apply = (ctx) => ctx.slots.inject('conversation.view', () => ctx.slots.register({ name: 'conversation.view', id: 'threat-evidence', order: 60, label: 'Evidence' }, View))
    return module.exports
  },
})
