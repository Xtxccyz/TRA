window.__ModuleLoader__.load({
  id: '@threat-dsh/ui-mechanisms',
  factory: (require) => {
    const module = { exports: {} }
    const React = require('react')
    const { useEffect, useState } = React
    const h = React.createElement
    const CONTEXT_PATH = '/api/v1/workbench/sessions/'
    const store = () => window.__THREAT_ANALYSIS_CONTEXT_STORE__
    // Resource requests are routed through the Store's guarded fetch( layer.
    const View = (props = {}) => {
      const [snapshot, setSnapshot] = useState(() => store()?.snapshot?.() || { context: { state: 'UNBOUND' } })
      const [items, setItems] = useState([]); const [error, setError] = useState('')
      useEffect(() => {
        const contextStore = store()
        if (!contextStore) { setError('Threat Context Store 未加载'); return undefined }
        let alive = true
        const stop = contextStore.subscribe(props, (next) => { if (!alive) return; setSnapshot(next); if (!next.context?.active_task_id) setItems([]) })
        const load = async () => {
          try {
            const id = contextStore.taskId(); if (!id) return
            const value = await contextStore.request('mechanisms', `/api/v1/workbench/tasks/${encodeURIComponent(id)}/mechanisms`)
            if (alive && value) { setItems(value.items || []); setError('') }
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
      const empty = context.state === 'UNBOUND' ? '当前会话尚未选择样本。' : context.state === 'ARTIFACT_READY' ? '样本已就绪，尚未开始静态分析。' : '分析完成后将在此显示证据支撑的机制'
      return h('section', { 'data-threat-view': 'mechanisms', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 980, margin: '0 auto', padding: 18, color: 'var(--dsw-alias-label-primary, #101828)' } }, h('h2', null, '机制与 ATT&CK'), h('p', { style: { color: 'var(--dsw-alias-label-secondary, #667085)' } }, context.active_task_id ? `当前任务：${String(context.active_task_id).slice(0, 12)}` : empty), error ? h('p', { style: { color: '#b42318' } }, error) : null, items.length ? items.map((item, i) => h('article', { key: item.id || i, style: { border: '1px solid var(--dsw-color-border-subtle, #e4e7ec)', borderRadius: 6, padding: 12, margin: '8px 0' } }, h('strong', null, item.type || item.dimension || '静态机制'), h('span', { style: { marginLeft: 10, color: '#475467' } }, item.status || 'UNKNOWN'), h('div', { style: { marginTop: 5 } }, item.statement || item.mechanism || item.target || '未提供机制说明'), item.attack_mapping ? h('div', { style: { color: '#175cd3', fontSize: 13, marginTop: 5 } }, `ATT&CK: ${JSON.stringify(item.attack_mapping)}`) : null)) : h('p', null, empty))
    }
    module.exports.name = 'threat-ui-mechanisms-client'
    module.exports.inject = ['slots']
    module.exports.apply = (ctx) => ctx.slots.inject('conversation.view', () => ctx.slots.register({ name: 'conversation.view', id: 'threat-mechanisms', order: 40, label: 'Mechanisms' }, View))
    return module.exports
  },
})
