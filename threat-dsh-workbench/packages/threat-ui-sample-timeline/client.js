window.__ModuleLoader__.load({
  id: '@threat-dsh/ui-sample-timeline',
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
      const [items, setItems] = useState([])
      useEffect(() => {
        const contextStore = store(); if (!contextStore) return undefined
        let alive = true
        const stop = contextStore.subscribe(props, (next) => { if (!alive) return; setSnapshot(next); if (!next.context?.active_task_id) setItems([]) })
        const load = async () => {
          const id = contextStore.taskId(); if (!id) return
          try { const value = await contextStore.request('sample-timeline', `/api/v1/workbench/tasks/${encodeURIComponent(id)}/sample-timeline`); if (alive && value) setItems(value.items || []) } catch {}
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
      const empty = context.state === 'UNBOUND' ? '当前会话尚未选择样本。' : context.state === 'ARTIFACT_READY' ? '样本已就绪，尚未开始静态分析。' : '暂无重建的静态行为流事件'
      return h('section', { 'data-threat-view': 'sample-timeline', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 980, margin: '0 auto', padding: 18, color: 'var(--dsw-alias-label-primary, #101828)' } }, h('h2', null, 'Static Behavior Flow'), h('p', { style: { color: 'var(--dsw-alias-label-secondary, #667085)' } }, '由静态控制流和数据流证据重建，不代表运行时观测。'), items.length ? items.map((item, i) => h('div', { key: item.id || i, style: { display: 'grid', gridTemplateColumns: '120px 1fr', gap: 10, padding: '9px 0', borderBottom: '1px solid var(--dsw-color-border-subtle, #eaecf0)' } }, h('strong', null, item.phase || item.order || i + 1), h('span', null, item.statement || item.message || item.action || JSON.stringify(item)))) : h('p', null, empty))
    }
    module.exports.name = 'threat-ui-sample-timeline-client'
    module.exports.inject = ['slots']
    module.exports.apply = (ctx) => ctx.slots.inject('conversation.view', () => ctx.slots.register({ name: 'conversation.view', id: 'threat-sample-timeline', order: 50, label: 'Static Behavior Flow' }, View))
    return module.exports
  },
})
