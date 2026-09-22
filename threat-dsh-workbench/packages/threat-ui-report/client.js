window.__ModuleLoader__.load({
  id: '@threat-dsh/ui-report',
  factory: (require) => {
    const module = { exports: {} }
    const React = require('react')
    const { useEffect, useRef, useState } = React
    const h = React.createElement
    const CONTEXT_PATH = '/api/v1/workbench/sessions/'
    const store = () => window.__THREAT_ANALYSIS_CONTEXT_STORE__
    // Resource requests are routed through the Store's guarded fetch( layer.
    const backend = () => window.__THREAT_BACKEND_URL__ || `${window.location.protocol}//${window.location.hostname}:8000`
    const emit = (type, detail) => window.dispatchEvent(new CustomEvent(type, { detail }))
    const rowsFrom = (document, type) => {
      const direct = (document?.modules || []).flatMap((module) => (module?.rows || []))
      const nested = direct.flatMap((row) => Array.isArray(row?.findings) ? row.findings : [])
      return [...direct, ...nested].filter((row) => !type || row.type === type)
    }
    const badge = (text, tone = 'neutral') => h('span', { style: { display: 'inline-block', padding: '3px 8px', borderRadius: 5, fontSize: 12, background: tone === 'good' ? '#dcfce7' : tone === 'bad' ? '#fee2e2' : '#eef2f6', color: tone === 'good' ? '#166534' : tone === 'bad' ? '#991b1b' : '#475467' } }, text || '-')
    const metric = (label, value) => h('div', { style: { padding: 12, border: '1px solid var(--dsw-color-border-subtle, #e4e7ec)', borderRadius: 6, minWidth: 120 } }, h('div', { style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary, #667085)' } }, label), h('strong', { style: { display: 'block', marginTop: 5, fontSize: 18 } }, String(value ?? '-')))
    // The Store wakes this view from the bounded session event stream. A
    // status projection is checked before the report request so an
    // in-progress task never exposes a partial document.
    const View = (props = {}) => {
      const [snapshot, setSnapshot] = useState(() => store()?.snapshot?.() || { context: { state: 'UNBOUND' } })
      const [report, setReport] = useState(null); const [error, setError] = useState('')
      const loadedRef = useRef(false)
    // Report UI only renders terminal task states: !['SUCCEEDED', 'FAILED', 'CANCELLED'].includes(lifecycle)
      useEffect(() => {
        const contextStore = store(); if (!contextStore) { setError('Threat Context Store 未加载'); return undefined }
        let alive = true
        loadedRef.current = false
        const load = async () => {
          try {
            const id = contextStore.taskId(); if (!id || loadedRef.current) return
            const status = await contextStore.request('status', `/api/v1/tasks/${encodeURIComponent(id)}/status`)
            const lifecycle = String(status?.lifecycle || status?.context?.state || '')
            if (!['SUCCEEDED', 'FAILED', 'CANCELLED', 'ANALYSIS_READY', 'ANALYSIS_FAILED', 'ANALYSIS_CANCELLED'].includes(lifecycle)) return
            const value = await contextStore.request('report', `/api/v1/workbench/tasks/${encodeURIComponent(id)}/report`)
            if (alive && value?.revision) { loadedRef.current = true; setReport(value); setError('') }
          }
          catch (e) { if (alive && e?.name !== 'AbortError') setError(e.message || String(e)) }
        }
        const stop = contextStore.subscribe(props, (next) => {
          if (!alive) return
          setSnapshot(next)
          if (!next.context?.active_task_id) {
            loadedRef.current = false
            setReport(null)
            return
          }
          if (!loadedRef.current) void load()
        })
        const offEvent = contextStore.onEvent?.((detail) => {
          if (!alive || detail?.sessionId !== contextStore.snapshot().sessionId) return
          const taskId = contextStore.taskId(); const eventTask = detail?.event?.task_id || detail?.event?.data?.task_id
          if (eventTask && taskId && String(eventTask) !== String(taskId)) return
          const eventType = String(detail?.event?.type || detail?.event?.event_type || detail?.event?.data?.source_type || '')
          if (/report[./-](ready|generated|recomposed|manually_edited|published|approved)$/.test(eventType)) loadedRef.current = false
          void load()
        })
        void load()
        return () => { alive = false; offEvent?.(); stop?.() }
      }, [props.sessionId])
      const context = snapshot.context || {}; const revision = report?.revision; const document = revision?.document || {}
      const leftoverMarkdown = String(revision?.markdown || report?.content || '').trim()
      const findings = rowsFrom(document, 'security_finding').slice(0, 15)
      const mechanisms = rowsFrom(document).filter((row) => row.type === 'mechanism_candidate' || row.type === 'verified_mechanism' || row.mechanism_id).slice(0, 24)
      const flow = rowsFrom(document).filter((row) => row.type === 'flow_step' || row.phase || row.semantic_phase).slice(0, 32)
      const assessment = rowsFrom(document).find((row) => row.type === 'analyst_assessment') || {}
      const manifest = rowsFrom(document).find((row) => row.analysis_coverage)
      const rawCoverage = document.analysis_coverage || manifest?.analysis_coverage || {}
      const coverage = { ...rawCoverage, overall: rawCoverage.overall ?? rawCoverage.score }
      const indicators = document.iocs || document.indicators || rowsFrom(document, 'ioc')
      const limitations = document.unknowns || document.limitations || rowsFrom(document, 'analysis_limitation').map((row) => row.detail).filter(Boolean)
      const executiveAssessment = assessment.summary || document.executive_assessment || document.executive_summary || '报告未提供执行摘要。'
      const download = (format) => revision?.id && window.open(`${backend()}/api/v1/reports/${encodeURIComponent(revision.id)}/download?format=${format}`, '_blank', 'noopener')
      if (!context.active_task_id) return h('section', { 'data-threat-view': 'report', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 980, margin: '0 auto', padding: 18 } }, h('h2', null, '分析报告'), h('p', { style: { color: '#667085' } }, context.state === 'ARTIFACT_READY' ? '样本已就绪，尚未开始静态分析。' : '当前会话尚未选择样本。'))
      if (!revision) return h('section', { 'data-threat-view': 'report', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 980, margin: '0 auto', padding: 18 } }, h('h2', null, '分析报告'), h('p', null, context.state === 'ANALYSIS_FAILED' ? '静态分析失败，暂无报告。' : '报告正在生成，页面会自动刷新。'), error ? h('p', { style: { color: '#b42318' } }, error) : null)
      const peRow = rowsFrom(document).find((row) => row.path || row.filename || row.display_name)
      const sampleName = document.sample_name || document.display_name || peRow?.path || peRow?.filename || peRow?.display_name || context.attached_artifacts?.[0]?.logical_path || '未知样本'
      const verifiedCount = document.verified_mechanism_count ?? coverage.verified_mechanism_count ?? mechanisms.filter((row) => String(row.status).toUpperCase() === 'VERIFIED').length
      const header = h('header', { style: { borderBottom: '1px solid var(--dsw-color-border-subtle, #e4e7ec)', paddingBottom: 14, marginBottom: 16 } }, h('div', { style: { display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'start' } }, h('div', null, h('h2', { style: { margin: 0 } }, '分析报告'), h('p', { style: { margin: '5px 0 0', color: '#667085' } }, `样本：${sampleName}`)), h('div', null, badge(revision.status || 'READY', 'good'), h('div', { style: { marginTop: 6, fontSize: 12, color: '#667085' } }, `Task ${context.active_task_id}`))), h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 14 } }, metric('Analysis Class', document.analysis_class || context.analysis_class || 'BOUNDED_STATIC_ANALYSIS'), metric('Static Coverage', coverage.overall ?? coverage.coverage ?? '-'), metric('Verified Mechanisms', verifiedCount), metric('Unknowns', document.unknown_count ?? '-'), metric('Revision', String(revision.id).slice(0, 12))))
      const exports = h('div', { style: { display: 'flex', gap: 8, marginBottom: 16 } }, h('button', { type: 'button', onClick: () => download('markdown') }, '导出 Markdown'), h('button', { type: 'button', onClick: () => download('docx') }, '导出 DOCX'), h('button', { type: 'button', onClick: () => download('pdf') }, '导出 PDF'))
      // Kunglao leftover dump: the immutable revision markdown is the one-round
      // report. Do not invent a second reconstructed report from document rows
      // when How / Unique OS / Unknowns are already written here.
      if (leftoverMarkdown) {
        return h('section', { 'data-threat-view': 'report', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 1080, margin: '0 auto', padding: 18, color: 'var(--dsw-alias-label-primary, #101828)' } },
          header, exports,
          h('article', { 'data-threat-report': 'leftover-dump', style: { whiteSpace: 'pre-wrap', lineHeight: 1.6, padding: 14, background: 'var(--dsw-color-bg-subtle, #f8fafc)', borderRadius: 6, overflowWrap: 'anywhere' } }, leftoverMarkdown),
        )
      }
      return h('section', { 'data-threat-view': 'report', style: { fontFamily: 'system-ui, sans-serif', maxWidth: 1080, margin: '0 auto', padding: 18, color: 'var(--dsw-alias-label-primary, #101828)' } },
        header, exports,
        h('article', { style: { padding: 14, background: 'var(--dsw-color-bg-subtle, #f8fafc)', borderRadius: 6, marginBottom: 16 } }, h('h3', { style: { marginTop: 0 } }, 'Executive Assessment'), h('p', { style: { whiteSpace: 'pre-wrap', lineHeight: 1.6 } }, executiveAssessment)),
        h('h3', null, `关键发现 (${findings.length})`), findings.length ? findings.map((finding, index) => h('article', { key: finding.finding_id || index, style: { border: '1px solid var(--dsw-color-border-subtle, #e4e7ec)', borderRadius: 6, padding: 14, margin: '8px 0' } }, h('div', { style: { display: 'flex', justifyContent: 'space-between', gap: 8 } }, h('strong', null, finding.title || finding.what || `Finding ${index + 1}`), badge(finding.verdict || 'SUPPORTED', String(finding.verdict).toUpperCase() === 'SUPPORTED' ? 'good' : 'neutral')), h('p', null, finding.what || finding.statement || ''), finding.how ? h('p', null, h('strong', null, 'How: '), finding.how) : null, finding.security_meaning ? h('p', null, h('strong', null, 'Security meaning: '), finding.security_meaning) : null, finding.boundary ? h('p', { style: { color: '#667085' } }, h('strong', null, 'Boundary: '), finding.boundary) : null, h('div', { style: { display: 'flex', gap: 8, flexWrap: 'wrap' } }, finding.mechanism_id && h('button', { type: 'button', onClick: () => emit('threat:ask-agent', { mechanism_id: finding.mechanism_id, finding_id: finding.finding_id, session_id: snapshot.sessionId }) }, 'Ask Agent'), (finding.evidence_ids || []).map((id) => h('button', { key: id, type: 'button', onClick: () => emit('threat:open-evidence', { evidence_id: id, session_id: snapshot.sessionId }) }, `Evidence ${id}`))))) : h('p', null, '暂无证据支撑的正式发现。'),
        h('h3', null, `Mechanisms / Candidates (${mechanisms.length})`), mechanisms.length ? mechanisms.map((item, index) => h('div', { key: item.mechanism_id || item.id || index, style: { padding: '9px 0', borderBottom: '1px solid #eef0f2' } }, h('strong', null, item.title || item.target || item.mechanism || `Mechanism ${index + 1}`), h('span', { style: { marginLeft: 8 } }, badge(item.status || 'CANDIDATE', String(item.status).toUpperCase() === 'VERIFIED' ? 'good' : 'neutral')), item.evidence_ids?.length ? h('div', { style: { color: '#175cd3', fontSize: 13, marginTop: 4 } }, `Evidence: ${item.evidence_ids.join(', ')}`) : null)) : h('p', null, '暂无机制投影。'),
        h('h3', null, 'Reconstructed Static Behavior Flow'), h('p', { style: { color: '#667085' } }, '由静态控制流和数据流证据重建，不代表运行时观测。'), flow.length ? h('ol', null, flow.map((item, index) => h('li', { key: item.id || index, style: { margin: '6px 0' } }, item.title || item.phase || item.semantic_phase || item.statement || item.message || JSON.stringify(item)))) : h('p', null, '暂无行为流。'),
        h('h3', null, 'IOC / Indicators'), indicators.length ? indicators.slice(0, 64).map((item, index) => h('div', { key: index, style: { padding: '8px 0', overflowWrap: 'anywhere', borderBottom: '1px solid #eef0f2' } }, h('strong', null, `${item.category || item.type || 'Indicator'}: `), String(item.value ?? item), item.evidence_ids?.length ? h('div', { style: { fontSize: 12, color: '#667085' } }, `Evidence: ${item.evidence_ids.join(', ')}`) : null)) : h('p', null, '暂无已提取指标。'),
        h('h3', null, 'Unknowns / Static Boundaries'), h('ul', null, limitations.map((item, index) => h('li', { key: index }, typeof item === 'string' ? item : JSON.stringify(item)))),
      )
    }
    module.exports.name = 'threat-ui-report-client'
    module.exports.inject = ['slots']
    module.exports.apply = (ctx) => ctx.slots.inject('conversation.view', () => ctx.slots.register({ name: 'conversation.view', id: 'threat-report', order: 70, label: 'Report' }, View))
    return module.exports
  },
})
