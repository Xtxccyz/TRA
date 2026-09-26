import assert from 'node:assert/strict'
import test from 'node:test'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply } from '../packages/threat-tool-provider/src/index.ts'

test('report summary is lossless JSON when optional backend fields are absent', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  globalThis.fetch = async (input) => Response.json(String(input).endsWith('/analysis-context')
    ? { active_task_id: 'task-1', state: 'ANALYSIS_READY' }
    : { revision: { id: 'revision-1', markdown: '# Static report' }, report_available: true })
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_get_report_summary').execute({},
      { agent: { session: { id: 'session-1' } } })
    assert.deepEqual(result, JSON.parse(JSON.stringify(result)))
    assert.equal(result.content, '# Static report')
    assert.equal(result.report_revision_id, 'revision-1')
    assert.equal(result.authoritative_revision_id, 'revision-1')
    assert.match(String(result.citation_instruction), /revision-1/)
    assert.match(String(result.citation_instruction), /MUST quote/)
  } finally { globalThis.fetch = originalFetch }
})

test('report summary stays empty while the bound task is still running', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    urls.push(String(input))
    return Response.json({ active_task_id: 'task-new', state: 'ANALYSIS_RUNNING', task_lifecycle: 'RUNNING' })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_get_report_summary').execute({},
      { agent: { session: { id: 'session-1' } } })
    assert.equal(result.report_available, false)
    assert.equal(result.code, 'ANALYSIS_IN_PROGRESS')
    assert.equal(result.content, undefined)
    assert.equal(result.authoritative_revision_id, undefined)
    assert.ok(!urls.some((url) => url.includes('/report')))
  } finally { globalThis.fetch = originalFetch }
})

test('report summary requires citing the GET report revision UUID', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const revisionId = '75215cce-1111-4222-8333-444455556666'
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    urls.push(String(input))
    if (String(input).endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-1', state: 'ANALYSIS_READY', task_lifecycle: 'SUCCEEDED' })
    }
    return Response.json({
      task_id: 'task-1',
      revision: { id: revisionId, markdown: '# Official GET report', status: 'PARTIAL' },
    })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_get_report_summary').execute({},
      { agent: { session: { id: 'session-1' } } })
    assert.equal(result.authoritative_revision_id, revisionId)
    assert.equal(result.report_revision_id, revisionId)
    assert.match(String(result.citation_instruction), new RegExp(revisionId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    assert.match(String(result.citation_instruction), /MUST quote/)
    assert.match(String(result.citation_instruction), /Do not summarize from memory/)
    assert.match(String(result.citation_instruction), /Do not ask 再深入/)
    assert.match(String(result.citation_instruction), /Do not call threat_propose_static_action/)
    assert.equal(result.stop_dispatch, true)
    assert.equal(result.convergence, 'CONVERGED')
    assert.ok(urls.some((url) => url.includes('/api/v1/workbench/tasks/task-1/report')))
  } finally { globalThis.fetch = originalFetch }
})

test('report summary keeps the full official markdown, not a 1200-char compact slice', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const how = 'CreateProcessW command=cmd.exe /c FoxitPDFReader.exe creation_flags=0x000f4240'
  const markdown = `${'# Official GET report\n\n'}${'A'.repeat(1600)}\n\n## How\n${how}\n`
  globalThis.fetch = async (input) => Response.json(String(input).endsWith('/analysis-context')
    ? { active_task_id: 'task-1', state: 'ANALYSIS_READY', task_lifecycle: 'SUCCEEDED' }
    : { revision: { id: 'revision-long', markdown }, report_available: true })
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_get_report_summary').execute({},
      { agent: { session: { id: 'session-1' } } })
    assert.equal(result.content, markdown)
    assert.ok(String(result.content).includes(how))
    assert.equal(String(result.content).includes('[compacted]'), false)
    assert.match(String(result.citation_instruction), /full content/)
    const tool = registered.get('threat_get_report_summary')
    const rendered = tool.output.render({}, result)
    const renderedText = String(rendered[0]?.text ?? '')
    assert.ok(renderedText.includes(how))
    assert.equal(renderedText.includes('[compacted]'), false)
    const view = tool.presentResult({}, { content: rendered, isError: false })
    assert.equal(view.title, 'Official behavior report revision-long')
    assert.match(String(view.content?.[0]?.text ?? ''), /^# Official GET report/)
    assert.ok(String(view.content?.[0]?.text ?? '').includes(how))
  } finally { globalThis.fetch = originalFetch }
})

test('report leftover dump shows 分析结论 and hides the investigation appendix', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const markdown = [
    '# 静态分析报告',
    '',
    '## 分析结论',
    '',
    'TLS 回调已恢复。',
    '',
    '## 调查附录（内部账本，非分析结论）',
    '',
    '## Investigation Seed Map',
    '',
    '- pipeline completion: {"score": 100}',
  ].join('\n')
  globalThis.fetch = async (input) => Response.json(String(input).endsWith('/analysis-context')
    ? { active_task_id: 'task-1', state: 'ANALYSIS_READY', task_lifecycle: 'SUCCEEDED' }
    : { revision: { id: 'revision-analyst', markdown }, report_available: true })
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_get_report_summary').execute({},
      { agent: { session: { id: 'session-1' } } })
    assert.equal(result.content, markdown)
    assert.match(String(result.citation_instruction), /分析结论/)
    const tool = registered.get('threat_get_report_summary')
    const rendered = tool.output.render({}, result)
    const view = tool.presentResult({}, { content: rendered, isError: false })
    const shown = String(view.content?.[0]?.text ?? '')
    assert.ok(shown.includes('TLS 回调已恢复'))
    assert.equal(shown.includes('Investigation Seed Map'), false)
    assert.equal(shown.includes('pipeline completion'), false)
  } finally { globalThis.fetch = originalFetch }
})

test('report leftover dump shows the full official markdown when there is no investigation appendix', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const markdown = [
    '# 静态分析报告',
    '',
    '## 分析结论',
    '',
    '同进程 CreateThread 入口 0x1800011c0。',
    '',
    '机制闭合率按验证器门限计算：13 条机制候选中 1 条达到门限（约 8%）。',
  ].join('\n')
  globalThis.fetch = async (input) => Response.json(String(input).endsWith('/analysis-context')
    ? { active_task_id: 'task-1', state: 'ANALYSIS_READY', task_lifecycle: 'SUCCEEDED' }
    : { revision: { id: 'revision-official-only', markdown }, report_available: true })
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_get_report_summary').execute({},
      { agent: { session: { id: 'session-1' } } })
    assert.equal(result.content, markdown)
    const tool = registered.get('threat_get_report_summary')
    const rendered = tool.output.render({}, result)
    const view = tool.presentResult({}, { content: rendered, isError: false })
    const shown = String(view.content?.[0]?.text ?? '')
    assert.ok(shown.includes('0x1800011c0'))
    assert.ok(shown.includes('约 8%'))
    assert.equal(shown.includes('Investigation Seed Map'), false)
  } finally { globalThis.fetch = originalFetch }
})

test('wait tool returns a heartbeat instead of event rows and full context', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    urls.push(String(input))
    return Response.json({
      wait_status: 'updated',
      must_continue_waiting: true,
      next_after_event_seq: 64,
      instruction: 'Task is still ANALYSIS_RUNNING. Call threat_wait_for_analysis_update again with after_event_seq=64.',
      changed: true,
      context: { state: 'ANALYSIS_RUNNING', investigation_frontier: { open_questions: ['x'.repeat(4000)] } },
      events: Array.from({ length: 64 }, (_, index) => ({ seq: index + 1, type: 'evidence.recorded', payload_summary: { evidence_ids: [`e-${index}`] } })),
      progress: { state: 'ANALYSIS_RUNNING', stage: 'evidence.recorded', new_evidence_since_last: 64, last_event_seq: 64 },
    })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_wait_for_analysis_update').execute(
      { after_event_seq: 0, timeout_seconds: 120 },
      { agent: { session: { id: 'session-1' } } })
    assert.equal(result.must_continue_waiting, true)
    assert.equal(result.next_after_event_seq, 64)
    assert.equal(result.events, undefined)
    assert.equal(result.context, undefined)
    assert.deepEqual(result, JSON.parse(JSON.stringify(result)))
    assert.equal(JSON.stringify(result).includes('e-1'), false)
    assert.ok(JSON.stringify(result).length < 2000)
    assert.equal(result.convergence, 'SATURATED')
    assert.equal(result.content, undefined)
    assert.ok(!urls.some((url) => url.includes('/report')))
    const waitTool = registered.get('threat_wait_for_analysis_update')
    const view = waitTool.presentResult({}, { content: waitTool.output.render({}, result), isError: false })
    assert.equal(view.title, undefined)
    assert.equal(view.content, undefined)
  } finally { globalThis.fetch = originalFetch }
})

test('wait CONVERGED leftover dump includes the full official markdown', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const how = 'CreateProcessW command=cmd.exe /c FoxitPDFReader.exe creation_flags=0x000f4240'
  const markdown = `${'# Official GET report\n\n'}${'A'.repeat(1600)}\n\n## How\n${how}\n`
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    const url = String(input)
    urls.push(url)
    if (url.includes('/analysis/wait')) {
      return Response.json({
        wait_status: 'updated',
        must_continue_waiting: false,
        next_after_event_seq: 88,
        convergence: 'CONVERGED',
        instruction: 'CONVERGED: task is terminal. Call threat_get_report_summary.',
        context: { state: 'ANALYSIS_READY' },
        progress: { state: 'ANALYSIS_READY', last_event_seq: 88 },
      })
    }
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-1', state: 'ANALYSIS_READY', task_lifecycle: 'SUCCEEDED' })
    }
    return Response.json({
      task_id: 'task-1',
      revision: { id: 'revision-wait', markdown },
      report_available: true,
    })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const tool = registered.get('threat_wait_for_analysis_update')
    const result = await tool.execute(
      { after_event_seq: 0, timeout_seconds: 120 },
      { agent: { session: { id: 'session-wait-dump' } } })
    assert.equal(result.convergence, 'CONVERGED')
    assert.equal(result.stop_dispatch, true)
    assert.equal(result.authoritative_revision_id, 'revision-wait')
    assert.equal(result.content, markdown)
    assert.ok(String(result.content).includes(how))
    assert.equal(String(result.content).includes('[compacted]'), false)
    assert.match(String(result.instruction), /Do not ask 再深入/)
    assert.ok(urls.some((url) => url.includes('/api/v1/workbench/tasks/task-1/report')))
    const rendered = tool.output.render({}, result)
    const renderedText = String(rendered[0]?.text ?? '')
    assert.ok(renderedText.includes(how))
    assert.equal(renderedText.includes('[compacted]'), false)
    const view = tool.presentResult({}, { content: rendered, isError: false })
    assert.equal(view.title, 'Official behavior report revision-wait')
    assert.match(String(view.content?.[0]?.text ?? ''), /^# Official GET report/)
    assert.ok(String(view.content?.[0]?.text ?? '').includes(how))
  } finally { globalThis.fetch = originalFetch }
})

test('wait CONVERGED leftover dump uses backend content without a second report fetch', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const how = 'CreateProcessW command=cmd.exe /c FoxitPDFReader.exe creation_flags=0x000f4240'
  const markdown = `${'# Official GET report\n\n'}${'A'.repeat(1600)}\n\n## How\n${how}\n`
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    urls.push(String(input))
    return Response.json({
      wait_status: 'updated',
      must_continue_waiting: false,
      next_after_event_seq: 91,
      convergence: 'CONVERGED',
      instruction: 'CONVERGED leftover dump is in content.',
      task_id: 'task-1',
      authoritative_revision_id: 'revision-wait-inline',
      report_revision_id: 'revision-wait-inline',
      content: markdown,
      context: { state: 'ANALYSIS_READY', active_task_id: 'task-1' },
      progress: { state: 'ANALYSIS_READY', last_event_seq: 91 },
    })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_wait_for_analysis_update').execute(
      { after_event_seq: 0, timeout_seconds: 120 },
      { agent: { session: { id: 'session-wait-inline' } } })
    assert.equal(result.convergence, 'CONVERGED')
    assert.equal(result.stop_dispatch, true)
    assert.equal(result.content, markdown)
    assert.equal(result.authoritative_revision_id, 'revision-wait-inline')
    assert.ok(String(result.content).includes(how))
    assert.equal(String(result.content).includes('[compacted]'), false)
    assert.match(String(result.citation_instruction), /Do not ask 再深入/)
    assert.ok(!urls.some((url) => url.includes('/report')))
    assert.ok(!urls.some((url) => url.includes('/analysis-context')))
  } finally { globalThis.fetch = originalFetch }
})

test('wait timeout is not CONVERGED, POLICY_DENIED, STATIC_BOUNDARY, or a leftover report', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    urls.push(String(input))
    return Response.json({
      wait_status: 'timed_out',
      must_continue_waiting: true,
      next_after_event_seq: 12,
      convergence: 'SATURATED',
      instruction: 'SATURATED: task is still ANALYSIS_RUNNING. Call wait again.',
    })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_wait_for_analysis_update').execute(
      { after_event_seq: 0, timeout_seconds: 30 },
      { agent: { session: { id: 'session-wait-timeout' } } })
    assert.equal(result.wait_status, 'timed_out')
    assert.equal(result.must_continue_waiting, true)
    assert.notEqual(result.convergence, 'CONVERGED')
    assert.equal(result.stop_dispatch, undefined)
    assert.equal(result.content, undefined)
    assert.doesNotMatch(JSON.stringify(result), /STATIC_BOUNDARY/)
    assert.doesNotMatch(JSON.stringify(result), /POLICY_DENIED/)
    assert.ok(!urls.some((url) => url.includes('/report')))
  } finally { globalThis.fetch = originalFetch }
})

test('wait tool owns the cursor and will not rewind after_seq to 0', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    urls.push(String(input))
    return Response.json({
      wait_status: 'timed_out',
      must_continue_waiting: true,
      next_after_event_seq: 64,
      convergence: 'SATURATED',
      instruction: 'SATURATED',
    })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const tool = registered.get('threat_wait_for_analysis_update')
    const session = { agent: { session: { id: 'session-wait-cursor' } } }
    await tool.execute({ after_event_seq: 0, timeout_seconds: 30 }, session)
    await tool.execute({ after_event_seq: 0, timeout_seconds: 30 }, session)
    assert.match(urls[0], /after_seq=0/)
    assert.match(urls[1], /after_seq=64/)
  } finally { globalThis.fetch = originalFetch }
})

const decompileProposal = {
  action_type: 'GET_DECOMPILE',
  target_artifact_id: 'artifact-1',
  reason: 'Recover the selected function body.',
  question: 'What does the selected function do?',
  hypothesis: 'The selected function may decode and resolve APIs.',
  alternatives: ['The selected function is unrelated setup.'],
  missing_evidence: ['function_semantic_summary'],
  failure_meaning: 'The selected function remains unresolved.',
  failure_interpretation: 'NO_NEW_EVIDENCE',
  target_selector: { function_entry: '0x401000' },
  expected_evidence_kinds: ['function_semantic_summary'],
}

test('after terminal report summary, further propose_static_action is forbidden', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const urls: string[] = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    urls.push(`${init?.method || 'GET'} ${url}`)
    if (url.endsWith('/analysis-context')) {
      return Response.json({
        active_task_id: 'task-1',
        state: 'ANALYSIS_READY',
        task_lifecycle: 'SUCCEEDED',
      })
    }
    if (url.includes('/report')) {
      return Response.json({
        task_id: 'task-1',
        revision: { id: 'revision-stop', markdown: '# Official GET report\n\nconsumer UNKNOWN' },
        report_available: true,
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const exec = { agent: { session: { id: 'session-stop-summary' } } }
    const summary = await registered.get('threat_get_report_summary').execute({}, exec)
    assert.equal(summary.authoritative_revision_id, 'revision-stop')
    assert.equal(summary.stop_dispatch, true)
    const proposed = await registered.get('threat_propose_static_action').execute(decompileProposal, exec)
    assert.equal(proposed.accepted, false)
    assert.equal(proposed.code, 'STOP_DISPATCH')
    assert.equal(proposed.convergence, 'CONVERGED')
    assert.equal(proposed.stop_dispatch, true)
    assert.match(String(proposed.instruction), /Do not read task_gaps to propose GET_DECOMPILE/)
    assert.match(String(proposed.instruction), /Do not write to the desktop/)
    assert.equal(urls.some((url) => url.includes('POST') && url.includes('/analysis/actions')), false)
  } finally { globalThis.fetch = originalFetch }
})

test('CONVERGED wait latches STOP_DISPATCH so propose_static_action is forbidden', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const urls: string[] = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    urls.push(`${init?.method || 'GET'} ${url}`)
    if (url.includes('/analysis/wait')) {
      return Response.json({
        wait_status: 'updated',
        must_continue_waiting: false,
        next_after_event_seq: 12,
        convergence: 'CONVERGED',
        instruction: 'CONVERGED leftover dump is in content.',
        task_id: 'task-1',
        authoritative_revision_id: 'revision-wait-stop',
        report_revision_id: 'revision-wait-stop',
        content: '# Official GET report',
      })
    }
    if (url.endsWith('/analysis-context')) {
      return Response.json({
        active_task_id: 'task-1',
        state: 'ANALYSIS_RUNNING',
        task_lifecycle: 'RUNNING',
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const exec = { agent: { session: { id: 'session-stop-wait' } } }
    const waited = await registered.get('threat_wait_for_analysis_update').execute(
      { after_event_seq: 0, timeout_seconds: 120 }, exec)
    assert.equal(waited.convergence, 'CONVERGED')
    const proposed = await registered.get('threat_propose_static_action').execute(decompileProposal, exec)
    assert.equal(proposed.accepted, false)
    assert.equal(proposed.code, 'STOP_DISPATCH')
    assert.equal(urls.some((url) => url.includes('POST') && url.includes('/analysis/actions')), false)
  } finally { globalThis.fetch = originalFetch }
})

test('RUNNING task still accepts propose_static_action', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const urls: string[] = []
  let posted: Record<string, unknown> | undefined
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    urls.push(`${init?.method || 'GET'} ${url}`)
    if (url.endsWith('/analysis-context')) {
      return Response.json({
        active_task_id: 'task-running',
        state: 'ANALYSIS_RUNNING',
        task_lifecycle: 'RUNNING',
      })
    }
    if (String(init?.method || '').toUpperCase() === 'POST' && url.includes('/analysis/actions')) {
      posted = JSON.parse(String(init?.body || '{}'))
      return Response.json({ id: 'action-running', accepted: true })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_propose_static_action').execute(
      decompileProposal, { agent: { session: { id: 'session-running-propose' } } })
    assert.equal(result.accepted, true)
    assert.equal(result.id, 'action-running')
    assert.equal(posted?.action_type, 'GET_DECOMPILE')
    assert.ok(urls.some((url) => url.includes('POST') && url.includes('/analysis/actions')))
  } finally { globalThis.fetch = originalFetch }
})

test('model action schema exposes every backend plan-first requirement', () => {
  const registered = new Map<string, any>()
  apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
    { backendUrl: 'http://localhost:8000' })
  const tool = registered.get('threat_propose_static_action')
  for (const field of ['question', 'hypothesis', 'alternatives', 'missing_evidence', 'failure_meaning', 'evidence_ids']) {
    assert.ok(tool.parameters.properties[field], `Missing model-visible field: ${field}`)
  }
})

test('model action payload coerces prose failure_interpretation to a catalog token', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  let posted: Record<string, unknown> | undefined
  globalThis.fetch = async (_input, init) => {
    posted = JSON.parse(String(init?.body || '{}'))
    return Response.json({ id: 'action-1', accepted: true })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    await registered.get('threat_propose_static_action').execute({
      action_type: 'GET_DECOMPILE',
      target_artifact_id: 'artifact-1',
      reason: 'Recover the selected function body.',
      question: 'What does the selected function do?',
      hypothesis: 'The selected function may decode and resolve APIs.',
      alternatives: ['The selected function is unrelated setup.'],
      missing_evidence: ['function_semantic_summary'],
      failure_meaning: 'The selected function remains unresolved.',
      failure_interpretation: 'NO_NEW_EVIDENCE 或空集 → 改查 GET_DECOMPILE',
      target_selector: { function_entry: '0x401000' },
      expected_evidence_kinds: ['function_semantic_summary'],
    }, { agent: { session: { id: 'session-1' } } })
    assert.equal(posted?.failure_interpretation, 'NO_NEW_EVIDENCE')
    assert.match(String(posted?.failure_meaning || ''), /GET_DECOMPILE/)
  } finally { globalThis.fetch = originalFetch }
})

test('model action payload aliases function_name/length and truncates success_condition', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  let posted: Record<string, unknown> | undefined
  globalThis.fetch = async (_input, init) => {
    posted = JSON.parse(String(init?.body || '{}'))
    return Response.json({ id: 'action-1', accepted: true })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    await registered.get('threat_propose_static_action').execute({
      action_type: 'READ_BYTES',
      target_artifact_id: 'artifact-1',
      reason: 'Read the selected encoded window.',
      question: 'What bytes sit at the selected encoded window?',
      hypothesis: 'The selected window may be a bounded decode input.',
      alternatives: ['The window is unrelated padding.'],
      missing_evidence: ['bytes_read'],
      failure_meaning: 'The selected window remains unread.',
      success_condition: 'x'.repeat(180),
      target_selector: { function_name: 'FUN_180001000', length: 64, mystery: 'drop-me' },
      expected_evidence_kinds: ['bytes_read'],
    }, { agent: { session: { id: 'session-1' } } })
    const selector = posted?.target_selector as Record<string, unknown>
    assert.equal(selector.function, 'FUN_180001000')
    assert.equal(selector.length, 64)
    assert.equal(selector.function_name, undefined)
    assert.equal(selector.mystery, undefined)
    assert.equal(String(posted?.success_condition || '').length, 160)
  } finally { globalThis.fetch = originalFetch }
})

test('analysis planner model tools are not registered separately from DSH chat', () => {
  const registered = new Map<string, any>()
  apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
    { backendUrl: 'http://localhost:8000' })
  assert.equal(registered.get('threat_get_analysis_planner_model'), undefined)
  assert.equal(registered.get('threat_configure_analysis_planner_model'), undefined)
  assert.ok(registered.get('threat_propose_static_action'))
  assert.ok(registered.get('threat_read_session_notes'))
  assert.ok(registered.get('threat_write_session_note'))
  assert.ok(registered.get('threat_workbench_model_complete'))
  assert.equal(registered.get('read'), undefined)
  assert.equal(registered.get('write'), undefined)
  assert.equal(registered.get('bash'), undefined)
  assert.equal(registered.get('pwsh'), undefined)
})

test('session notes persist under DSH_HOME and reject path-escape session ids', async () => {
  const registered = new Map<string, any>()
  const previousHome = process.env.DSH_HOME
  const home = await mkdtemp(join(tmpdir(), 'threat-notes-'))
  process.env.DSH_HOME = home
  apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
    { backendUrl: 'http://localhost:8000' })
  try {
    const exec = { agent: { session: { id: 'session-notes-1' } } }
    const written = await registered.get('threat_write_session_note').execute({ note: 'frontier: decode window' }, exec)
    assert.equal(written.accepted, true)
    assert.deepEqual(written.items, ['frontier: decode window'])
    const read = await registered.get('threat_read_session_notes').execute({}, exec)
    assert.deepEqual(read.items, ['frontier: decode window'])
    const escaped = await registered.get('threat_write_session_note').execute(
      { note: 'nope' }, { agent: { session: { id: '../etc' } } })
    assert.equal(escaped.accepted, false)
    assert.equal(escaped.code, 'DSH_HOME_REQUIRED')
  } finally {
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    await rm(home, { recursive: true, force: true })
  }
})

test('workbench model complete fills bound session identity and does not take a provider', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const posts: Array<{ url: string; body: Record<string, unknown> }> = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {}
    if (init?.method === 'POST') posts.push({ url, body })
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-1', case_id: '11111111-1111-1111-1111-111111111111', state: 'ANALYSIS_READY' })
    }
    return Response.json({ status: 'SUCCEEDED', content: '{"plan":"ok"}', model_call_id: 'call-1', provider: 'deepseek' })
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_workbench_model_complete').execute(
      { question: 'What decode window remains open?', operation: 'planning' },
      { agent: { session: { id: 'session-1' } } })
    assert.equal(result.status, 'SUCCEEDED')
    assert.equal(posts.length, 1)
    assert.match(posts[0].url, /\/api\/v1\/workbench\/model\/complete$/)
    assert.equal(posts[0].body.session_id, 'session-1')
    assert.equal(posts[0].body.task_id, 'task-1')
    assert.equal(posts[0].body.case_id, '11111111-1111-1111-1111-111111111111')
    assert.equal(posts[0].body.operation, 'planning')
    assert.equal(posts[0].body.provider, undefined)
    // The first message is the versioned protocol; the question is the user turn.
    const messages = posts[0].body.messages as { role: string; content: string }[]
    assert.equal(messages[0].role, 'system')
    assert.match(messages[0].content, /first-request-autonomous-deep-dive/)
    assert.equal(messages[1].role, 'user')
    assert.equal(messages[1].content, 'What decode window remains open?')
  } finally { globalThis.fetch = originalFetch }
})

test('workbench model complete classifies a provider 402 as model/transport, never a product result', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  globalThis.fetch = async (input) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-402', case_id: '11111111-1111-1111-1111-111111111111', state: 'ANALYSIS_READY' })
    }
    if (url.endsWith('/model/complete')) {
      return Response.json({
        status: 'FAILED',
        run_id: 'run-402',
        model_call_id: 'call-402',
        attempts: [{
          provider: 'deepseek', model: 'deepseek-v4-pro', status: 'FAILED',
          error_type: 'HTTPStatusError', http_status: 402,
          error_detail: 'Insufficient Balance', latency_ms: 33,
        }],
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_workbench_model_complete').execute(
      { question: 'Does the decoder reach the loader?', operation: 'planning' },
      { agent: { session: { id: 'session-402' } } })
    assert.equal(result.status, 'FAILED')
    assert.equal(result.failure_kind, 'MODEL_402_PAYMENT_REQUIRED')
    assert.equal(result.failure_class.kind, 'MODEL_402_PAYMENT_REQUIRED')
    assert.equal(result.failure_class.http_status, 402)
    assert.equal(result.failure_class.distinct_from_static_boundary, true)
    assert.equal(result.not_an_analysis_result, true)
    assert.equal(result.model_or_transport, true)
    assert.equal(result.content, undefined)
    assert.notEqual(result.state, 'STATIC_BOUNDARY')
    assert.notEqual(result.state, 'POLICY_DENIED')
    assert.match(String(result.user_action), /模型/)
  } finally { globalThis.fetch = originalFetch }
})

test('workbench model complete refuses a blank provider reply instead of reporting a completion', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  globalThis.fetch = async (input) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-empty', case_id: '11111111-1111-1111-1111-111111111111', state: 'ANALYSIS_READY' })
    }
    if (url.endsWith('/model/complete')) {
      return Response.json({
        status: 'SUCCEEDED', provider: 'deepseek', model: 'deepseek-v4-pro',
        model_call_id: 'call-empty', content: '   ',
        usage: { input_tokens: 7378, output_tokens: 2048 },
        attempts: [{ provider: 'deepseek', model: 'deepseek-v4-pro', status: 'SUCCEEDED', latency_ms: 22000 }],
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_workbench_model_complete').execute(
      { question: 'Summarise the recovered consumer.', operation: 'claims' },
      { agent: { session: { id: 'session-empty' } } })
    assert.equal(result.accepted, false)
    assert.equal(result.content, undefined)
    assert.equal(result.failure_kind, 'MODEL_EMPTY_REPLY')
    assert.equal(result.not_an_analysis_result, true)
    assert.equal(result.model_or_transport, true)
    assert.notEqual(result.state, 'STATIC_BOUNDARY')
  } finally { globalThis.fetch = originalFetch }
})

test('workbench model complete sends the versioned first-request protocol as the effective instruction', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const posts: Array<{ body: Record<string, unknown> }> = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-protocol', case_id: '11111111-1111-1111-1111-111111111111', state: 'ANALYSIS_READY' })
    }
    if (init?.method === 'POST') {
      posts.push({ body: JSON.parse(String(init.body)) as Record<string, unknown> })
      return Response.json({ status: 'SUCCEEDED', content: '{"plan":"ok"}', model_call_id: 'call-protocol', provider: 'deepseek' })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    const sdk = await import('../packages/threat-plugin-sdk/src/index.ts') as Record<string, any>
    const protocol = sdk.firstRequestInvestigationProtocol()
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const question = 'Which investigation thread does the decoded buffer feed?'
    await registered.get('threat_workbench_model_complete').execute(
      { question, operation: 'planning' }, { agent: { session: { id: 'session-protocol' } } })
    assert.equal(posts.length, 1)
    const body = posts[0].body
    assert.equal(body.prompt_id, 'dsh-workbench-complete')
    assert.equal(body.prompt_version, protocol.version)
    assert.match(String(body.prompt_version), /^\d+\.\d+\.\d+$/)
    assert.equal(body.prompt_sha256, protocol.digest)
    assert.match(String(body.prompt_sha256), /^[0-9a-f]{64}$/)
    assert.notEqual(body.prompt_sha256, undefined)
    const messages = body.messages as { role: string; content: string }[]
    assert.equal(messages.length, 2)
    assert.equal(messages[0].role, 'system')
    assert.equal(messages[0].content, protocol.system_instruction)
    assert.equal(messages[1].role, 'user')
    assert.equal(messages[1].content, question)
    for (const token of ['initiator', 'failure_fallback', 'competing hypothes', 'investigation thread', 'NO_NEW_EVIDENCE', 'frontier']) {
      assert.match(messages[0].content, new RegExp(token, 'i'), `protocol instruction must cover ${token}`)
    }
    // Prompt identity must identify the instruction that took effect, not a hash of the question.
    assert.notEqual(body.prompt_sha256, createHash('sha256').update(question).digest('hex'))
  } finally { globalThis.fetch = originalFetch }
})

test('a model/transport failure cannot be recorded as STATIC_BOUNDARY in the action contract', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const actionBodies: Record<string, unknown>[] = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-boundary', case_id: '11111111-1111-1111-1111-111111111111', state: 'ANALYSIS_RUNNING', task_lifecycle: 'RUNNING' })
    }
    if (url.endsWith('/analysis/actions') && init?.method === 'POST') {
      actionBodies.push(JSON.parse(String(init.body)) as Record<string, unknown>)
      return Response.json({ accepted: true, action_id: 'action-1' })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    await registered.get('threat_propose_static_action').execute({
      action_type: 'GET_DECOMPILE',
      target_artifact_id: 'artifact-1',
      reason: 'read the entry function body',
      question: 'What does the entry stub resolve before it jumps?',
      hypothesis: 'the stub resolves imports and jumps to the payload',
      alternatives: ['the stub is dead code'],
      missing_evidence: ['entry body bytes'],
      failure_meaning: 'the provider returned 402 insufficient balance, so no tool ran and the slot stays open',
      target_selector: { function_entry: '0x401000' },
      expected_evidence_kinds: ['decompile_slice'],
      success_condition: 'new_targeted_evidence',
      failure_interpretation: 'STATIC_BOUNDARY',
    }, { agent: { session: { id: 'session-boundary' } } })
    assert.equal(actionBodies.length, 1)
    const body = actionBodies[0]
    assert.notEqual(body.failure_interpretation, 'STATIC_BOUNDARY')
    assert.notEqual(body.failure_interpretation, 'NO_NEW_EVIDENCE')
    assert.equal(body.failure_interpretation, 'UNKNOWN')
    assert.match(String(body.failure_meaning), /MODEL_402_PAYMENT_REQUIRED/)
    assert.match(String(body.failure_meaning), /insufficient balance/i)
  } finally { globalThis.fetch = originalFetch }
})

test('analyst narrative submission publishes one citable revision with explicit authorship', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const revisionId = '9f2c4d51-1111-4222-8333-444455556666'
  const bodies: string[] = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-draft', case_id: '11111111-1111-1111-1111-111111111111', state: 'ANALYSIS_READY' })
    }
    if (url.endsWith('/report/analyst-draft') && init?.method === 'POST') {
      bodies.push(String(init.body))
      return Response.json({
        id: revisionId, task_id: 'task-draft', status: 'DRAFT', author: 'dsh-agent',
        edit_kind: 'AGENT_GENERATED', markdown: '# 分析结论\n\nrecovered behaviour',
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_submit_analyst_report').execute(
      { markdown: '# 分析结论\n\nrecovered behaviour' },
      { agent: { session: { id: 'session-draft' } } })
    assert.equal(result.accepted, true)
    assert.equal(result.authoritative_revision_id, revisionId)
    assert.equal(result.report_revision_id, revisionId)
    assert.equal(result.id, revisionId)
    assert.match(String(result.citation_instruction), new RegExp(revisionId))
    assert.equal(result.authorship.narrative_source, 'dsh-agent')
    assert.equal(result.authorship.revision_edit_kind, 'AGENT_GENERATED')
    assert.equal(result.authorship.deterministic_fragments_authoritative, true)
    assert.equal(result.authorship.product_generated_text, false)
    assert.equal(bodies.length, 1)
  } finally { globalThis.fetch = originalFetch }
})

test('the written report file is agent-authored text, not a product revision', async () => {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) {
      return Response.json({ active_task_id: 'task-file', case_id: '11111111-1111-1111-1111-111111111111', state: 'ANALYSIS_READY' })
    }
    if (url.endsWith('/report/file') && init?.method === 'POST') {
      return Response.json({ written: true, path: '/reports/sample.分析报告.md', filename: 'sample.分析报告.md' })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    const result = await registered.get('threat_write_report_file').execute(
      { filename: 'sample.分析报告.md', markdown: '# 分析结论' },
      { agent: { session: { id: 'session-file' } } })
    assert.equal(result.written, true)
    assert.equal(result.authorship.narrative_source, 'dsh-agent')
    assert.equal(result.authorship.product_generated_text, false)
    assert.equal(result.authorship.official_revision, false)
  } finally { globalThis.fetch = originalFetch }
})
