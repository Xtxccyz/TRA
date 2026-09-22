import assert from 'node:assert/strict'
import test from 'node:test'
import { ThreatApiClient } from '../packages/threat-api-client/src/index.ts'
import { apply, buildContext, overlayAuthoritativeGetReport, projectInvestigationContext } from '../packages/threat-context-provider/src/index.ts'

const task = {
  task: {
    id: 'task-1', lifecycle: 'SUCCEEDED', outcome: 'PARTIAL',
    latest_report_revision_id: 'revision-7',
    limitations: ['consumer is not recovered'],
    strategy_snapshot: {
      investigation: {
        deferred_frontier: [{ artifact_id: 'artifact-1', question: 'Where is the output consumed?' }],
      },
    },
  },
  artifacts: [{ id: 'artifact-1', logical_path: 'sample.bin', detected_type: 'PE' }],
  threads: [{ id: 'thread-1', state: 'EVIDENCE_GATHERING', question: 'Is the decoded buffer executed?', evidence_ids: ['ev-1'] }],
  hypotheses: [{ id: 'hyp-1', thread_id: 'thread-1', status: 'OPEN', statement: 'Decoded bytes may feed a loader', required_evidence: ['consumer'] }],
  actions: [{ id: 'action-1', action_type: 'GET_CALLEES', status: 'NO_NEW_EVIDENCE', reason: 'No callee in bounded slice', evidence_ids: ['ev-1'] }],
  mechanisms: [{ id: 'mech-1', type: 'loader', status: 'CANDIDATE', missing_fields: ['output', 'consumer'], evidence_ids: ['ev-1'] }],
  evidence: [{ id: 'ev-1', artifact_id: 'artifact-1', module: 'loader', kind: 'decode_result', nature: 'STATIC_OBSERVED', anchor: 'rva:0x401000' }],
  report: { revision_id: 'revision-7', available: true, status: 'PARTIAL' },
}

const gapTask = {
  task: {
    id: 'task-gap', lifecycle: 'SUCCEEDED', outcome: 'PARTIAL',
    latest_report_revision_id: 'revision-old',
    limitations: ['decode consumer UNKNOWN', 'OS thread start UNKNOWN'],
  },
  artifacts: [{ id: 'artifact-1', logical_path: 'sample.bin', detected_type: 'PE' }],
  threads: [
    {
      id: 'inv-thread-decode', state: 'EVIDENCE_GATHERING',
      question: 'Who consumes the decoded buffer?', seed_kind: 'decode_result',
      evidence_ids: ['ev-decode'],
      protocol: {
        output: { status: 'ANSWERED', value: 'decoded_buf', evidence_ids: ['ev-decode'], reason: '', question: 'What output object or bytes are produced?' },
        consumer: { status: 'UNKNOWN', value: null, evidence_ids: [], reason: 'producer writes decoded_buf; no recovered consumer', question: 'Who consumes that output?' },
      },
      s_ladder: {
        s1_context: 'ATTEMPTED', s2_dataflow: 'PARTIAL', s3_consumer: 'MISSING',
        s4_orchestration: 'OPEN', attempted_action_types: ['GET_CALLEES'],
      },
    },
    {
      id: 'inv-thread-os', state: 'EVIDENCE_GATHERING',
      question: 'What lpStartAddress does CreateThread start?', seed_kind: 'create_thread',
      evidence_ids: ['ev-thread'],
      protocol: {
        initiator: { status: 'UNKNOWN', reason: 'lpStartAddress not recovered from CreateThread arguments', question: 'Who starts or registers this behavior?' },
      },
      s_ladder: {
        s1_context: 'ATTEMPTED', s2_dataflow: 'MISSING', s3_consumer: 'MISSING',
        s4_orchestration: 'OPEN', attempted_action_types: ['GET_FUNCTION'],
      },
    },
  ],
  hypotheses: [{ id: 'hyp-1', thread_id: 'inv-thread-decode', status: 'OPEN', statement: 'Decoded bytes may feed a loader', required_evidence: ['consumer'] }],
  actions: [
    { id: 'action-1', action_type: 'GET_CALLEES', status: 'NO_NEW_EVIDENCE', reason: 'No callee in bounded slice', evidence_ids: ['ev-decode'] },
    { id: 'action-2', action_type: 'GET_FUNCTION', status: 'NO_NEW_EVIDENCE', reason: 'start routine body not recovered', evidence_ids: ['ev-thread'] },
  ],
  mechanisms: [
    { id: 'mech-decode', type: 'decode', status: 'CANDIDATE', output: 'decoded_buf', missing_fields: ['consumer'], unknowns: ['consumer'], evidence_ids: ['ev-decode'] },
    { id: 'mech-thread', type: 'os_thread', status: 'CANDIDATE', missing_fields: ['start_routine'], evidence_ids: ['ev-thread'] },
  ],
  evidence: [
    { id: 'ev-decode', artifact_id: 'artifact-1', module: 'decryption', kind: 'decode_result', nature: 'STATIC_OBSERVED', anchor: 'rva:0x401000', value: { plaintext: 'MZ' } },
    { id: 'ev-thread', artifact_id: 'artifact-1', module: 'loader', kind: 'thread_callback', nature: 'STATIC_OBSERVED', anchor: 'rva:0x401100' },
  ],
  unique_execution_threads: [
    { api: 'CreateThread', start_routine: 'UNKNOWN(start_routine)', parameter: 'UNKNOWN(parameter)', function_entry: '0x401100' },
  ],
  report: { revision_id: 'revision-old', available: true, status: 'PARTIAL' },
}

function packetFrom(text: string): Record<string, unknown> {
  const encoded = /<threat_analysis_context untrusted="true">([\s\S]*)<\/threat_analysis_context>/.exec(text)
  assert.ok(encoded, text)
  return JSON.parse(encoded[1]) as Record<string, unknown>
}

test('context projection exposes durable investigation frontier and report revision', () => {
  const projected = projectInvestigationContext(task, 'session-1')
  assert.equal(projected.session_id, 'session-1')
  assert.equal((projected.report as Record<string, unknown>).revision_id, 'revision-7')
  assert.equal((projected.report as Record<string, unknown>).this_turn_ready, true)
  const frontier = projected.investigation_frontier as Record<string, unknown>
  assert.equal((frontier.missing_evidence as unknown[]).length, 0)
  assert.equal((frontier.open_questions as unknown[]).length, 1)
  assert.equal((frontier.deferred as unknown[]).length, 1)
  const actions = projected.actions as Record<string, unknown>[]
  assert.equal(actions[0].result_status, undefined)
  assert.equal(actions[0].status, 'NO_NEW_EVIDENCE')
})

test('recorded UNKNOWN and CANDIDATE threads are report content, not open planner tickets', () => {
  const projected = projectInvestigationContext({
    ...task,
    threads: [
      { id: 'thread-process', state: 'CLAIM_READY', question: 'How does CreateProcess start Foxit?' },
      { id: 'thread-http', state: 'UNKNOWN', question: 'Which WinHTTP call sends the beacon?' },
      { id: 'thread-ppid', state: 'UNKNOWN', question: 'Does UpdateProcThreadAttribute spoof the parent?' },
    ],
    mechanisms: [
      { id: 'mech-process', type: 'PROCESS_EXECUTION', status: 'CANDIDATE', missing_fields: ['consumer'], evidence_ids: ['ev-1'] },
      { id: 'mech-http', type: 'HTTP_BEACON', status: 'UNKNOWN', missing_fields: ['api'], unknowns: ['transport API not imported'] },
    ],
    task: { ...task.task, strategy_snapshot: { investigation: { deferred_frontier: [] } } },
  }, 'session-1')
  const frontier = projected.investigation_frontier as Record<string, unknown>
  assert.equal((frontier.open_questions as unknown[]).length, 0)
  assert.equal((frontier.missing_evidence as unknown[]).length, 0)
})

test('leftover emu and budget-exhausted deferred rows are not planner tickets', () => {
  const projected = projectInvestigationContext({
    ...task,
    threads: [
      { id: 'thread-process', state: 'CLAIM_READY', question: 'How does CreateProcess start Foxit?' },
    ],
    task: {
      ...task.task,
      strategy_snapshot: {
        investigation: {
          deferred_frontier: [
            { artifact_id: 'artifact-1', action_type: 'CONTROLLED_EMULATE', question: 'Emulate FUN_140004605' },
            { artifact_id: 'artifact-1', reason: 'INVESTIGATION_BUDGET_EXHAUSTED', question: 'Close the HTTP frontier' },
          ],
        },
      },
    },
  }, 'session-1')
  const frontier = projected.investigation_frontier as Record<string, unknown>
  assert.equal((frontier.deferred as unknown[]).length, 0)
  assert.equal((frontier.open_questions as unknown[]).length, 0)
})

test('persist HOW skip cancelled TRACE is leftover remainder, not a planner ticket', () => {
  const skipped = Array.from({ length: 12 }, (_, index) => ({
    id: `skip-${index}`,
    action_type: 'GET_CALLEES',
    status: 'CANCELLED',
    error: 'PERSIST_HOW_SKIP',
    reason: 'persist HOW already recorded',
  }))
  const projected = projectInvestigationContext({
    ...task,
    threads: [
      { id: 'thread-process', state: 'CLAIM_READY', question: 'How does CreateProcess start Foxit?' },
    ],
    actions: [
      ...skipped,
      {
        id: 'emu-1',
        action_type: 'CONTROLLED_EMULATE',
        status: 'QUEUED',
        target_selector: 'FUN_140004605',
      },
    ],
    mechanisms: [
      { id: 'mech-process', type: 'PROCESS_EXECUTION', status: 'CANDIDATE', missing_fields: ['consumer'] },
    ],
    task: { ...task.task, strategy_snapshot: { investigation: { deferred_frontier: [] } } },
  }, 'session-persist-skip')
  const frontier = projected.investigation_frontier as Record<string, unknown>
  const recent = frontier.recent_actions as Record<string, unknown>[]
  const projectedActions = projected.actions as Record<string, unknown>[]
  assert.equal(recent.some((row) => row.status === 'CANCELLED'), false)
  assert.equal(projectedActions.some((row) => row.status === 'CANCELLED'), false)
  assert.ok(recent.some((row) => row.action_type === 'CONTROLLED_EMULATE'))
  assert.ok(projectedActions.some((row) => row.action_type === 'CONTROLLED_EMULATE'))
  assert.equal((frontier.open_questions as unknown[]).length, 0)
  const gaps = projected.task_gaps as Record<string, unknown>
  assert.equal((gaps.next_bounded_methods as unknown[]).length, 0)
  const s4 = gaps.s4 as Record<string, unknown>[]
  assert.ok(s4.every((row) => row.status !== 'BLOCKED'))
})

test('persist CLAIM_READY without TRACE actions is leftover remainder, not S4 BLOCKED', () => {
  const projected = projectInvestigationContext({
    ...gapTask,
    threads: [
      {
        id: 'thread-process',
        state: 'CLAIM_READY',
        question: 'How does CreateProcess start Foxit?',
        evidence_ids: ['ev-process'],
        action_ids: [],
        protocol: {
          input: { status: 'ANSWERED', value: 'cmd.exe /c FoxitPDFReader.exe' },
          consumer: { status: 'UNKNOWN', reason: 'runtime consumer not observed' },
        },
      },
      {
        id: 'thread-http',
        state: 'UNKNOWN',
        question: 'Which WinHTTP call sends the beacon?',
        evidence_ids: [],
        s_ladder: { s4_orchestration: 'OPEN' },
      },
    ],
    mechanisms: [
      { id: 'mech-process', type: 'PROCESS_EXECUTION', status: 'CANDIDATE', missing_fields: ['consumer'] },
    ],
  }, 'session-remainder')
  const gaps = projected.task_gaps as Record<string, unknown>
  const unanswered = gaps.unanswered_ten_question_slots as Record<string, unknown>[]
  assert.equal(unanswered.length, 0)
  const s4 = gaps.s4 as Record<string, unknown>[]
  assert.ok(s4.some((row) => row.investigation_thread_id === 'thread-process' && row.status === 'CLOSED'))
  assert.ok(s4.some((row) => row.investigation_thread_id === 'thread-http' && row.status === 'RECORDED'))
  assert.ok(s4.every((row) => row.status !== 'BLOCKED'))
  const frontier = projected.investigation_frontier as Record<string, unknown>
  assert.equal((frontier.missing_evidence as unknown[]).length, 0)
  assert.equal((frontier.open_questions as unknown[]).length, 0)
  assert.equal((gaps.unique_os_thread_starts as unknown[]).length, 0)
  assert.equal((gaps.decode_consumers as unknown[]).length, 0)
  assert.equal((gaps.next_bounded_methods as unknown[]).length, 0)
})

test('terminal FAILED and CANCELLED keep the GET report revision, not a stale running id', () => {
  for (const lifecycle of ['SUCCEEDED', 'FAILED', 'CANCELLED'] as const) {
    const projected = projectInvestigationContext({
      ...task,
      task: { ...task.task, lifecycle, latest_report_revision_id: 'revision-old' },
      report: { revision_id: '75215cce-aaaa-4bbb-8ccc-ddddeeeeffff', available: true, status: 'PARTIAL' },
    }, 'session-1')
    const report = projected.report as Record<string, unknown>
    assert.equal(report.revision_id, '75215cce-aaaa-4bbb-8ccc-ddddeeeeffff', lifecycle)
    assert.notEqual(report.revision_id, undefined)
    assert.notEqual(report.revision_id, 'revision-old')
  }
})

test('GET overlay replaces a stale running revision after the task is terminal', () => {
  const projected = projectInvestigationContext({
    ...task,
    task: { ...task.task, lifecycle: 'SUCCEEDED', latest_report_revision_id: 'revision-old' },
    report: { revision_id: 'revision-old', available: true, status: 'PARTIAL' },
  }, 'session-1')
  const overlaid = overlayAuthoritativeGetReport(projected, {
    task_id: 'task-1',
    revision: { id: '75215cce-1111-4222-8333-444455556666' },
  })
  const report = overlaid.report as Record<string, unknown>
  assert.equal(report.revision_id, '75215cce-1111-4222-8333-444455556666')
  assert.equal((overlaid.task as Record<string, unknown>).latest_report_revision_id, '75215cce-1111-4222-8333-444455556666')
  assert.equal((overlaid.task as Record<string, unknown>).authoritative_report_revision_id, '75215cce-1111-4222-8333-444455556666')
})

test('GET overlay does not restore a revision while the task is still RUNNING', () => {
  const projected = projectInvestigationContext({
    ...task,
    task: { ...task.task, lifecycle: 'RUNNING', latest_report_revision_id: 'revision-old' },
    report: { revision_id: 'revision-old', available: true, status: 'PARTIAL' },
  }, 'session-1')
  const overlaid = overlayAuthoritativeGetReport(projected, {
    revision: { id: '75215cce-1111-4222-8333-444455556666' },
  })
  const report = overlaid.report as Record<string, unknown>
  assert.equal(report.revision_id, undefined)
  assert.equal(report.do_not_cite_prior_revisions, true)
})

test('in-flight analysis hides prior revision so chat cannot cite an older SUCCEEDED report', () => {
  const projected = projectInvestigationContext({
    ...task,
    task: { ...task.task, lifecycle: 'RUNNING', latest_report_revision_id: 'revision-old' },
    report: { revision_id: 'revision-old', available: true, status: 'PARTIAL' },
  }, 'session-1')
  const report = projected.report as Record<string, unknown>
  assert.equal(report.available, false)
  assert.equal(report.revision_id, undefined)
  assert.equal(report.this_turn_ready, false)
  assert.equal(report.do_not_cite_prior_revisions, true)
  const gaps = projected.task_gaps as Record<string, unknown>
  assert.equal(gaps.official_report_revision_id, undefined)
  assert.equal(gaps.do_not_invent_second_report, true)
})

test('model failure is projected separately from STATIC_BOUNDARY', () => {
  const projected = projectInvestigationContext({
    ...task,
    task: {
      ...task.task,
      failure: { failure_code: 'MODEL_FAILURE', http_status: 402, retryable: true },
      model_status: {
        kind: 'MODEL_OR_TRANSPORT',
        http_status: 402,
        distinct_from_static_boundary: true,
        prompt_sha256: 'abc',
      },
    },
  }, 'session-1')
  const projectedTask = projected.task as Record<string, unknown>
  const failure = projectedTask.failure as Record<string, unknown>
  const modelStatus = projectedTask.model_status as Record<string, unknown>
  const distinction = (projected.task_gaps as Record<string, unknown>).failure_kind_distinction as Record<string, unknown>
  assert.equal(failure.failure_code, 'MODEL_FAILURE')
  assert.equal(modelStatus.kind, 'MODEL_OR_TRANSPORT')
  assert.equal(modelStatus.distinct_from_static_boundary, 'true')
  assert.equal(modelStatus.user_action, undefined)
  assert.equal(distinction.observed, 'MODEL_OR_TRANSPORT')
  assert.equal(distinction.do_not_collapse, true)
  assert.doesNotMatch(JSON.stringify(projectedTask), /STATIC_BOUNDARY/)
})

test('model timeout is projected as MODEL_OR_TRANSPORT, not POLICY_DENIED or STATIC_BOUNDARY', () => {
  const projected = projectInvestigationContext({
    ...task,
    task: {
      ...task.task,
      failure: { failure_code: 'TIMEOUT_FAILURE', retryable: true },
      model_status: {
        kind: 'MODEL_OR_TRANSPORT',
        last_status: 'TIMEOUT',
        error_type: 'timeout',
        distinct_from_static_boundary: true,
      },
    },
  }, 'session-timeout')
  const projectedTask = projected.task as Record<string, unknown>
  const distinction = (projected.task_gaps as Record<string, unknown>).failure_kind_distinction as Record<string, unknown>
  assert.equal((projectedTask.failure as Record<string, unknown>).failure_code, 'TIMEOUT_FAILURE')
  assert.equal((projectedTask.model_status as Record<string, unknown>).last_status, 'TIMEOUT')
  assert.equal(distinction.observed, 'MODEL_OR_TRANSPORT')
  assert.equal(distinction.model_or_transport, '402/timeout')
  assert.doesNotMatch(JSON.stringify(projectedTask), /STATIC_BOUNDARY/)
  assert.doesNotMatch(JSON.stringify(projectedTask), /POLICY_DENIED/)
})

test('POLICY_DENIED is projected separately from model 402/timeout and STATIC_BOUNDARY', () => {
  const projected = projectInvestigationContext({
    ...task,
    task: {
      ...task.task,
      failure: { failure_code: 'POLICY_DENIED', reason: 'emu window not granted' },
    },
    actions: [
      { id: 'action-policy', action_type: 'CONTROLLED_EMULATE', status: 'POLICY_DENIED', reason: 'self-authorize refused' },
    ],
  }, 'session-policy')
  const projectedTask = projected.task as Record<string, unknown>
  const distinction = (projected.task_gaps as Record<string, unknown>).failure_kind_distinction as Record<string, unknown>
  assert.equal((projectedTask.failure as Record<string, unknown>).failure_code, 'POLICY_DENIED')
  assert.equal(distinction.observed, 'POLICY_DENIED')
  assert.equal(distinction.policy_denied, 'POLICY_DENIED')
  assert.notEqual(distinction.observed, 'MODEL_OR_TRANSPORT')
  assert.notEqual(distinction.observed, 'STATIC_BOUNDARY')
  assert.doesNotMatch(JSON.stringify(projectedTask), /STATIC_BOUNDARY/)
  assert.doesNotMatch(JSON.stringify(projectedTask), /MODEL_OR_TRANSPORT/)
})

test('investigation uses the conversation model instead of a second planner', () => {
  const projected = projectInvestigationContext({
    ...task,
    analysis_planner: {
      role: 'dsh-conversation',
      source: 'settings.models',
      distinct_from_dsh_chat: false,
      user_action: '调查与对话共用左下角设置 →「模型」',
    },
    task: {
      ...task.task,
      model_status: {
        kind: 'NONE',
        provider: 'deepseek',
        model: 'deepseek-v4-pro',
        distinct_from_dsh_chat: false,
        user_action: '调查与对话共用左下角设置 →「模型」',
      },
    },
  }, 'session-1')
  const planner = projected.analysis_planner as Record<string, unknown>
  assert.equal(planner.role, 'dsh-conversation')
  assert.equal(planner.distinct_from_dsh_chat, 'false')
  assert.equal(planner.source, 'settings.models')
  const modelStatus = (projected.task as Record<string, unknown>).model_status as Record<string, unknown>
  assert.equal(modelStatus.provider, 'deepseek')
  assert.doesNotMatch(String(modelStatus.user_action), /分析规划/)
})

test('context provider registers a real prompt hook and refreshes session-bound task data', async () => {
  const originalFetch = globalThis.fetch
  const calls: string[] = []
  const contexts: Record<string, unknown>[] = []
  const listeners: ((session: { id: string }) => void)[] = []
  const assemblyListeners: ((assembly: { contexts: { name: string; text: string }[] }, context: unknown, next: () => Promise<unknown>) => Promise<unknown>)[] = []
  globalThis.fetch = async (input) => {
    const url = String(input)
    calls.push(url)
    if (url.endsWith('/analysis-context')) return Response.json({ state: 'ANALYSIS_READY', active_task_id: 'task-1' })
    if (url.endsWith('/tasks/task-1/report')) {
      return Response.json({ task_id: 'task-1', revision: { id: 'revision-7', markdown: '# GET report' } })
    }
    if (url.endsWith('/tasks/task-1')) return Response.json(task)
    throw new Error(`unexpected request ${url}`)
  }
  try {
    const ctx = {
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({
        systemPrompt: { context: (value: Record<string, unknown>) => { contexts.push(value); return () => {} } },
      }),
      on: (name: string, listener: any) => {
        if (name === 'session/event') listeners.push(listener)
        if (name === 'system-prompt/assemble') assemblyListeners.push(listener)
        return () => {}
      },
    }
    apply(ctx as never, { backendUrl: 'http://backend' })
    assert.equal(contexts.length, 1, 'prompt context hook must be registered')
    const provider = contexts[0].text as (assembly: unknown) => string
    const sessionAssembly = { agent: { session: { id: 'session-1' } } }
    assert.match(provider(sessionAssembly), /state="LOADING"/)
    await new Promise((resolve) => setTimeout(resolve, 0))
    const rendered = provider(sessionAssembly)
    assert.match(rendered, /<threat_analysis_context untrusted="true">/)
    assert.match(rendered, /revision-7/)
    assert.match(rendered, /consumer/)
    assert.ok(calls.some((url) => url.endsWith('/analysis-context')))
    assert.ok(calls.some((url) => url.endsWith('/tasks/task-1')))
    assert.equal(listeners.length, 1, 'session event invalidation must be installed')
    assert.equal(assemblyListeners.length, 1, 'first-turn assembly waterfall must be installed')
    const promptAssembly = { contexts: [{ name: 'threat:analysis-context', text: '<stale>' }, { name: 'other', text: 'keep' }] }
    await assemblyListeners[0](promptAssembly, { agent: { session: { id: 'session-1' } } }, async () => promptAssembly)
    assert.equal(promptAssembly.contexts.filter((item) => item.name === 'threat:analysis-context').length, 1)
    assert.match(promptAssembly.contexts.find((item) => item.name === 'threat:analysis-context')!.text, /revision-7/)
    assert.equal(promptAssembly.contexts.find((item) => item.name === 'other')!.text, 'keep')
  } finally { globalThis.fetch = originalFetch }
})

test('terminal assembly uses the GET report revision instead of a stale task id', async () => {
  const originalFetch = globalThis.fetch
  const getId = '75215cce-1111-4222-8333-444455556666'
  let assemble: ((assembly: { contexts: { name: string; text: string }[] }, context: unknown, next: () => Promise<unknown>) => Promise<unknown>) | undefined
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    const url = String(input)
    urls.push(url)
    if (url.endsWith('/analysis-context')) return Response.json({ state: 'ANALYSIS_READY', active_task_id: 'task-1' })
    if (url.endsWith('/tasks/task-1/report')) {
      return Response.json({ task_id: 'task-1', revision: { id: getId, markdown: '# Official GET report' } })
    }
    if (url.endsWith('/tasks/task-1')) {
      return Response.json({
        ...task,
        task: { ...task.task, lifecycle: 'SUCCEEDED', latest_report_revision_id: 'revision-old' },
        report: { revision_id: 'revision-old', available: true, status: 'PARTIAL' },
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({ systemPrompt: { context: () => () => {} } }),
      on: (name: string, listener: any) => { if (name === 'system-prompt/assemble') assemble = listener; return () => {} },
    } as never, { backendUrl: 'http://backend' })
    const assembly = { contexts: [] as { name: string; text: string }[] }
    await assemble!(assembly, { agent: { session: { id: 'session-get-revision' } } }, async () => assembly)
    const context = assembly.contexts.find((item) => item.name === 'threat:analysis-context')
    assert.ok(context)
    const encoded = /<threat_analysis_context untrusted="true">([\s\S]*)<\/threat_analysis_context>/.exec(context.text)
    assert.ok(encoded)
    const packet = JSON.parse(encoded[1]) as { report: Record<string, unknown> }
    assert.equal(packet.report.revision_id, getId)
    assert.notEqual(packet.report.revision_id, 'revision-old')
    assert.ok(urls.some((url) => url.endsWith('/tasks/task-1/report')))
  } finally { globalThis.fetch = originalFetch }
})

test('running assembly does not fetch GET report or keep a stale revision', async () => {
  const originalFetch = globalThis.fetch
  let assemble: ((assembly: { contexts: { name: string; text: string }[] }, context: unknown, next: () => Promise<unknown>) => Promise<unknown>) | undefined
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    const url = String(input)
    urls.push(url)
    if (url.endsWith('/analysis-context')) return Response.json({ state: 'ANALYSIS_RUNNING', active_task_id: 'task-1' })
    if (url.endsWith('/tasks/task-1')) {
      return Response.json({
        ...task,
        task: { ...task.task, lifecycle: 'RUNNING', latest_report_revision_id: 'revision-old' },
        report: { revision_id: 'revision-old', available: true, status: 'PARTIAL' },
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({ systemPrompt: { context: () => () => {} } }),
      on: (name: string, listener: any) => { if (name === 'system-prompt/assemble') assemble = listener; return () => {} },
    } as never, { backendUrl: 'http://backend' })
    const assembly = { contexts: [] as { name: string; text: string }[] }
    await assemble!(assembly, { agent: { session: { id: 'session-running' } } }, async () => assembly)
    const context = assembly.contexts.find((item) => item.name === 'threat:analysis-context')
    assert.ok(context)
    const encoded = /<threat_analysis_context untrusted="true">([\s\S]*)<\/threat_analysis_context>/.exec(context.text)
    assert.ok(encoded)
    const packet = JSON.parse(encoded[1]) as { report: Record<string, unknown> }
    assert.equal(packet.report.revision_id, undefined)
    assert.equal(packet.report.do_not_cite_prior_revisions, true)
    assert.ok(!urls.some((url) => url.includes('/report')))
  } finally { globalThis.fetch = originalFetch }
})

test('assembly hook exposes backend outage as a transport state, never a static boundary', async () => {
  const originalFetch = globalThis.fetch
  let assemble: ((assembly: { contexts: { name: string; text: string }[] }, context: unknown, next: () => Promise<unknown>) => Promise<unknown>) | undefined
  globalThis.fetch = async () => { throw new Error('backend unavailable') }
  try {
    apply({
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({ systemPrompt: { context: () => () => {} } }),
      on: (name: string, listener: any) => { if (name === 'system-prompt/assemble') assemble = listener; return () => {} },
    } as never, { backendUrl: 'http://backend' })
    const assembly = { contexts: [] as { name: string; text: string }[] }
    await assemble!(assembly, { agent: { session: { id: 'session-outage' } } }, async () => assembly)
    const context = assembly.contexts.find((item) => item.name === 'threat:analysis-context')
    assert.ok(context)
    assert.match(context.text, /BACKEND_UNAVAILABLE/)
    assert.doesNotMatch(context.text, /STATIC_BOUNDARY/)
  } finally { globalThis.fetch = originalFetch }
})

test('context projection injects compact evidence-backed task gaps, not raw ledgers', () => {
  const projected = projectInvestigationContext(gapTask, 'session-gap')
  const gaps = projected.task_gaps as Record<string, unknown>
  const unanswered = gaps.unanswered_ten_question_slots as Record<string, unknown>[]
  assert.ok(unanswered.some((row) => row.slot === 'consumer' && row.status === 'UNKNOWN' && String(row.reason).includes('decoded_buf')))
  assert.ok(unanswered.every((row) => row.investigation_thread_id))
  const osStarts = gaps.unique_os_thread_starts as Record<string, unknown>[]
  assert.ok(osStarts.some((row) => String(row.start_routine).startsWith('UNKNOWN') && String(row.os_object).includes('CreateThread')))
  assert.ok(osStarts.every((row) => row.investigation_thread_id !== row.os_object))
  const decode = gaps.decode_consumers as Record<string, unknown>[]
  assert.ok(decode.some((row) => row.consumer === 'UNKNOWN' && row.mechanism_id === 'mech-decode'))
  const s4 = gaps.s4 as Record<string, unknown>[]
  assert.ok(s4.some((row) => row.status === 'BLOCKED' && row.investigation_thread_id === 'inv-thread-decode'))
  assert.equal(gaps.official_report_revision_id, 'revision-old')
  assert.equal(gaps.do_not_invent_second_report, true)
  assert.equal(gaps.stop_dispatch, true)
  assert.equal(gaps.convergence, 'CONVERGED')
  assert.equal(gaps.remainder_unknowns_stay_unknown, true)
  const next = gaps.next_bounded_methods as Record<string, unknown>[]
  assert.equal(next.length, 0)
  const distinction = gaps.kind_distinction as Record<string, unknown>
  assert.match(String(distinction.investigation_thread), /question/)
  assert.match(String(distinction.os_thread), /CreateThread/)
})

test('in-flight gap packet still proposes GET_DECOMPILE after GET_CALLEES stall', () => {
  const projected = projectInvestigationContext({
    ...gapTask,
    task: { ...gapTask.task, lifecycle: 'RUNNING' },
  }, 'session-running-gap')
  const gaps = projected.task_gaps as Record<string, unknown>
  assert.equal(gaps.stop_dispatch, undefined)
  assert.equal(gaps.convergence, undefined)
  const next = gaps.next_bounded_methods as Record<string, unknown>[]
  assert.ok(next.some((row) => row.after === 'GET_CALLEES' && Array.isArray(row.propose) && row.propose.includes('GET_DECOMPILE') && row.propose.includes('CONTROLLED_EMULATE') && row.self_authorized === false))
})

test('first-turn assemble injects task gaps and the GET report revision without raw evidence values', async () => {
  const originalFetch = globalThis.fetch
  const getId = '75215cce-aaaa-4bbb-8ccc-ddddeeeeffff'
  let assemble: ((assembly: { contexts: { name: string; text: string }[] }, context: unknown, next: () => Promise<unknown>) => Promise<unknown>) | undefined
  globalThis.fetch = async (input) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) return Response.json({ state: 'ANALYSIS_READY', active_task_id: 'task-gap' })
    if (url.endsWith('/tasks/task-gap/report')) {
      return Response.json({ task_id: 'task-gap', revision: { id: getId, markdown: '# Official GET report', status: 'PARTIAL' } })
    }
    if (url.endsWith('/tasks/task-gap')) return Response.json(gapTask)
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({ systemPrompt: { context: () => () => {} } }),
      on: (name: string, listener: any) => { if (name === 'system-prompt/assemble') assemble = listener; return () => {} },
    } as never, { backendUrl: 'http://backend' })
    const assembly = { contexts: [] as { name: string; text: string }[] }
    await assemble!(assembly, { agent: { session: { id: 'session-first-analyze' } } }, async () => assembly)
    const context = assembly.contexts.find((item) => item.name === 'threat:analysis-context')
    assert.ok(context)
    assert.doesNotMatch(context.text, /state="LOADING"/)
    const packet = packetFrom(context.text)
    const gaps = packet.task_gaps as Record<string, unknown>
    assert.equal(gaps.official_report_revision_id, getId)
    assert.notEqual(gaps.official_report_revision_id, 'revision-old')
    assert.ok((gaps.unanswered_ten_question_slots as unknown[]).length >= 1)
    assert.ok((gaps.unique_os_thread_starts as Record<string, unknown>[]).some((row) => String(row.start_routine).startsWith('UNKNOWN')))
    assert.ok((gaps.decode_consumers as Record<string, unknown>[]).some((row) => row.consumer === 'UNKNOWN'))
    assert.ok((gaps.s4 as Record<string, unknown>[]).some((row) => row.status === 'BLOCKED'))
    assert.equal(packet.hypotheses, undefined)
    assert.equal(packet.evidence_index, undefined)
    assert.equal(packet.threads, undefined)
    assert.doesNotMatch(context.text, /"plaintext"/)
    assert.equal((packet.report as Record<string, unknown>).revision_id, getId)
  } finally { globalThis.fetch = originalFetch }
})

test('buildContext is the real task-gap loader used for analysis start', async () => {
  const originalFetch = globalThis.fetch
  const getId = '75215cce-bbbb-4ccc-8ddd-eeeeeeeeffff'
  const urls: string[] = []
  globalThis.fetch = async (input) => {
    const url = String(input)
    urls.push(url)
    if (url.endsWith('/tasks/task-gap/report')) {
      return Response.json({ task_id: 'task-gap', revision: { id: getId, markdown: '# Official GET report' } })
    }
    if (url.endsWith('/tasks/task-gap')) return Response.json(gapTask)
    throw new Error(`unexpected request ${url}`)
  }
  try {
    const client = new ThreatApiClient({ baseUrl: 'http://backend' })
    const built = await buildContext(client, 'task-gap', '分析这个样本', { sessionId: 'session-build' })
    assert.equal(built.task_id, 'task-gap')
    assert.equal(built.question, '分析这个样本')
    const gaps = built.context.task_gaps as Record<string, unknown>
    assert.equal(gaps.official_report_revision_id, getId)
    assert.ok((gaps.decode_consumers as Record<string, unknown>[]).some((row) => row.consumer === 'UNKNOWN'))
    assert.ok(urls.some((url) => url.endsWith('/tasks/task-gap')))
    assert.ok(urls.some((url) => url.endsWith('/tasks/task-gap/report')))
  } finally { globalThis.fetch = originalFetch }
})

test('first-turn assemble dispatches analysis intent before the model call', async () => {
  const originalFetch = globalThis.fetch
  let assemble: ((assembly: { contexts: { name: string; text: string }[] }, context: unknown, next: () => Promise<unknown>) => Promise<unknown>) | undefined
  const urls: string[] = []
  const bodies: string[] = []
  let contextState = { state: 'UNBOUND', active_task_id: null as string | null }
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    urls.push(url)
    if (url.endsWith('/analysis/intent') && String(init?.method || 'GET').toUpperCase() === 'POST') {
      bodies.push(String(init?.body || ''))
      contextState = { state: 'ANALYSIS_QUEUED', active_task_id: 'task-intent' }
      return Response.json({ dispatched: true, created: true, active_task_id: 'task-intent', state: 'ANALYSIS_QUEUED' })
    }
    if (url.endsWith('/analysis-context')) return Response.json(contextState)
    if (url.endsWith('/tasks/task-intent')) {
      return Response.json({
        task: { id: 'task-intent', lifecycle: 'PENDING' },
        artifacts: [], threads: [], hypotheses: [], actions: [], mechanisms: [],
        evidence: [], report: { available: false },
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({ systemPrompt: { context: () => () => {} } }),
      on: (name: string, listener: any) => { if (name === 'system-prompt/assemble') assemble = listener; return () => {} },
    } as never, { backendUrl: 'http://backend' })
    const assembly = { contexts: [] as { name: string; text: string }[] }
    await assemble!(assembly, { agent: { session: { id: 'session-intent' } }, prompt: '分析这个样本' }, async () => assembly)
    assert.ok(urls.some((url) => url.endsWith('/analysis/intent')))
    assert.ok(bodies.some((body) => body.includes('分析这个样本')))
    const context = assembly.contexts.find((item) => item.name === 'threat:analysis-context')
    assert.ok(context)
    assert.match(context.text, /ANALYSIS_QUEUED|task-intent/)
  } finally { globalThis.fetch = originalFetch }
})

test('DSH assemble context without prompt still dispatches from the last user message', async () => {
  const originalFetch = globalThis.fetch
  let assemble: ((assembly: { contexts: { name: string; text: string }[] }, context: unknown, next: () => Promise<unknown>) => Promise<unknown>) | undefined
  const urls: string[] = []
  const bodies: string[] = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    urls.push(url)
    if (url.endsWith('/analysis/intent') && String(init?.method || 'GET').toUpperCase() === 'POST') {
      bodies.push(String(init?.body || ''))
      return Response.json({ dispatched: true, created: true, active_task_id: 'task-dsh-shape', state: 'ANALYSIS_QUEUED' })
    }
    if (url.endsWith('/analysis-context')) {
      return Response.json({ state: 'ANALYSIS_QUEUED', active_task_id: 'task-dsh-shape' })
    }
    if (url.endsWith('/tasks/task-dsh-shape')) {
      return Response.json({
        task: { id: 'task-dsh-shape', lifecycle: 'PENDING' },
        artifacts: [], threads: [], hypotheses: [], actions: [], mechanisms: [],
        evidence: [], report: { available: false },
      })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({ systemPrompt: { context: () => () => {} } }),
      on: (name: string, listener: any) => { if (name === 'system-prompt/assemble') assemble = listener; return () => {} },
    } as never, { backendUrl: 'http://backend' })
    const agent = {
      session: {
        id: 'session-dsh-shape',
        events: [
          {
            type: 'user/message',
            data: {
              role: 'user',
              content: [{ type: 'text', text: '分析这个样本' }],
              source: { kind: 'user' },
            },
          },
        ],
      },
      inbox: { nextTurn: [], nextStep: [] },
    }
    const assembly = { contexts: [] as { name: string; text: string }[] }
    await assemble!(assembly, { agent, scope: agent }, async () => assembly)
    assert.ok(urls.some((url) => url.endsWith('/analysis/intent')), 'live DSH assemble has no prompt field')
    assert.ok(bodies.some((body) => body.includes('分析这个样本')))
  } finally { globalThis.fetch = originalFetch }
})

test('user message session event dispatches analysis intent before the model call', async () => {
  const originalFetch = globalThis.fetch
  let onSessionEvent: ((session: unknown, event?: unknown) => unknown) | undefined
  const urls: string[] = []
  const bodies: string[] = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    urls.push(url)
    if (url.endsWith('/analysis/intent') && String(init?.method || 'GET').toUpperCase() === 'POST') {
      bodies.push(String(init?.body || ''))
      return Response.json({ dispatched: true, created: true, active_task_id: 'task-event', state: 'ANALYSIS_QUEUED' })
    }
    if (url.endsWith('/analysis-context')) {
      return Response.json({ state: 'ANALYSIS_QUEUED', active_task_id: 'task-event' })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({
      inject: (_dependencies: readonly string[], callback: (scope: unknown) => void) => callback({ systemPrompt: { context: () => () => {} } }),
      on: (name: string, listener: any) => { if (name === 'session/event') onSessionEvent = listener; return () => {} },
    } as never, { backendUrl: 'http://backend' })
    onSessionEvent!(
      { id: 'session-event' },
      {
        type: 'user/message',
        data: {
          role: 'user',
          content: [{ type: 'text', text: '分析这个样本' }],
          source: { kind: 'user' },
        },
      },
    )
    await new Promise((resolve) => setTimeout(resolve, 0))
    assert.ok(urls.some((url) => url.endsWith('/analysis/intent')))
    assert.ok(bodies.some((body) => body.includes('分析这个样本')))
  } finally { globalThis.fetch = originalFetch }
})
