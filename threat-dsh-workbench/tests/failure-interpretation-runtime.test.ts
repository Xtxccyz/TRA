/**
 * B00 runtime half: the failure-interpretation vocabulary the DSH tool layer ACTUALLY uses.
 *
 * `tests/model-routing-audit.test.mjs` proves the Python enum, the generated file and the
 * tool-provider's constant are the same SET. That is a source-text check and cannot see what
 * `modelActionPayload` really posts. This file executes the real tool against a stubbed fetch
 * and pins, per status, the token that reaches the backend:
 *
 *   provider 402 / timeout / empty reply -> MODEL_TRANSPORT_FAILURE (a fact about the PLATFORM)
 *   a method that found nothing          -> NO_NEW_EVIDENCE      (a fact about the METHOD)
 *   an honest artifact limit             -> STATIC_BOUNDARY      (a fact about the SAMPLE)
 *   an ordinary tool failure             -> UNKNOWN              (neither, and never a model fault)
 *
 * The runtime list must also be the generated one: the default export list cannot be a copy.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { apply } from '../packages/threat-tool-provider/src/index.ts'
import {
  FAILURE_INTERPRETATION_TOKENS,
  MODEL_TRANSPORT_FAILURE,
} from '../packages/threat-plugin-sdk/src/index.ts'

interface Posted { [key: string]: unknown }

async function proposeAction(payload: Record<string, unknown>): Promise<Posted> {
  const originalFetch = globalThis.fetch
  const registered = new Map<string, any>()
  const bodies: Posted[] = []
  globalThis.fetch = async (input, init) => {
    const url = String(input)
    if (url.endsWith('/analysis-context')) {
      return Response.json({
        active_task_id: 'task-b00',
        case_id: '11111111-1111-1111-1111-111111111111',
        state: 'ANALYSIS_RUNNING',
        task_lifecycle: 'RUNNING',
      })
    }
    if (url.endsWith('/analysis/actions') && init?.method === 'POST') {
      bodies.push(JSON.parse(String(init.body)) as Posted)
      return Response.json({ accepted: true, action_id: 'action-b00' })
    }
    throw new Error(`unexpected request ${url}`)
  }
  try {
    apply({ tools: { register: (tool: any) => registered.set(tool.name, tool) } } as never,
      { backendUrl: 'http://localhost:8000' })
    await registered.get('threat_propose_static_action').execute(payload,
      { agent: { session: { id: 'session-b00' } } })
    assert.equal(bodies.length, 1, 'the action must be posted exactly once')
    return bodies[0]
  } finally { globalThis.fetch = originalFetch }
}

function actionPayload(failureInterpretation: string, failureMeaning: string): Record<string, unknown> {
  return {
    action_type: 'GET_DECOMPILE',
    target_artifact_id: 'artifact-b00',
    reason: 'Recover the selected function body.',
    question: 'What does the selected function do?',
    hypothesis: 'The selected function may decode and resolve APIs.',
    alternatives: ['The selected function is unrelated setup.'],
    missing_evidence: ['function_semantic_summary'],
    failure_meaning: failureMeaning,
    failure_interpretation: failureInterpretation,
    target_selector: { function_entry: '0x401000' },
    expected_evidence_kinds: ['function_semantic_summary'],
    success_condition: 'new_targeted_evidence',
  }
}

test('the DSH tool layer uses the generated contract token list, not a copy', () => {
  assert.deepEqual(
    [...FAILURE_INTERPRETATION_TOKENS].sort(),
    ['MODEL_TRANSPORT_FAILURE', 'NO_NEW_EVIDENCE', 'STATIC_BOUNDARY', 'UNKNOWN'],
  )
  assert.equal(MODEL_TRANSPORT_FAILURE, 'MODEL_TRANSPORT_FAILURE')
  for (const token of FAILURE_INTERPRETATION_TOKENS) {
    assert.equal(typeof token, 'string')
  }
})

test('provider 402, timeout and empty reply are posted as MODEL_TRANSPORT_FAILURE', async () => {
  const cases: [string, string, string][] = [
    ['402', 'STATIC_BOUNDARY', 'the provider returned 402 insufficient balance'],
    ['timeout', 'STATIC_BOUNDARY', 'ReadTimeout: the provider did not answer within 180s'],
    ['empty reply', 'UNKNOWN', 'the provider returned an empty reply'],
    ['connect timeout', 'STATIC_BOUNDARY', 'ConnectTimeout while calling the model route'],
  ]
  for (const [label, raw, meaning] of cases) {
    const body = await proposeAction(actionPayload(raw, meaning))
    assert.equal(body.failure_interpretation, 'MODEL_TRANSPORT_FAILURE',
      `${label}: a platform fault must be posted as the transport token, saw ${String(body.failure_interpretation)}`)
    assert.match(String(body.failure_meaning), /model\/transport fault/,
      `${label}: the operator still needs the class + prose in failure_meaning`)
  }
})

test('a no-gain method result, a real boundary and an ordinary tool failure stay distinct', async () => {
  const noGain = await proposeAction(actionPayload('NO_NEW_EVIDENCE', 'this slice produced nothing new'))
  assert.equal(noGain.failure_interpretation, 'NO_NEW_EVIDENCE')

  const boundary = await proposeAction(actionPayload('STATIC_BOUNDARY', 'the payload needs a live server'))
  assert.equal(boundary.failure_interpretation, 'STATIC_BOUNDARY')

  // An ordinary tool failure is neither a model fault nor a statement about the artifact.
  const toolFailure = await proposeAction(actionPayload('UNKNOWN', 'the Ghidra worker exited with code 1'))
  assert.equal(toolFailure.failure_interpretation, 'UNKNOWN')
  assert.notEqual(toolFailure.failure_interpretation, 'MODEL_TRANSPORT_FAILURE')

  // A REAL static boundary statement must not be re-labelled as transport by the transport scan.
  const honestBoundary = await proposeAction(
    actionPayload('STATIC_BOUNDARY', 'the sample never calls CreateProcess, so this path is unreachable'),
  )
  assert.equal(honestBoundary.failure_interpretation, 'STATIC_BOUNDARY')
})

test('a recorded transport annotation on a later action does not make fresh prose look like a fault', async () => {
  // The annotation this client writes into failure_meaning names the class, and `MODEL_402_PAYMENT_REQUIRED`
  // contains markers that would otherwise re-classify a perfectly ordinary next action.
  const body = await proposeAction(actionPayload(
    'NO_NEW_EVIDENCE',
    'MODEL_402_PAYMENT_REQUIRED: model/transport fault, not a static boundary and not a negative result; the callee slice produced nothing new',
  ))
  assert.equal(body.failure_interpretation, 'NO_NEW_EVIDENCE')
})
