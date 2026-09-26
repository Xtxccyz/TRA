import assert from 'node:assert/strict'
import test from 'node:test'
import * as gateway from '../packages/threat-model-gateway/src/index.ts'

const request = {
  case_id: 'case-1', task_id: 'task-1', session_id: 'session-1',
  turn_id: 'turn-1', step_id: 'step-1', module: 'planning',
  messages: [{ role: 'user' as const, content: 'Which thread consumes the decoded buffer?' }],
  response_schema: {},
}

function adapterReturning(result: Record<string, unknown>): gateway.ExistingModelGateway {
  return new gateway.BackendModelGatewayAdapter({
    completeModel: async () => result,
  } as never, 'planning')
}

async function rejection(adapter: gateway.ExistingModelGateway): Promise<Record<string, unknown>> {
  const error = await adapter.complete(request).then(() => undefined, (reason: unknown) => reason)
  assert.ok(error instanceof Error, `expected the adapter to reject, got ${String(error)}`)
  return error as unknown as Record<string, unknown>
}

test('a provider 402 surfaces as a classified model/transport fault, not a bare FAILED', async () => {
  const error = await rejection(adapterReturning({
    status: 'FAILED',
    run_id: 'run-402',
    attempts: [{
      provider: 'deepseek', model: 'deepseek-v4-pro', status: 'FAILED',
      error_type: 'HTTPStatusError', http_status: 402, error_detail: 'Insufficient Balance',
    }],
  }))
  assert.equal(error.name, 'ModelTransportError')
  assert.equal(error.failure_kind, 'MODEL_402_PAYMENT_REQUIRED')
  assert.equal(error.http_status, 402)
  assert.equal(error.distinct_from_static_boundary, true)
  assert.equal(error.not_an_analysis_result, true)
  const asResult = (error as unknown as { asResult?: () => Record<string, unknown> }).asResult?.() || {}
  assert.equal(asResult.state, 'MODEL_OR_TRANSPORT')
  assert.equal(asResult.failure_kind, 'MODEL_402_PAYMENT_REQUIRED')
  assert.notEqual(asResult.state, 'STATIC_BOUNDARY')
})

test('a SUCCEEDED reply with no content is an empty reply, never a completion', async () => {
  const error = await rejection(adapterReturning({
    status: 'SUCCEEDED', provider: 'deepseek', model: 'deepseek-v4-pro',
    model_call_id: 'call-empty', content: '   ',
    usage: { input_tokens: 7378, output_tokens: 2048 },
  }))
  assert.equal(error.name, 'ModelTransportError')
  assert.equal(error.failure_kind, 'MODEL_EMPTY_REPLY')
  assert.equal(error.not_an_analysis_result, true)
})

test('a model timeout is classified as a timeout, not as a missing capability', async () => {
  const error = await rejection(adapterReturning({
    status: 'FAILED',
    attempts: [{
      provider: 'deepseek', model: 'deepseek-v4-pro', status: 'FAILED',
      error_type: 'ReadTimeout', error_detail: 'model response exceeded total deadline of 180.0s',
    }],
  }))
  assert.equal(error.name, 'ModelTransportError')
  assert.equal(error.failure_kind, 'MODEL_TIMEOUT')
  const asResult = (error as unknown as { asResult?: () => Record<string, unknown> }).asResult?.() || {}
  assert.equal((asResult.failure_class as Record<string, unknown>).retryable, true)
})

test('a real completion still resolves with its provider, model and content', async () => {
  const response = await adapterReturning({
    status: 'SUCCEEDED', provider: 'deepseek', model: 'deepseek-v4-pro',
    model_call_id: 'call-ok', content: '{"actions":[]}',
    attempts: [{ provider: 'deepseek', model: 'deepseek-v4-pro', status: 'SUCCEEDED', latency_ms: 900 }],
  }).complete(request)
  assert.equal(response.model_call_id, 'call-ok')
  assert.equal(response.provider, 'deepseek')
  assert.equal(response.model, 'deepseek-v4-pro')
  assert.equal(response.content, '{"actions":[]}')
})

test('a deployment-level model shutdown still propagates as a named fault', async () => {
  const adapter = new gateway.BackendModelGatewayAdapter({
    completeModel: async () => {
      throw new Error('backend request failed (422): MODEL_CALLS_DISABLED: model calls are disabled by deployment policy')
    },
  } as never, 'planning')
  const error = await rejection(adapter)
  assert.match(String(error.message), /MODEL_CALLS_DISABLED/)
})
