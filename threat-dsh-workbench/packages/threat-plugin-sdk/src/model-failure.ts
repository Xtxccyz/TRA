/**
 * Model / transport failure classification for the workbench.
 *
 * B00 requires the workbench to keep a model fault distinguishable from a
 * static-analysis boundary, and to never record one as a product effect. The
 * backend already separates the raw facts (an HTTP status, an error type, an
 * error detail, a provider status on every attempt), but the DSH boundary used
 * to collapse all of them into the string `backend model call failed: FAILED`.
 *
 * This module is the single classifier both DSH packages use:
 *
 *  - ``threat-tool-provider`` classifies the ``/model/complete`` result before
 *    the model can read it;
 *  - ``threat-context-provider`` classifies the bound task's
 *    ``failure`` / ``model_status`` rows for the first-turn packet.
 *
 * Every class below is a *transport* condition. None of them is evidence about
 * the sample, and none of them may be written as ``STATIC_BOUNDARY``,
 * ``POLICY_DENIED``, ``NO_NEW_EVIDENCE`` or a negative analysis result.
 *
 * Vocabulary is pinned to the backend's real surfaces by
 * ``tests/model-routing-audit.test.mjs``: ``MODEL_CALLS_DISABLED`` and
 * ``MODEL_NOT_CONFIGURED`` (ModelUnavailable), ``MODEL_PROVIDERS_UNAVAILABLE``
 * (AgentRuntime), ``REASONING_BUDGET_EXHAUSTED`` / ``COMPLETION_BUDGET_EXHAUSTED``
 * (an HTTP 200 with an empty content string) and the retryable timeout types
 * ``ReadTimeout`` / ``ConnectTimeout`` / ``PoolTimeout``.
 */

export const MODEL_FAILURE_CONTRACT_VERSION = '1.0.0'

export type ModelFailureKind =
  | 'NONE'
  | 'MODEL_CALLS_DISABLED'
  | 'MODEL_NOT_CONFIGURED'
  | 'MODEL_402_PAYMENT_REQUIRED'
  | 'MODEL_401_AUTH'
  | 'MODEL_429_RATE_LIMITED'
  | 'MODEL_TIMEOUT'
  | 'MODEL_EMPTY_REPLY'
  | 'MODEL_GATEWAY_5XX'
  | 'MODEL_TRANSPORT'

export interface ModelFailureClass {
  readonly kind: ModelFailureKind
  readonly observed: 'NONE' | 'MODEL_OR_TRANSPORT'
  readonly http_status: number | null
  readonly provider_status: string
  readonly error_type: string
  readonly error_detail: string
  readonly retryable: boolean
  /** A model fault says nothing about the sample or about static reachability. */
  readonly distinct_from_static_boundary: true
  /** Never a Claim, Evidence, report finding or achieved analysis effect. */
  readonly not_an_analysis_result: true
  readonly do_not_collapse: true
  /** What the operator should actually do; the workbench UI is Chinese. */
  readonly user_action: string
}

export interface ModelFailureInput {
  readonly status?: unknown
  readonly kind?: unknown
  readonly http_status?: unknown
  readonly error_type?: unknown
  readonly error_detail?: unknown
  readonly error?: unknown
  readonly last_status?: unknown
  readonly failure_code?: unknown
  readonly content?: unknown
  readonly parsed?: unknown
  readonly retryable?: unknown
  readonly attempts?: unknown
}

const PAYMENT_MARKERS = [
  '402', 'payment required', 'insufficient balance', 'insufficient_quota',
  'insufficient quota', 'quota exceeded', 'current quota', 'billing',
  '余额', '欠费', '配额',
]

const AUTH_MARKERS = [
  '401', '403', 'unauthorized', 'forbidden', 'invalid api key',
  'invalid_api_key', 'authentication', '鉴权', '密钥无效',
]

const RATE_MARKERS = ['429', 'rate limit', 'too many requests', '限流']

const TIMEOUT_MARKERS = [
  'timeout', 'timed out', 'readtimeout', 'connecttimeout', 'pooltimeout',
  'writetimeout', 'deadline exceeded', 'exceeded total deadline', '超时',
]

const EMPTY_MARKERS = [
  'reasoning_budget_exhausted', 'completion_budget_exhausted',
  'empty reply', 'empty response', 'empty content', 'no content was returned',
  'no content returned', 'returned no content',
]

/** Prose markers that name a model/transport fault rather than the sample. */
export const MODEL_TRANSPORT_FAILURE_TOKENS = [
  ...PAYMENT_MARKERS, ...TIMEOUT_MARKERS, ...EMPTY_MARKERS,
  'model_providers_unavailable', 'model_calls_disabled', 'model_not_configured',
  'model failure', 'provider error', 'provider returned', 'gateway refusal',
  'gateway refused', '模型故障', '模型调用失败', '模型不可用', '网关拒绝',
] as const

const GATEWAY_STATUSES = new Set([500, 501, 502, 503, 505, 506, 507, 508, 510, 511])

function textValue(value: unknown, max = 400): string {
  if (typeof value !== 'string' && typeof value !== 'number') return ''
  const text = String(value).trim()
  return text ? text.slice(0, max) : ''
}

function statusCode(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value)
  const parsed = Number.parseInt(textValue(value, 12), 10)
  return Number.isFinite(parsed) ? parsed : null
}

/** A completion with no content is not a completion, whatever the status says. */
export function isBlankModelContent(value: unknown): boolean {
  if (value === undefined || value === null) return true
  if (typeof value !== 'string') return false
  return value.trim() === ''
}

function emptyParsedEnvelope(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const keys = Object.keys(value as Record<string, unknown>)
  if (!keys.length) return true
  return keys.every((key) => {
    const item = (value as Record<string, unknown>)[key]
    return item === undefined || item === null || (Array.isArray(item) && !item.length)
  })
}

function includesMarker(blob: string, markers: readonly string[]): boolean {
  return markers.some((marker) => blob.includes(marker))
}

function firstAttempt(row: Record<string, unknown>): Record<string, unknown> {
  const attempts = Array.isArray(row.attempts) ? row.attempts : []
  for (const item of attempts) {
    if (!item || typeof item !== 'object') continue
    const attempt = item as Record<string, unknown>
    const status = textValue(attempt.status, 40).toUpperCase()
    const http = statusCode(attempt.http_status)
    if (http !== null || textValue(attempt.error_type, 80)) return attempt
    if (status && status !== 'SUCCEEDED') return attempt
  }
  return {}
}

function classOf(
  kind: ModelFailureKind,
  fields: {
    httpStatus: number | null
    providerStatus: string
    errorType: string
    errorDetail: string
    retryable: boolean
    userAction: string
  },
): ModelFailureClass {
  const kindIsNone = kind === 'NONE'
  return Object.freeze({
    kind,
    observed: kindIsNone ? 'NONE' : 'MODEL_OR_TRANSPORT',
    http_status: fields.httpStatus,
    provider_status: fields.providerStatus,
    error_type: fields.errorType,
    error_detail: fields.errorDetail,
    retryable: fields.retryable,
    distinct_from_static_boundary: true,
    not_an_analysis_result: true,
    do_not_collapse: true,
    user_action: fields.userAction,
  })
}

/**
 * Classify one model/transport failure record.
 *
 * Accepts a backend ``/model/complete`` result, a task row
 * (``failure`` / ``model_status``) or a thrown transport message. A record with
 * no failure surface at all classifies as ``NONE``.
 */
export function classifyModelFailure(input: ModelFailureInput = {}): ModelFailureClass {
  const row = (input ?? {}) as Record<string, unknown>
  const attempt = firstAttempt(row)
  const httpStatus = statusCode(row.http_status) ?? statusCode(attempt.http_status)
  const providerStatus = textValue(row.status, 40).toUpperCase()
  const lastStatus = textValue(row.last_status, 80).toUpperCase()
  const errorType = textValue(row.error_type, 120) || textValue(attempt.error_type, 120)
  const errorDetail = textValue(row.error_detail, 400) || textValue(attempt.error_detail, 400)
  const kindField = textValue(row.kind, 60).toUpperCase()
  const failureCode = textValue(row.failure_code, 80).toUpperCase()
  const explicitError = textValue(row.error, 120).toUpperCase()
  const content = row.content
  const blob = [
    providerStatus, lastStatus, kindField, failureCode, explicitError, errorType, errorDetail,
  ].join(' ').toLowerCase()

  const base = {
    httpStatus,
    providerStatus: providerStatus || lastStatus || failureCode || kindField,
    errorType,
    errorDetail,
  }

  if (blob.includes('model_calls_disabled')) {
    return classOf('MODEL_CALLS_DISABLED', {
      ...base, retryable: false,
      userAction: '部署策略关闭了模型调用（MODEL_CALLS_DISABLED）。这是部署配置，不是样本结论；在设置 → 模型中确认模型调用已启用。',
    })
  }

  // Only an explicit success signal can turn a missing body into an empty
  // reply. A failure row without a `content` field says nothing about content,
  // and classifying it as EMPTY_REPLY would hide the real 402/timeout behind it.
  const successish = providerStatus === 'SUCCEEDED' || providerStatus === 'OK'
    || lastStatus === 'SUCCEEDED' || kindField === 'SUCCEEDED'
  const emptyNamed = includesMarker(blob, EMPTY_MARKERS)
    || ['EMPTY_REPLY', 'EMPTY_RESPONSE'].includes(lastStatus)
    || ['MODEL_EMPTY_REPLY', 'EMPTY_REPLY'].includes(kindField)
  const blankSuccess = successish
    && (isBlankModelContent(content) || (content === undefined && emptyParsedEnvelope(row.parsed)))
  if (emptyNamed || blankSuccess) {
    return classOf('MODEL_EMPTY_REPLY', {
      ...base, retryable: true,
      userAction: '模型返回空正文（可能是 REASONING_BUDGET_EXHAUSTED：推理 token 吃完了 completion 预算）。这是模型/传输故障，不是"没有证据"；提高该路由的 completion 预算后重试，不要把空回复当结论。',
    })
  }
  if (httpStatus === 402 || includesMarker(blob, PAYMENT_MARKERS)) {
    return classOf('MODEL_402_PAYMENT_REQUIRED', {
      ...base, retryable: false,
      userAction: '模型账户余额/配额不足（HTTP 402，例如 Insufficient Balance）。这是模型/传输故障，不是样本结论，也不是静态边界；在左下角 设置 → 模型 检查该 provider 的额度。',
    })
  }
  if (httpStatus === 401 || httpStatus === 403 || includesMarker(blob, AUTH_MARKERS)) {
    return classOf('MODEL_401_AUTH', {
      ...base, retryable: false,
      userAction: '模型鉴权失败（HTTP 401/403）。这是凭证/路由配置问题，不是样本结论；在设置 → 模型中重新填写 API Key。',
    })
  }
  if (httpStatus === 429 || includesMarker(blob, RATE_MARKERS)) {
    return classOf('MODEL_429_RATE_LIMITED', {
      ...base, retryable: true,
      userAction: '模型路由被限流（HTTP 429）。这是可重试的传输故障，不是静态边界。',
    })
  }
  if (httpStatus === 408 || httpStatus === 425 || httpStatus === 504
    || lastStatus === 'TIMEOUT' || lastStatus === 'TIMED_OUT'
    || includesMarker(blob, TIMEOUT_MARKERS)) {
    return classOf('MODEL_TIMEOUT', {
      ...base, retryable: true,
      userAction: '模型调用超时（ReadTimeout/ConnectTimeout 或 deadline）。这是传输故障，不是"样本无法静态分析"；可重试或改用更小上下文。',
    })
  }
  if (httpStatus !== null && GATEWAY_STATUSES.has(httpStatus)) {
    return classOf('MODEL_GATEWAY_5XX', {
      ...base, retryable: true,
      userAction: `模型网关返回 ${httpStatus}。这是网关侧故障，不是样本结论。`,
    })
  }
  if (blob.includes('model_not_configured')) {
    return classOf('MODEL_NOT_CONFIGURED', {
      ...base, retryable: false,
      userAction: '没有可用的模型路由（MODEL_NOT_CONFIGURED）。在左下角 设置 → 模型 配置主路由与回退路由；这不是静态分析边界。',
    })
  }
  if (httpStatus !== null || errorType || lastStatus || providerStatus === 'FAILED' || providerStatus === 'CANCELLED'
    || explicitError || errorDetail) {
    if (explicitError === 'MODEL_PROVIDERS_UNAVAILABLE') {
      return classOf('MODEL_NOT_CONFIGURED', {
        ...base, retryable: false,
        userAction: '所有已配置的模型路由都失败了（MODEL_PROVIDERS_UNAVAILABLE）。先看该路由的 error_type / http_status（402、超时、空回复各不相同），这是模型故障，不是静态分析边界。',
      })
    }
    return classOf('MODEL_TRANSPORT', {
      ...base, retryable: false,
      userAction: '模型/传输调用失败。这是模型故障，不是静态分析边界；先看该路由的 error_type / http_status 再决定重试或改配置。',
    })
  }
  return classOf('NONE', { ...base, retryable: false, userAction: '' })
}

/** True when the text names a model/transport fault rather than the sample. */
export function modelTransportFailureInProse(value: unknown): ModelFailureKind {
  const blob = textValue(value, 1200).toLowerCase()
  if (!blob) return 'NONE'
  if (includesMarker(blob, EMPTY_MARKERS)) return 'MODEL_EMPTY_REPLY'
  if (includesMarker(blob, PAYMENT_MARKERS)) return 'MODEL_402_PAYMENT_REQUIRED'
  if (includesMarker(blob, TIMEOUT_MARKERS)) return 'MODEL_TIMEOUT'
  if (includesMarker(blob, RATE_MARKERS)) return 'MODEL_429_RATE_LIMITED'
  if (includesMarker(blob, AUTH_MARKERS)) return 'MODEL_401_AUTH'
  const folded = blob.replace(/[-\s]/g, '_')
  if (folded.includes('model_providers_unavailable') || folded.includes('model_calls_disabled')
    || folded.includes('model_not_configured') || includesMarker(blob, ['模型故障', '模型调用失败', '模型不可用', '网关拒绝'])) {
    return 'MODEL_TRANSPORT'
  }
  return 'NONE'
}

/** Compact, model-facing view of a classification. */
export function modelFailureFields(failure: ModelFailureClass): Record<string, unknown> {
  return {
    failure_kind: failure.kind,
    model_or_transport: failure.observed === 'MODEL_OR_TRANSPORT',
    not_an_analysis_result: failure.not_an_analysis_result,
    distinct_from_static_boundary: failure.distinct_from_static_boundary,
    do_not_collapse: failure.do_not_collapse,
    retryable: failure.retryable,
    http_status: failure.http_status,
    provider_status: failure.provider_status || undefined,
    error_type: failure.error_type || undefined,
    error_detail: failure.error_detail || undefined,
    user_action: failure.user_action || undefined,
    failure_class: failure,
  }
}
