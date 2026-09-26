/**
 * The first-request investigation protocol (B04 / M03).
 *
 * ONE user message -- 「分析这个样本」 -- has to produce a multi-step autonomous
 * investigation: questions, actions, evidence deltas, and either new evidence
 * or a concrete blocker, without a second nudge. That obligation used to exist
 * only as prose inside the preset persona, so nothing could version it, send it,
 * or check that it arrived.
 *
 * This module makes it one versioned instruction with three consumers:
 *
 *  1. ``firstRequestInvestigationProtocol().system_instruction`` is the system
 *     message ``threat_workbench_model_complete`` sends to the backend gateway,
 *     and ``digest`` is the ``prompt_sha256`` recorded for that call -- so the
 *     instruction that actually took effect is auditable in the stored request;
 *  2. the compact projection (``firstRequestProtocolPacket``) rides in the
 *     first-turn ``threat_analysis_context`` packet every turn, so the DSH
 *     conversation model works from the same versioned obligations;
 *  3. the ten question slots are the canonical list the gap packet's
 *     ``unanswered_ten_question_slots`` is built from.
 *
 * Terminology is load-bearing: an *investigation thread* is a question work
 * unit, an *OS execution thread* is a sample object (CreateThread/APC/TLS/
 * timer). Model/transport failures are never analysis results, and isolated
 * Unicorn/Speakeasy/Qiling is static analysis, never dynamic execution.
 */
import { createHash } from 'node:crypto'

import { MODEL_FAILURE_CONTRACT_VERSION } from './model-failure.ts'

export const FIRST_REQUEST_PROTOCOL_ID = 'first-request-autonomous-deep-dive'
export const FIRST_REQUEST_PROTOCOL_VERSION = '1.0.0'

export interface InvestigationQuestionSlot {
  readonly slot: string
  readonly question: string
}

/** The ten questions a high-value investigation thread must answer or name. */
export const TEN_INVESTIGATION_QUESTIONS: readonly InvestigationQuestionSlot[] = Object.freeze([
  Object.freeze({ slot: 'initiator', question: 'Who starts or registers this behavior?' }),
  Object.freeze({ slot: 'input', question: 'What input, buffer, or handle reaches it?' }),
  Object.freeze({ slot: 'state_config', question: 'What state or configuration does it use?' }),
  Object.freeze({ slot: 'transformation', question: 'What transform or control-flow step is recovered?' }),
  Object.freeze({ slot: 'condition', question: 'What condition gates success, failure, or a branch?' }),
  Object.freeze({ slot: 'side_effect', question: 'What side effect is statically visible?' }),
  Object.freeze({ slot: 'output', question: 'What output object or bytes are produced?' }),
  Object.freeze({ slot: 'consumer', question: 'Who consumes that output?' }),
  Object.freeze({ slot: 'loop', question: 'Is there a loop, back-edge, or repetition?' }),
  Object.freeze({ slot: 'failure_fallback', question: 'What happens on failure or the fallback path?' }),
])

export interface FirstRequestInvestigationProtocol {
  readonly protocol_id: string
  readonly version: string
  /** SHA-256 of ``system_instruction``: the identity of the effective prompt. */
  readonly digest: string
  readonly question_slots: readonly InvestigationQuestionSlot[]
  readonly obligations: Readonly<Record<string, boolean>>
  readonly thread_model: Readonly<Record<string, string | number | boolean>>
  readonly stop_rule: Readonly<Record<string, string | boolean>>
  readonly failure_contract_version: string
  readonly system_instruction: string
}

const OBLIGATIONS: Readonly<Record<string, boolean>> = Object.freeze({
  one_request_is_a_multi_step_investigation: true,
  competing_hypotheses: true,
  failure_fallback: true,
  evidence_or_named_reason_per_slot: true,
  evidence_delta_per_action: true,
  action_before_question_is_closed: true,
  persisted_frontier: true,
  next_step_or_concrete_blocker: true,
  no_result_is_not_a_negative_result: true,
  canary_free: true,
})

const THREAD_MODEL: Readonly<Record<string, string | number | boolean>> = Object.freeze({
  investigation_thread: 'question work unit',
  os_execution_thread: 'CreateThread/APC/TLS/timer execution object in the sample',
  os_thread_is_not_investigation_thread: true,
  distinct_thread_floor: 3,
  same_method_replay_forbidden: true,
  parallel_threads_share_case_evidence: true,
  decode_consumer_is_a_mandatory_join: true,
})

const STOP_RULE: Readonly<Record<string, string | boolean>> = Object.freeze({
  on_no_new_evidence: 'switch method family or state a concrete boundary',
  on_model_or_transport_failure: 'report the model failure as a model failure; it is not a boundary, not a negative result, and not evidence',
  on_static_boundary: 'name the missing input, unsupported capability, or missing consumer; never write "超出静态能力" alone',
  one_user_request_is_enough: true,
  do_not_wait_for_second_message: true,
  isolated_emulation_is_static: true,
})

/**
 * Deterministic text. It IS the instruction: the digest identity, the packet
 * projection and the model-complete system message are all derived from it, so
 * there is exactly one place an obligation can be edited.
 */
function renderSystemInstruction(): string {
  const questions = TEN_INVESTIGATION_QUESTIONS
    .map((item, index) => `  ${index + 1}. ${item.slot}: ${item.question}`)
    .join('\n')
  return [
    `You are the investigation planner and claims writer for one bound static-analysis task.`,
    `Effective protocol: ${FIRST_REQUEST_PROTOCOL_ID} v${FIRST_REQUEST_PROTOCOL_VERSION}.`,
    `ONE user request ("分析这个样本") must produce the whole first round: questions, actions, evidence deltas and either new evidence or a concrete blocker. Do not wait for a second message such as 再深入.`,
    ``,
    `Work every high-value investigation thread through these ten questions, and for each one record either evidence or an explicit UNKNOWN / N-A with the reason and what you tried:`,
    questions,
    ``,
    `Rules:`,
    `- Competing hypotheses are mandatory: name the leading explanation and at least one credible alternative, then pick the action that separates them by information gain.`,
    `- Every action declares a question, hypothesis, alternatives, missing_evidence, success_condition and failure_meaning; record the evidence delta it produced (EVIDENCE_GAIN, HYPOTHESIS_NARROWED, NO_NEW_EVIDENCE, MISSING_INPUT, POLICY_DENIED, BUDGET_EXHAUSTED).`,
    `- NO_NEW_EVIDENCE means the method failed, not the sample: switch to a different method family for the same slot, or state a concrete boundary. Never report it as a negative result.`,
    `- Keep the frontier persisted as you go (session note + proposed actions) so the next turn continues the investigation instead of restarting it.`,
    `- An investigation thread is a question work unit; it is NOT an OS execution thread. CreateThread / APC / TLS / timer callbacks are sample objects to recover (start routine, parameter, shared state, loop, cleanup) and are distinct from the investigation threads that ask about them.`,
    `- Recover how objects relate: initiator, parameter binding, shared state, indirect calls, output, and the consumer of every decoded buffer. A decode_result with no recoverable consumer is an open consumer slot, not a closed decode.`,
    `- Failure and fallback branches are part of the mechanism, not a footnote.`,
    `- Static only: reading, parsing, decoding and disassembling bytes. Unicorn / Speakeasy / Qiling over a granted window on the isolated worker is static analysis and produces EMULATION_OBSERVED, never DYNAMIC_OBSERVED. Never self-authorize an emulation window.`,
    `- A model or transport failure (HTTP 402, timeout, empty reply, gateway refusal) is a fault of the model route. It is not evidence, not a static boundary, not POLICY_DENIED, and it must never be recorded as a product effect or as a finding about the sample.`,
    `- Answer with the structured envelope only; do not invent Evidence IDs, endpoints, or model provenance.`,
  ].join('\n')
}

let cached: FirstRequestInvestigationProtocol | undefined

/** The one versioned first-request instruction. */
export function firstRequestInvestigationProtocol(): FirstRequestInvestigationProtocol {
  if (cached) return cached
  const system_instruction = renderSystemInstruction()
  cached = Object.freeze({
    protocol_id: FIRST_REQUEST_PROTOCOL_ID,
    version: FIRST_REQUEST_PROTOCOL_VERSION,
    digest: createHash('sha256').update(system_instruction, 'utf8').digest('hex'),
    question_slots: TEN_INVESTIGATION_QUESTIONS,
    obligations: OBLIGATIONS,
    thread_model: THREAD_MODEL,
    stop_rule: STOP_RULE,
    failure_contract_version: MODEL_FAILURE_CONTRACT_VERSION,
    system_instruction,
  })
  return cached
}

/**
 * Compact projection for the first-turn packet. The full instruction text is
 * deliberately not inlined here -- the packet is bounded and the digest is its
 * identity -- but the obligations, the ten slots and the stop rule are.
 */
export function firstRequestProtocolPacket(): Record<string, unknown> {
  const protocol = firstRequestInvestigationProtocol()
  return {
    protocol_id: protocol.protocol_id,
    version: protocol.version,
    digest: protocol.digest,
    system_instruction_digest: protocol.digest,
    question_slots: protocol.question_slots.map((item) => ({ slot: item.slot, question: item.question })),
    obligations: protocol.obligations,
    thread_model: protocol.thread_model,
    stop_rule: protocol.stop_rule,
    failure_contract_version: protocol.failure_contract_version,
    instruction_carrier: 'threat_workbench_model_complete',
  }
}
