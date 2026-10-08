/**
 * GENERATED FILE - DO NOT EDIT BY HAND.
 *
 * Generator: threat-dsh-workbench/scripts/generate-failure-interpretation.mjs
 * Source:    src/threat_report_agent/contracts.py (class FailureInterpretation)
 * Source SHA-256: 1378bb050c09a20ce1b0158eeb245029a3d083588fe7641956ab0c60e9918a71
 *
 * The DSH track must not keep its own copy of this vocabulary: the backend owns
 * it, and a client that guesses it files a model/transport fault as a statement
 * about the sample. Regenerate with:
 *   node threat-dsh-workbench/scripts/generate-failure-interpretation.mjs
 */

/** SHA-256 of the Python source this file was generated from. */
export const FAILURE_INTERPRETATION_SOURCE_SHA256 = '1378bb050c09a20ce1b0158eeb245029a3d083588fe7641956ab0c60e9918a71' as const

/** The backend's `contracts.FailureInterpretation` member values, in declaration order. */
export const FAILURE_INTERPRETATION_TOKENS = [
  'UNKNOWN',
  'NO_NEW_EVIDENCE',
  'STATIC_BOUNDARY',
  'MODEL_TRANSPORT_FAILURE',
] as const

/** The backend's failure-interpretation vocabulary as a union type. */
export type FailureInterpretation =
  | 'UNKNOWN'
  | 'NO_NEW_EVIDENCE'
  | 'STATIC_BOUNDARY'
  | 'MODEL_TRANSPORT_FAILURE'

/**
 * MODEL_TRANSPORT_FAILURE is a fact about the PLATFORM (a provider 402, a
 * timeout, an empty reply), never a static boundary of the artifact. Only
 * NO_NEW_EVIDENCE and STATIC_BOUNDARY describe the sample. Derived from the
 * union above, so it cannot name a token the backend does not define.
 */
export type ModelTransportFailure = Extract<FailureInterpretation, 'MODEL_TRANSPORT_FAILURE'>
