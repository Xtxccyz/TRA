import test from 'node:test'
import assert from 'node:assert/strict'
import { buildMechanismDebugRows, buildMechanismViewModel } from '../packages/threat-ui-mechanisms/src/index'
import { buildEvidenceFunnelRows } from '../packages/threat-ui-evidence/src/index'
import { buildHypothesisHistory } from '../packages/threat-ui-investigation/src/index'

test('mechanism view exposes bounded debug funnel and verifier state', () => {
  const view = buildMechanismViewModel({ id: 'm1', type: 'ETW_PATCH', status: 'CONFIRMED', completeness_score: 90, evidence_ids: ['e1', 'e2'], verifier: { status: 'VERIFIED' } })
  assert.equal(view.type, 'ETW_PATCH')
  assert.equal(view.requirements.verified, 1)
  assert.equal(buildMechanismDebugRows({ id: 'm1', verifier: { status: 'VERIFIED' } }).length, 5)
})

test('evidence funnel keeps explicit exclusion visible', () => {
  const rows = buildEvidenceFunnelRows([
    { evidence_id: 'e1', stage: 'CANDIDATE', exclusion_reason: 'out_of_scope' },
    { evidence_id: 'e1', stage: 'DELIVERED' },
  ])
  assert.equal(rows[0].delivered, true)
  assert.equal(rows[0].exclusion_reason, 'out_of_scope')
})

test('hypothesis history is bounded to evidence references', () => {
  const history = buildHypothesisHistory([{ status: 'SUPPORTED', confidence: 'HIGH', evidence_ids: ['e1', 'e2', 'e3', 'e4', 'e5', 'e6'] }])
  assert.equal(history[0].evidence_ids.length, 5)
})
