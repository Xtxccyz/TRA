import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

test('threat-static persona requires convergent, evidence-seeking first-pass investigation', async () => {
  const source = await readFile(new URL('../profiles/threat-static/agent-presets/threat-static/agent.cordis.yml', import.meta.url), 'utf8')
  for (const token of [
    'autonomous', 'information-gain', 'initiator', 'consumer', 'failure/fallback',
    'EVIDENCE_GAIN', 'HYPOTHESIS_NARROWED', 'MISSING_INPUT', 'POLICY_DENIED',
    'BUDGET_EXHAUSTED', 'NO_NEW_EVIDENCE', 'frontier item', 'model/provider errors',
  ]) assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), `missing convergence requirement: ${token}`)
  assert.match(source, /Do not expose private\s+chain-of-thought/)
  assert.match(source, /successful static run\s+is not dynamic execution/)
  assert.match(source, /Settings → 模型/)
  assert.match(source, /no separate analysis-planner/)
  assert.match(source, /failure_interpretation must be exactly UNKNOWN,\s*NO_NEW_EVIDENCE, or STATIC_BOUNDARY/)
  assert.match(source, /absent from that\s+revision markdown/)
  assert.match(source, /older SUCCEEDED\s+task for the same SHA256/)
  assert.match(source, /do not quote a previous task's\s+report/)
  assert.match(source, /SUCCEEDED,\s*FAILED, or CANCELLED/)
  assert.match(source, /authoritative_revision_id/)
  assert.match(source, /first factual reply/)
  assert.match(source, /Do not summarize from\s+memory/)
  assert.doesNotMatch(source, /Settings → 分析规划 page/)
  assert.match(source, /threat_workbench_model_complete/)
  assert.match(source, /threat_write_session_note/)
  assert.match(source, /CONVERGED/)
  assert.match(source, /Do not call threat_propose_static_action after that summary/)
  assert.match(source, /Ghidra not IDA/)
  assert.match(source, /Packer latch/)
  assert.match(source, /IAT is hypothesis/)
  assert.match(source, /CREATE_SUSPENDED/)
  assert.match(source, /explorer\.exe/)
  assert.match(source, /CONTROLLED_EMULATE is isolated static/)
  assert.doesNotMatch(source, /Once analysis is ready, read\s+threat_get_thread_context/)
  assert.doesNotMatch(source, /keep reading thread_context\/task_gaps/)
  assert.match(source, /^\s*- id: tool-todo\b/m)
  assert.match(source, /^\s*- id: tool-ask-user\b/m)
  for (const blocked of ['tool-fs', 'tool-bash', 'tool-pwsh', 'tool-web', 'tool-subagent', 'tool-workflow']) {
    assert.doesNotMatch(source, new RegExp(`(?:^|\\n)\\s*- id: ${blocked}\\b`))
  }
})

test('persona and tool-provider keep 402/timeout, policy denial, and STATIC_BOUNDARY distinct; STOP after CONVERGED forbids GET_DECOMPILE', async () => {
  const persona = await readFile(new URL('../profiles/threat-static/agent-presets/threat-static/agent.cordis.yml', import.meta.url), 'utf8')
  const tools = await readFile(new URL('../packages/threat-tool-provider/src/index.ts', import.meta.url), 'utf8')
  assert.match(persona, /402\/timeout/)
  assert.match(persona, /do not downgrade into POLICY_DENIED or STATIC_BOUNDARY/)
  assert.match(persona, /then\s+STOP[\s\S]{0,280}GET_DECOMPILE/)
  assert.match(persona, /Do not write to the desktop/)
  assert.match(tools, /A timeout is not a report, not POLICY_DENIED, and not STATIC_BOUNDARY/)
  assert.match(tools, /then STOP[\s\S]{0,220}GET_DECOMPILE/i)
  assert.match(tools, /Do not write to the desktop/)
  assert.match(tools, /STOP_DISPATCH/)
})
