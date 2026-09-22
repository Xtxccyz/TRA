import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import vm from 'node:vm'

test('report view projects module indicators and limitations without calling candidates verified', async () => {
  const document = { modules: [{ rows: [
    { type: 'mechanism_candidate', status: 'CANDIDATE', target: 'candidate-path' },
    { type: 'ioc', category: 'sha256', value: 'fixture-hash', evidence_ids: ['e1'] },
    { type: 'analysis_limitation', detail: 'Provider unavailable; static results only.' },
    { analysis_coverage: { score: 44.44 } },
  ] }] }
  const states = [{ context: { active_task_id: 'task-1' } }, { revision: { id: 'revision-1', document } }, '']
  let index = 0
  let view
  const React = {
    useState: () => [states[index++], () => {}], useRef: () => ({ current: false }), useEffect: () => {},
    createElement: (type, props, ...children) => ({ type, props, children }),
  }
  const window = { __ModuleLoader__: { load: ({ factory }) => {
    const plugin = factory(() => React)
    plugin.apply({ slots: { inject: (_name, fn) => fn(), register: (_spec, render) => { view = render } } })
  } } }
  const source = await readFile(new URL('../packages/threat-ui-report/client.js', import.meta.url), 'utf8')
  vm.runInNewContext(source, { window })
  const rendered = JSON.stringify(view())
  assert.ok(rendered.includes('fixture-hash'))
  assert.ok(rendered.includes('Provider unavailable; static results only.'))
  assert.ok(rendered.includes('44.44'))
  assert.ok(!rendered.includes('Verified Mechanisms (1)'))
})

test('report view leftover-dumps official markdown instead of a reconstructed second report', async () => {
  const how = 'CreateProcessW command=cmd.exe /c FoxitPDFReader.exe creation_flags=0x000f4240'
  const markdown = `# Official GET report\n\n## How\n${how}\n\n## Unique OS threads\nstart=0x140038ae0\n\n## Unknowns\nHTTP=UNKNOWN\nPPID=UNKNOWN\n`
  const document = { modules: [{ rows: [
    { type: 'mechanism_candidate', status: 'CANDIDATE', target: 'reconstructed-only' },
  ] }] }
  const states = [{ context: { active_task_id: 'task-1' } }, { revision: { id: 'revision-leftover', markdown, document } }, '']
  let index = 0
  let view
  const React = {
    useState: () => [states[index++], () => {}], useRef: () => ({ current: false }), useEffect: () => {},
    createElement: (type, props, ...children) => ({ type, props, children }),
  }
  const window = { __ModuleLoader__: { load: ({ factory }) => {
    const plugin = factory(() => React)
    plugin.apply({ slots: { inject: (_name, fn) => fn(), register: (_spec, render) => { view = render } } })
  } } }
  const source = await readFile(new URL('../packages/threat-ui-report/client.js', import.meta.url), 'utf8')
  vm.runInNewContext(source, { window })
  const rendered = JSON.stringify(view())
  assert.ok(rendered.includes(how))
  assert.ok(rendered.includes('Unique OS threads'))
  assert.ok(rendered.includes('HTTP=UNKNOWN'))
  assert.ok(rendered.includes('leftover-dump'))
  assert.equal(rendered.includes('reconstructed-only'), false)
  assert.equal(rendered.includes('Reconstructed Static Behavior Flow'), false)
})

test('report leftover chrome uses pe path and coverage verified count', async () => {
  const markdown = '# 静态分析报告\n\n## 分析结论\nTarget: Resume.pdf.exe.VIR\n'
  const document = {
    analysis_coverage: { mechanism_count: 28, verified_mechanism_count: 1 },
    modules: [{ rows: [
      { type: 'pe', path: 'Resume.pdf.exe.VIR', sha256: '6bb6bfcb' },
      { type: 'mechanism_candidate', status: 'CANDIDATE', target: 'Resume.pdf.exe.VIR' },
    ] }],
  }
  const states = [{ context: { active_task_id: 'task-1' } }, { revision: { id: 'e9df9d24-c02e-4cec-9dad-096d30d6e960', markdown, document } }, '']
  let index = 0
  let view
  const React = {
    useState: () => [states[index++], () => {}], useRef: () => ({ current: false }), useEffect: () => {},
    createElement: (type, props, ...children) => ({ type, props, children }),
  }
  const window = { __ModuleLoader__: { load: ({ factory }) => {
    const plugin = factory(() => React)
    plugin.apply({ slots: { inject: (_name, fn) => fn(), register: (_spec, render) => { view = render } } })
  } } }
  const source = await readFile(new URL('../packages/threat-ui-report/client.js', import.meta.url), 'utf8')
  vm.runInNewContext(source, { window })
  const rendered = JSON.stringify(view())
  assert.ok(rendered.includes('样本：Resume.pdf.exe.VIR'))
  assert.equal(rendered.includes('未知样本'), false)
  assert.ok(rendered.includes('Verified Mechanisms'))
  assert.ok(rendered.includes('"1"') || rendered.includes('>1<') || /Verified Mechanisms[^]*?"1"/.test(rendered))
})
