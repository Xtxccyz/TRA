import assert from 'node:assert/strict'
import test from 'node:test'
import { apply as applyHost, appendPluginTestEvent } from '../examples/threat-plugin-template/src/index.ts'
import { apply as applyClient } from '../examples/threat-plugin-template/src/client.ts'
import { ThreatSessionEventBridge } from '../packages/threat-session-events/src/index.ts'

class RuntimeHarness {
  readonly tools = new Map<string, any>()
  readonly entries = new Map<string, any[]>()
  readonly disposers: (() => void)[] = []
  readonly sessionEvents: Record<string, unknown>[] = []
  readonly ctx = {
    tools: { register: (tool: any) => {
      if (this.tools.has(tool.name)) throw new Error(`duplicate tool ${tool.name}`)
      this.tools.set(tool.name, tool)
      const dispose = () => this.tools.delete(tool.name)
      this.disposers.push(dispose)
      return dispose
    } },
    slots: {
      inject: (_name: string, register: () => unknown) => register(),
      register: (options: Record<string, unknown>, component: (props?: unknown) => unknown) => {
        const name = String(options.name)
        const row = { options, component }
        const list = this.entries.get(name) ?? []
        list.push(row)
        this.entries.set(name, list)
        const dispose = () => this.entries.set(name, (this.entries.get(name) ?? []).filter((item) => item !== row))
        this.disposers.push(dispose)
        return dispose
      },
    },
  }
  dispose(): void { for (const dispose of this.disposers.splice(0)) dispose() }
}

test('acceptance plugin registers, executes, projects, replays, and unloads cleanly', async () => {
  const runtime = new RuntimeHarness()
  applyHost(runtime.ctx as never)
  applyClient(runtime.ctx as never)
  const tool = runtime.tools.get('threat_echo_evidence_summary')
  assert.ok(tool, 'plugin tool is visible after load')
  assert.deepEqual(await tool.execute({ task_id: 'task-1', evidence_count: 999 }), { task_id: 'task-1', evidence_count: 500 })
  assert.equal(runtime.entries.get('conversation.view')?.[0]?.options.id, 'plugin-test')

  const durable = { append: (type: string, data: Record<string, unknown>) => runtime.sessionEvents.push({ type, data }) }
  appendPluginTestEvent(durable, 'task-1')
  const replayed: Record<string, unknown>[] = []
  const bridge = new ThreatSessionEventBridge({
    events: async () => ({ schema_version: 1, task_id: 'task-1', events: [{ seq: 1, type: 'plugin-test', task_id: 'task-1', payload_summary: { status: 'READY' } }], next_seq: 1, has_more: false }),
  }, { append: (type, data) => replayed.push({ type, ...data }) })
  assert.deepEqual(await bridge.sync('task-1'), { appended: 1, nextSeq: 1 })
  assert.equal(replayed[0]?.type, 'threat/plugin-test')

  runtime.dispose()
  assert.equal(runtime.tools.has('threat_echo_evidence_summary'), false)
  assert.equal(runtime.entries.get('conversation.view')?.length ?? 0, 0)
})
