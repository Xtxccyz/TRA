import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = process.env.DSH_HARNESS_ROOT ?? 'C:/Users/王宪韬/Desktop/deepseek-harness'
const tsx = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'tsx.cmd' : 'tsx')
if (!existsSync(tsx)) throw new Error(`tsx not found under ${root}; set DSH_HARNESS_ROOT to the pinned DSH checkout`)
const workspace = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const result = spawnSync(tsx, ['--test', 'tests/session-event-bridge.test.ts', 'tests/session-scope-guard.test.ts', 'tests/session-scope-client.test.mjs', 'tests/pluginability-runtime.test.ts', 'tests/tool-provider-runtime.test.ts', 'tests/context-provider-runtime.test.ts', 'tests/model-gateway-runtime.test.ts', 'tests/threat-policy-runtime.test.ts'], {
  cwd: workspace, stdio: 'inherit', shell: process.platform === 'win32',
  env: { ...process.env, TSX_TSCONFIG_PATH: join(root, 'tsconfig.json') },
})
process.exit(result.status ?? 1)
