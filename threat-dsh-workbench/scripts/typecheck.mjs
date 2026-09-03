import { existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const workspace = dirname(here)
const candidates = [
  process.env.DSH_HARNESS_ROOT,
  join(workspace, '..', 'deepseek-harness'),
  'C:/Users/王宪韬/Desktop/deepseek-harness',
].filter(Boolean)
const tsc = candidates
  .map((root) => join(root, 'node_modules', 'typescript', 'bin', 'tsc'))
  .find((candidate) => existsSync(candidate))
if (!tsc) {
  console.error('TypeScript compiler not found. Set DSH_HARNESS_ROOT to the pinned DeepSeek Harness checkout.')
  process.exit(1)
}
const result = spawnSync(process.execPath, [tsc, '--noEmit', '--project', join(workspace, 'tsconfig.json')], {
  cwd: workspace,
  stdio: 'inherit',
})
process.exit(result.status ?? 1)
