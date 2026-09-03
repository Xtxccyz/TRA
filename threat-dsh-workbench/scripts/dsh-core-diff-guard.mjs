import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'

const pinned = '47f943859bef60e4160492346772ded9b24f765a'
const root = resolve(process.env.DSH_HARNESS_ROOT ?? 'C:/Users/王宪韬/Desktop/deepseek-harness')
const paths = ['packages', 'apps', 'native', 'python', 'vendor', 'website', 'scripts']
const rev = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' })
if (rev.status !== 0) throw new Error(`DSH checkout is not a git repository: ${root}`)
const diff = spawnSync('git', ['-C', root, 'diff', '--name-only', pinned, '--', ...paths], { encoding: 'utf8' })
if (diff.status !== 0) throw new Error(`cannot compare DSH checkout against pinned commit ${pinned}`)
const changed = diff.stdout.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
if (changed.length) {
  console.error(JSON.stringify({ pinned, head: rev.stdout.trim(), changed }, null, 2))
  process.exit(1)
}
console.log(JSON.stringify({ pinned, head: rev.stdout.trim(), upstream_core_diff: 0 }))
