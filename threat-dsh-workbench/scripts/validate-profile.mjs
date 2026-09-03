import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const dumpPath = resolve(process.env.DSH_PROFILE_DUMP ?? '../.scratch/dsh-threat-static-dump.txt')
const dump = await readFile(dumpPath, 'utf8')
// Host-side executors (subprocess, *-sandbox) may remain mounted as internal
// services. The gate is about model-facing tool rows only.
const forbidden = new Set(['bash', 'pwsh', 'terminal', 'run_code', 'web_fetch', 'tool-bash', 'tool-pwsh', 'tool-terminal', 'tool-web-fetch', 'tool-subprocess'])
const rows = []
let current
for (const line of dump.split(/\r?\n/)) {
  const id = line.match(/^\s*- id:\s*([^\s#]+)/)?.[1]
  if (id) {
    if (current) rows.push(current)
    current = { id, disabled: false, name: '' }
    continue
  }
  if (!current) continue
  const name = line.match(/^\s*name:\s*['"]?([^'"\s]+)['"]?/)?.[1]
  if (name) current.name = name
  if (/^\s*disabled:\s*true\s*$/.test(line)) current.disabled = true
}
if (current) rows.push(current)
const exposed = rows.filter((row) => !row.disabled && (forbidden.has(row.id) || forbidden.has(row.name.replace(/^@deepseek-ai\/dsh-/, ''))))
if (exposed.length) {
  console.error(JSON.stringify({ dump: dumpPath, exposed }, null, 2))
  process.exit(1)
}
const presetRoot = process.env.THREAT_DSH_PRESETS_ROOT ?? resolve('../threat-dsh-workbench/profiles/threat-static/agent-presets')
const presetPath = resolve(presetRoot, 'threat-static', 'agent.cordis.yml')
const preset = await readFile(presetPath, 'utf8')
const presetForbidden = ['tool-bash', 'tool-pwsh', 'tool-fs', 'tool-fs-search', 'tool-web', 'tool-jobs', 'tool-workflow', 'tool-subagent', 'tool-subagent-fork', 'tool-skill', 'tool-goal', 'tool-todo', 'tool-ralph', 'tool-str-replace-editor', 'tool-ask-user']
const leaked = presetForbidden.filter((id) => new RegExp(`(?:^|\\n)\\s*- id: ${id}\\b`).test(preset))
if (leaked.length) {
  console.error(JSON.stringify({ preset: presetPath, forbidden_rows: leaked }, null, 2))
  process.exit(1)
}
const defaultPreset = preset.match(/(?:^|\\n)\\s*default:\s*([^\\s#]+)/)?.[1]
if (defaultPreset && defaultPreset !== 'threat-static') throw new Error(`unexpected threat-static default preset: ${defaultPreset}`)
console.log(JSON.stringify({ dump: dumpPath, preset: presetPath, dangerous_tools: 0, checked_rows: rows.length }))
