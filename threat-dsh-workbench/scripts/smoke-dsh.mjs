import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const harnessRoot = resolve(process.env.DSH_HARNESS_ROOT ?? 'C:/Users/王宪韬/Desktop/deepseek-harness')
const workbenchRoot = fileURLToPath(new URL('..', import.meta.url))
// 53471 is reserved by some Windows security policies. Keep the smoke
// harness on a high, unprivileged port while retaining DSH_SMOKE_PORT as an
// override for CI or a host with a different port policy.
const port = Number(process.env.DSH_SMOKE_PORT ?? 58473)
const env = {
  ...process.env,
  DSH_HOME: process.env.DSH_HOME ?? resolve(workbenchRoot, '../.data/dsh-threat-static'),
  THREAT_DSH_PRESETS_ROOT: process.env.THREAT_DSH_PRESETS_ROOT ?? resolve('../threat-dsh-workbench/profiles/threat-static/agent-presets'),
}
const tsx = resolve(harnessRoot, 'node_modules/tsx/dist/cli.mjs')
const child = spawn(process.execPath, [tsx, 'apps/cli/src/bin.ts', '--profile', 'threat-static', '--port', String(port), '--host', '127.0.0.1'], {
  cwd: harnessRoot, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
})
let stdout = ''
let stderr = ''
let spawnError = ''
let exited = false
let bootHtml = ''
child.stdout.on('data', (chunk) => { stdout += String(chunk) })
child.stderr.on('data', (chunk) => { stderr += String(chunk) })
child.on('error', (error) => { spawnError = String(error) })
child.on('exit', () => { exited = true })
const fetchWithTimeout = async (url, timeoutMs = 1500) => {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try { return await fetch(url, { signal: controller.signal }) } finally { clearTimeout(timer) }
}
const deadline = Date.now() + 60000
let ready = false
const requiredPlugins = ['overview', 'investigation', 'mechanisms', 'sample-timeline', 'evidence', 'report', 'brand']
const pluginId = (name) => name === 'brand' ? '@threat-dsh/brand' : `@threat-dsh/ui-${name}`
while (Date.now() < deadline) {
  if (exited) break
  try {
    const response = await fetchWithTimeout(`http://127.0.0.1:${port}/`)
    if (response.ok) {
      bootHtml = await response.text()
      const title = bootHtml.match(/<title>[^<]*<\/title>/i)?.[0] ?? ''
      const productIdentity = title === '<title>\u5a01\u80c1\u5206\u6790\u5de5\u4f5c\u53f0</title>' &&
        !/DeepSeek Harness/i.test(bootHtml) && !/\/favicon\.svg/i.test(bootHtml)
      const results = await Promise.all(requiredPlugins.map(async (name) => {
        const plugin = pluginId(name)
        const bundle = await fetchWithTimeout(`http://127.0.0.1:${port}/plugins/${plugin}/client.js`)
        const body = await bundle.text()
        return bundle.ok && body.includes('window.__ModuleLoader__.load')
      }))
      ready = productIdentity && results.every(Boolean)
      if (ready) break
    }
  } catch {}
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 250))
}
if (!child.killed) child.kill('SIGTERM')
const clientPlugins = requiredPlugins.filter((name) => bootHtml.includes(pluginId(name)))
const title = bootHtml.match(/<title>[^<]*<\/title>/i)?.[0] ?? ''
process.stdout.write(JSON.stringify({
  ready,
  title,
  legacy_visible_text: /DeepSeek Harness/i.test(bootHtml),
  legacy_favicon: /\/favicon\.svg/i.test(bootHtml),
  client_plugins: clientPlugins,
  html_bytes: bootHtml.length,
  html_preview: bootHtml.slice(0, 1000),
  spawnError,
  stdout: stdout.slice(-4000),
  stderr: stderr.slice(-4000),
}, null, 2) + '\n')
if (!ready) process.exit(1)
