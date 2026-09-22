import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

test('supported Windows entrypoint boots the product workbench, not the upstream desktop app', async () => {
  const entrypoint = await readFile(new URL('../../Start-ThreatReportAgent.bat', import.meta.url), 'utf8')
  assert.match(entrypoint, /start-dsh-threat-workbench\.ps1/i)
  assert.doesNotMatch(entrypoint, /DSH Desktop\.exe/i)
  assert.doesNotMatch(entrypoint, /deepseek-harness.*desktop/i)
})

test('workbench launcher opens only the product URL after validating DSH identity', async () => {
  const launcher = await readFile(new URL('../../scripts/start-dsh-threat-workbench.ps1', import.meta.url), 'utf8')
  assert.match(launcher, /Test-ThreatWorkbenchRuntime/)
  assert.match(launcher, /127\.0\.0\.1:\$DshPort\//)
  assert.match(launcher, /Start-Process "http:\/\/127\.0\.0\.1:\$DshPort\//)
  assert.doesNotMatch(launcher, /Start-Process "http:\/\/127\.0\.0\.1:8000\//)
  const readyLoop = launcher.slice(launcher.indexOf('$ready = $false'))
  assert.match(readyLoop, /if \(Test-ThreatWorkbenchRuntime\) \{ \$ready = \$true; break \}/)
  assert.doesNotMatch(readyLoop, /if \(\$response\.StatusCode -eq 200\)/)
})

test('workbench launcher roots new DSH sessions in the product checkout', async () => {
  const launcher = await readFile(new URL('../../scripts/start-dsh-threat-workbench.ps1', import.meta.url), 'utf8')
  assert.match(launcher, /-WorkingDirectory \$dshRoot/)
  assert.match(launcher, /tsxLoader/)
  assert.match(launcher, /tsxLoaderUrl/)
  assert.match(launcher, /--import', \$tsxLoaderUrl/)
  assert.match(launcher, /TSX_TSCONFIG_PATH/)
  assert.match(launcher, /Test-ForeignDshSessionState/)
  assert.match(launcher, /Quarantine-ForeignDshSessions/)
  assert.match(launcher, /dsh-quarantine/)
  assert.match(launcher, /DSH_HOME\s*=\s*\$threatDshHome/)
})

test('launcher canonicalizes junction aliases and can prepare the profile without Docker', async () => {
  const launcher = await readFile(new URL('../../scripts/start-dsh-threat-workbench.ps1', import.meta.url), 'utf8')
  assert.match(launcher, /function Resolve-CanonicalPath/)
  assert.match(launcher, /function Normalize-PathForComparison/)
  assert.match(launcher, /function Test-DirectoryLinkEntry/)
  assert.match(launcher, /PrepareOnly/)
  assert.match(launcher, /Profile preparation succeeded/)
  assert.match(launcher, /Normalize-PathForComparison \$link\.Target/)
})

test('Windows prepare mode resolves the profile link to this checkout', async (t) => {
  if (process.platform !== 'win32') return t.skip('Windows launcher only')
  const harnessRoot = process.env.DSH_HARNESS_ROOT ?? join(process.env.USERPROFILE ?? '', 'Desktop', 'deepseek-harness')
  if (!existsSync(join(harnessRoot, 'node_modules', 'tsx', 'dist', 'esm', 'index.mjs'))) {
    return t.skip('pinned DSH checkout is unavailable')
  }

  const home = await mkdtemp(join(tmpdir(), 'threat-workbench-launcher-'))
  const productRoot = resolve(root, '..')
  const launcher = existsSync('D:\\threat-agent\\scripts\\start-dsh-threat-workbench.ps1')
    ? 'D:\\threat-agent\\scripts\\start-dsh-threat-workbench.ps1'
    : resolve(root, '../scripts/start-dsh-threat-workbench.ps1')
  try {
    const result = await new Promise((resolveResult, reject) => {
      const child = spawn('powershell.exe', [
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', launcher, '-PrepareOnly',
      ], {
        env: { ...process.env, THREAT_DSH_HOME: home, DSH_HARNESS_ROOT: harnessRoot },
        windowsHide: true,
      })
      let stdout = ''
      let stderr = ''
      child.stdout.on('data', (chunk) => { stdout += chunk })
      child.stderr.on('data', (chunk) => { stderr += chunk })
      child.once('error', reject)
      child.once('close', (code) => resolveResult({ code, stdout, stderr }))
    })
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`)
    assert.match(result.stdout, /Profile preparation succeeded/i)
    assert.equal(await realpath(join(home, 'profiles', 'threat-static', 'agent')), await realpath(productRoot))
  } finally {
    await rm(home, { recursive: true, force: true })
  }
})
