import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))

test('launcher reuses an active threat-static process instead of interrupting it', async () => {
  const script = await readFile(resolve(root, '../scripts/start-dsh-threat-workbench.ps1'), 'utf8')
  assert.match(script, /Reusing running threat-static process/)
  assert.match(script, /\$dshProcess = if \(\$existingDsh\)/)
  assert.match(script, /\$dshProcessId = if \(\$existingDsh\)/)
  assert.match(script, /Set-Content[\s\S]*\$dshProcessId/)
  assert.match(script, /Get-ThreatWorkbenchBuildId/)
  assert.match(script, /dsh-threat-static-build\.sha256/)
  assert.match(script, /runningBuildId -eq \$script:threatWorkbenchBuildId/)
  assert.doesNotMatch(script, /Stopped stale threat-static process/)
})

test('launcher opens the workbench immediately when the product stack is already healthy', async () => {
  const workbench = await readFile(resolve(root, '../scripts/start-dsh-threat-workbench.ps1'), 'utf8')
  const backend = await readFile(resolve(root, '../scripts/start-threat-report-agent.ps1'), 'utf8')
  assert.match(workbench, /function Test-ThreatBackendRuntime/)
  assert.match(workbench, /Stack already running/)
  assert.match(workbench, /-SkipIfRunning/)
  assert.match(workbench, /BuildApi/)
  const hashAssignAt = workbench.indexOf('$script:threatWorkbenchBuildId = Get-ThreatWorkbenchBuildId')
  const skipAt = workbench.indexOf('Stack already running')
  assert.ok(hashAssignAt > skipAt, 'healthy-stack reuse must not hash the workbench tree first')
  assert.match(backend, /\[switch\]\$SkipIfRunning/)
  assert.match(backend, /Backend already healthy; skipping Docker compose/)
  const skipBlock = backend.slice(backend.indexOf('if ($SkipIfRunning'))
  const composeAt = skipBlock.indexOf('compose up --detach')
  const skipExitAt = skipBlock.indexOf('exit 0')
  const digestAt = skipBlock.indexOf('Get-BackendSourceDigest')
  assert.ok(skipExitAt >= 0, 'SkipIfRunning must exit before compose up')
  assert.ok(composeAt < 0 || skipExitAt < composeAt, 'SkipIfRunning must not reach compose up')
  assert.ok(digestAt < 0 || skipExitAt < digestAt, 'SkipIfRunning must not hash Python before reuse')
  assert.match(skipBlock.slice(0, skipExitAt), /Test-EmuWorkerRunning/)
  assert.doesNotMatch(workbench, /Start-Process "http:\/\/127\.0\.0\.1:8000\//)
})
