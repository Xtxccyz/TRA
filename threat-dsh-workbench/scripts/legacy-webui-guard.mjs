import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'

const root = fileURLToPath(new URL('..', import.meta.url))
const profile = await readFile(resolve(root, 'profiles/threat-static/package.json'), 'utf8')
const bundle = await readFile(resolve(root, 'packages/threat-bundle/cordis.patch.yml'), 'utf8')
const compose = await readFile(resolve(root, '..', 'docker-compose.yml'), 'utf8')

const forbiddenInProfile = [
  'src/threat_report_agent/static',
  'legacy-webui',
  'old-webui',
  'static/app.js',
]
const profileLeaks = forbiddenInProfile.filter((marker) => profile.includes(marker))
const bundleLeaks = forbiddenInProfile.filter((marker) => bundle.includes(marker))

// The backend compatibility UI may remain mounted for old API clients. The
// production DSH profile must never mount it or make it a DSH plugin.
const composeMountsLegacy = /volumes:\s*[\s\S]{0,800}src[\\/]threat_report_agent[\\/]static|static[\\/]app\.js/.test(compose)
if (profileLeaks.length || bundleLeaks.length || composeMountsLegacy) {
  console.error(JSON.stringify({ profileLeaks, bundleLeaks, composeMountsLegacy }, null, 2))
  process.exit(1)
}

const bundles = JSON.parse(profile).dsh?.profile?.bundles ?? []
if (!bundles.includes('@threat-dsh/bundle-workbench')) throw new Error('DSH profile does not load Threat Workbench bundle')
if (bundles.some((name) => /legacy|webui|old/i.test(name))) throw new Error('legacy UI bundle is in the DSH production profile')
console.log(JSON.stringify({ status: 'PASS', dsh_bundle: '@threat-dsh/bundle-workbench', legacy_mounts: 0, compatibility_ui: 'backend-only' }))
