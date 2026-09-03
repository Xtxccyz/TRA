import { readFile } from 'node:fs/promises'

const root = new URL('..', import.meta.url)
const packageFiles = [
  'packages/threat-plugin-sdk/package.json', 'packages/threat-api-client/package.json',
  'packages/threat-tool-provider/package.json', 'packages/threat-session-events/package.json',
  'packages/threat-bundle/package.json', 'examples/threat-plugin-template/package.json',
  'packages/threat-policy/package.json', 'packages/threat-jobs/package.json',
  'packages/threat-context-provider/package.json', 'packages/threat-model-gateway/package.json',
  'packages/threat-ui-overview/package.json', 'packages/threat-ui-investigation/package.json',
  'packages/threat-ui-mechanisms/package.json', 'packages/threat-ui-sample-timeline/package.json',
  'packages/threat-ui-evidence/package.json', 'packages/threat-ui-report/package.json',
  'packages/threat-brand/package.json',
  'packages/threat-context-store/package.json',
]
for (const file of packageFiles) {
  const pkg = JSON.parse(await readFile(new URL(file, root), 'utf8'))
  if (!pkg.name || pkg.private !== true || pkg.type !== 'module') throw new Error(`invalid package manifest: ${file}`)
  if (file.includes('threat-ui-') || file.includes('threat-brand') || file.includes('threat-plugin-template')) {
    if (pkg.dsh?.client?.platform !== 'web') throw new Error(`client platform missing: ${file}`)
    if (!pkg.exports?.['./client']) throw new Error(`client export missing: ${file}`)
  }
}
const profile = JSON.parse(await readFile(new URL('profiles/threat-static/package.json', root), 'utf8'))
if (profile.dsh?.profile?.bundles?.at(-1) !== '@threat-dsh/bundle-workbench') throw new Error('threat-static profile does not load Threat bundle')
console.log(`validated ${packageFiles.length} package manifests and threat-static profile`)
