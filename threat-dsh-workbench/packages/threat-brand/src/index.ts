import type { ThreatPluginManifest } from '@threat-dsh/plugin-sdk'
import type { Context } from '@deepseek-ai/cordis'

/** Product-owned identity and presentation boundary for the Threat Workbench. */
export const manifest: ThreatPluginManifest = {
  id: 'threat-brand',
  version: '1.0.0',
  plugin_api: 1,
  capabilities: ['view'],
  required_backend_api: '>=1,<2',
  required_event_schema: 1,
  security_profile: ['threat-static'],
}

/** Product-owned favicon. It is inline so the standalone profile has no asset dependency. */
export const PRODUCT_FAVICON = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"%3E%3Cpath fill="%230b6bcb" d="M16 2 28 7v8c0 7.7-5 12.7-12 15C9 27.7 4 22.7 4 15V7z"/%3E%3Cpath fill="%23fff" d="m10 16 4 4 8-9-2-2-6 7-2-2z"/%3E%3C/svg%3E'

/** Rewrite upstream static HTML before it reaches the browser. */
export function transformIndexHtml(html: string): string {
  const title = '<title>\u5a01\u80c1\u5206\u6790\u5de5\u4f5c\u53f0</title>'
  const favicon = `<link rel="icon" type="image/svg+xml" href="${PRODUCT_FAVICON}" />`
  const withTitle = /<title>[^<]*<\/title>/i.test(html)
    ? html.replace(/<title>[^<]*<\/title>/i, title)
    : html.replace(/<head>/i, `<head>${title}`)
  const withoutLegacyIcon = withTitle.replace(/<link[^>]+rel=["'](?:icon|shortcut icon)["'][^>]*>/gi, '')
  return withoutLegacyIcon.replace(/<head>/i, `<head>${favicon}`)
}

/** Host half owns the response transform; browser identity is installed by `./client`. */
export const inject = ['webServer']
interface WebServerContext {
  webServer: { tapIndex(transform: (html: string) => string): () => void }
}
export function apply(ctx: Context): void {
  ;(ctx as unknown as WebServerContext).webServer.tapIndex(transformIndexHtml)
}
