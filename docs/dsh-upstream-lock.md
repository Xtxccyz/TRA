# DSH Upstream Lock

```yaml
dsh_repository: https://github.com/deepseek-ai/deepseek-harness
dsh_commit: 47f943859bef60e4160492346772ded9b24f765a
dsh_version_or_tag: pinned-2026-08-13 (npm-public merge #2519)
observed_upstream_tag: dsh-v0.1.5-rc.2
observed_upstream_commit: fb2c4b9e698e30edb738bca4cf0618587db7d203
node_version: v24.14.0
pnpm_version: 11.7.0
backend_commit: null
backend_source_manifest: ffd2f99764481075950077b279961cc6bae272875f04c1c3ade99622a599bd0e
backend_lock_kind: source-manifest-sha256 (backend checkout has no .git directory)
threat_plugin_api_version: 1
backend_api_version: 1
session_event_version: 1
report_contract_version: 2
```

The source manifest lists every file under backend `src/` and its SHA-256.
Regenerate it before a release when backend source changes. The DSH
clone is kept separately at `C:/Users/王宪韬/Desktop/deepseek-harness` and is
not modified by this project.

## DeepSeek-V41-Flash (do not bump the clone yet)

GitHub `dsh-v0.1.5-rc.1` / `dsh-v0.1.5-rc.2` (2026-09-10) adds official
adapter catalog id `deepseek-flash` (`DeepSeek-V41-Flash`) as the new-session
default, with image modalities and `systemPromptUpdate: in-history`. Old ids
`deepseek-v4-flash` / `deepseek-v4-flash-vision-exp` (and from 2026-09-14
04:00 UTC also `deepseek-v4-pro`) are API-routed to V4.1-Flash until V4.1-Pro
ships.

That tagged Harness is **not** a drop-in checkout for this product:

- Session log format upgrades to V3 (no downgrade read).
- Plugin Agent API removes `ctx.agent`; Inbox is type-only.
- Web `conversation` slot moves under `main`; Detail panel is replaced by Sidebar.
- Threat UI plugins still inject `conversation.view`. Checking out 0.1.5
  without migrating those slots would drop Overview / Investigation / Report.

Stay on the pinned clone. Product adaptation is the isolated-home catalog:

- `threat-dsh-workbench/profiles/threat-static/settings.defaults.yaml`
- live `DSH_HOME/settings.yaml` (`provider: deepseek`, `model: deepseek-flash`)

The Workbench talks to DeepSeek through `llm-pi-ai` route `deepseek`, not
`deepseek-official`. An explicit `models` list is required because the pinned
pi-ai catalog does not advertise `deepseek-flash`. New sessions use that id;
a settings file that still names `deepseek-v4-pro` keeps sending the old id
even after a future Harness bump (config wins over the adapter default).
