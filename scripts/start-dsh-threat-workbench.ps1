[CmdletBinding()]
param(
    [switch]$BuildApi,
    [switch]$BuildGhidra,
    [int]$DshPort = 3080,
    [int]$DockerTimeoutSeconds = 180,
    [int]$DshTimeoutSeconds = 60,
    [switch]$NoBrowser,
    [switch]$PrepareOnly
)

$ErrorActionPreference = "Stop"

function Remove-TrailingDirectorySeparators([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -match '^[A-Za-z]:\\$' -or $full -match '^\\\\[^\\]+\\[^\\]+\\$') {
        return $full
    }
    return ($full -replace '[\\/]+$', '')
}

function Resolve-CanonicalPath([string]$Path) {
    # Junction targets can themselves be junctions (for example the historical
    # D:\threat-agent alias). Follow a bounded chain so ownership checks compare
    # the physical product root rather than the path used to launch the script.
    $candidate = Remove-TrailingDirectorySeparators $Path
    $seen = @{}
    for ($depth = 0; $depth -lt 8; $depth++) {
        $key = $candidate.ToUpperInvariant()
        if ($seen.ContainsKey($key)) { break }
        $seen[$key] = $true
        try {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        } catch {
            break
        }
        if ($item.LinkType -eq 'Junction' -and $item.Target) {
            $candidate = Remove-TrailingDirectorySeparators ([string]$item.Target)
            continue
        }
        $candidate = Remove-TrailingDirectorySeparators ([string]$item.FullName)
        break
    }
    return $candidate
}

function Normalize-PathForComparison([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return (Resolve-CanonicalPath $Path).ToUpperInvariant()
}

function Test-DirectoryLinkEntry([string]$Path) {
    # `Get-Item` cannot open a broken junction because it follows the target.
    # `dir /a:l` inspects only the parent directory entry and is safe for the
    # marker-protected product home.
    $parent = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    # Keep `2>nul` inside cmd's command string. A PowerShell-level redirect
    # would turn the normal "File Not Found" result into a terminating native
    # error under this launcher's strict error policy.
    $entries = @(& cmd.exe /d /c "dir /a:l /b `"$parent`" 2>nul")
    return $entries -contains $leaf
}

# `D:\threat-agent` was historically exposed as a junction to this checkout.
# Resolve it once so profile links, PID ownership, and process checks all use
# the same canonical product path regardless of which launcher path is clicked.
$projectRoot = Resolve-CanonicalPath (Split-Path -Parent $PSScriptRoot)
$dshRoot = if ($env:DSH_HARNESS_ROOT) { $env:DSH_HARNESS_ROOT } else { Join-Path $env:USERPROFILE 'Desktop\deepseek-harness' }
$dshRoot = [System.IO.Path]::GetFullPath($dshRoot)
$threatDshHome = if ($env:THREAT_DSH_HOME) { [System.IO.Path]::GetFullPath($env:THREAT_DSH_HOME) } else { Join-Path $projectRoot '.data\dsh-threat-static' }
$tsx = Join-Path $dshRoot 'node_modules\tsx\dist\cli.mjs'
$tsxLoader = Join-Path $dshRoot 'node_modules\tsx\dist\esm\index.mjs'
$tsxLoaderUrl = ([System.Uri]::new($tsxLoader)).AbsoluteUri
$dshBin = Join-Path $dshRoot 'apps\cli\src\bin.ts'
$pidFile = Join-Path $projectRoot '.scratch\dsh-threat-static.pid'
$buildFile = Join-Path $projectRoot '.scratch\dsh-threat-static-build.sha256'
$dshStdout = Join-Path $projectRoot '.scratch\dsh-threat-static-stdout.log'
$dshStderr = Join-Path $projectRoot '.scratch\dsh-threat-static-stderr.log'
$threatHomeMarker = Join-Path $threatDshHome '.threat-workbench-home-v1'
$env:THREAT_BACKEND_URL = if ($env:THREAT_BACKEND_URL) { $env:THREAT_BACKEND_URL } else { 'http://127.0.0.1:8000' }
$env:THREAT_DSH_PRESETS_ROOT = Join-Path $projectRoot 'threat-dsh-workbench\profiles\threat-static\agent-presets'
$env:DSH_HOME = $threatDshHome
# tsx uses the Harness solution config for its workspace path aliases. Keep
# this explicit because the DSH process intentionally runs with the product
# checkout as cwd, not the upstream Harness checkout.
$env:TSX_TSCONFIG_PATH = Join-Path $dshRoot 'tsconfig.json'

function Initialize-ThreatOwnedState {
    # The directory is product-owned, so a first-run migration can remove
    # state created by an earlier DSH experiment without touching %USERPROFILE%\.dsh.
    if (Test-Path -LiteralPath $threatHomeMarker) { return }
    New-Item -ItemType Directory -Force -Path $threatDshHome | Out-Null
    foreach ($relativePath in @('sessions', 'storages', '.credentials.yaml', '.anonymous-user-id', 'settings.yaml')) {
        $target = Join-Path $threatDshHome $relativePath
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
    }
    [System.IO.File]::WriteAllText(
        $threatHomeMarker,
        "Threat Workbench isolated home initialized $(Get-Date -Format o)`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Host "[Threat Workbench] Cleared pre-product state from isolated home: $threatDshHome" -ForegroundColor DarkCyan
}

function Ensure-ThreatDefaultSettings {
    # Isolated DSH_HOME is gitignored. Seed the conversation catalog so a
    # first launch can select DeepSeek-V41-Flash (`deepseek-flash`) instead of
    # only the pinned pi-ai V4 Flash / V4 Pro names.
    $settingsPath = Join-Path $threatDshHome 'settings.yaml'
    $defaultsPath = Join-Path $projectRoot 'threat-dsh-workbench\profiles\threat-static\settings.defaults.yaml'
    if (-not (Test-Path -LiteralPath $defaultsPath)) {
        throw "Threat Workbench settings defaults missing: $defaultsPath"
    }
    if (Test-Path -LiteralPath $settingsPath) { return }
    Copy-Item -LiteralPath $defaultsPath -Destination $settingsPath -Force
    Write-Host "[Threat Workbench] Seeded isolated settings.yaml with DeepSeek-V41-Flash default." -ForegroundColor DarkCyan
}

function Test-ThreatWorkbenchRuntime {
    # A process can have the expected Node command line while still serving a
    # stale or plain DSH profile. Validate the bootstrap identity before reuse.
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$DshPort/" -TimeoutSec 3 -UseBasicParsing
        if ($response.StatusCode -ne 200) { return $false }
        $html = [string]$response.Content
        return $html -match '@threat-dsh/brand' -and
            $html -match '@threat-dsh/ui-overview' -and
            $html -match '@threat-dsh/ui-investigation' -and
            $html -match '@threat-dsh/ui-report' -and
            $html -notmatch 'DeepSeek Harness'
    } catch {
        return $false
    }
}

function Test-ThreatBackendRuntime {
    # A live workbench with a down API is not a successful BAT click. Probe the
    # bounded backend first so a healthy stack can skip Docker compose.
    try {
        $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/healthz' -TimeoutSec 3
        return $health.status -eq 'ok'
    } catch {
        return $false
    }
}

function Get-ThreatWorkbenchBuildId {
    # A PID/profile match alone can still point at an old product process after
    # a frontend edit. Hash the shipped profile and product plugin sources so
    # reuse is allowed only for the exact source tree being launched.
    $sourceRoot = Join-Path $projectRoot 'threat-dsh-workbench'
    $parts = @(
        Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -ErrorAction Stop |
            Where-Object { $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\.git\\' -and $_.Extension -in @('.js', '.ts', '.yml', '.yaml', '.json', '.css') } |
            Sort-Object FullName |
            ForEach-Object {
                $fileBytes = [System.IO.File]::ReadAllBytes($_.FullName)
                $fileDigest = [System.Security.Cryptography.SHA256]::Create().ComputeHash($fileBytes)
                $hash = ([System.BitConverter]::ToString($fileDigest) -replace '-', '')
                "$($_.FullName.ToLowerInvariant())=$hash"
            }
    )
    $payload = [System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n"))
    $digest = [System.Security.Cryptography.SHA256]::Create().ComputeHash($payload)
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function Test-ForeignDshSessionState {
    # A previous launcher could create sessions while its cwd pointed at the
    # upstream Harness checkout. Treat those sessions as foreign product state
    # so the current launcher never presents them as the active workbench.
    $sessionsRoot = Join-Path $threatDshHome 'sessions'
    if (-not (Test-Path -LiteralPath $sessionsRoot)) { return $false }
    return [bool](Get-ChildItem -LiteralPath $sessionsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'deepseek-harness' } |
        Select-Object -First 1)
}

function Quarantine-ForeignDshSessions {
    # Keep old Harness sessions recoverable, but outside the product's active
    # DSH home. The cache is updated so DSH cannot re-list orphaned sessions.
    $sessionsRoot = Join-Path $threatDshHome 'sessions'
    if (-not (Test-Path -LiteralPath $sessionsRoot)) { return }
    $foreignDirs = @(Get-ChildItem -LiteralPath $sessionsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'deepseek-harness' })
    if ($foreignDirs.Count -eq 0) { return }

    $quarantineRoot = Join-Path $projectRoot ('.scratch\dsh-quarantine\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Force -Path $quarantineRoot | Out-Null
    $foreignSessionIds = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($directory in $foreignDirs) {
        Get-ChildItem -LiteralPath $directory.FullName -Directory -Recurse -Filter 'session-*' -ErrorAction SilentlyContinue |
            ForEach-Object { [void]$foreignSessionIds.Add($_.Name) }
        Move-Item -LiteralPath $directory.FullName -Destination $quarantineRoot -Force
    }

    $cachePath = Join-Path $threatDshHome 'storages\session_projcache.json'
    if (Test-Path -LiteralPath $cachePath) {
        $cache = $null
        for ($attempt = 0; $attempt -lt 5 -and $null -eq $cache; $attempt++) {
            try {
                # DSH may flush its append-only cache just as the process exits;
                # retry a short-lived partial read instead of failing startup.
                $cache = Get-Content -Raw -LiteralPath $cachePath | ConvertFrom-Json
            } catch {
                if ($attempt -lt 4) { Start-Sleep -Milliseconds 250 }
            }
        }
        if ($null -ne $cache) {
            $sessions = $cache.tables.sessions
            foreach ($sessionId in $foreignSessionIds) {
                if ($sessions.PSObject.Properties[$sessionId]) {
                    $sessions.PSObject.Properties.Remove($sessionId)
                }
            }
            [System.IO.File]::WriteAllText(
                $cachePath,
                (($cache | ConvertTo-Json -Depth 100) + [Environment]::NewLine),
                [System.Text.UTF8Encoding]::new($false)
            )
        } else {
            Write-Warning "Unable to parse DSH session cache after quarantining foreign sessions; stale entries were left untouched: $cachePath"
        }
    }
    Write-Host "[Threat Workbench] Quarantined $($foreignDirs.Count) upstream session workspace(s) under $quarantineRoot." -ForegroundColor DarkCyan
}

function Stop-StaleThreatDsh {
    $listeners = Get-NetTCPConnection -LocalPort $DshPort -State Listen -ErrorAction SilentlyContinue
    $ownedPid = 0
    if (Test-Path -LiteralPath $pidFile) {
        [int]::TryParse((Get-Content -Raw -LiteralPath $pidFile), [ref]$ownedPid) | Out-Null
    }
    $runningBuildId = if (Test-Path -LiteralPath $buildFile) {
        (Get-Content -Raw -LiteralPath $buildFile -ErrorAction SilentlyContinue).Trim().ToLowerInvariant()
    } else { '' }
    $expectedDshBin = [System.IO.Path]::GetFullPath($dshBin).ToLowerInvariant()
    $foreignSessionState = Test-ForeignDshSessionState
    foreach ($listener in $listeners) {
        $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
        $commandLine = if ($existing) { [string]$existing.CommandLine } else { '' }
        $normalizedCommandLine = $commandLine.ToLowerInvariant().Replace('/', '\\')
        $isExpectedBinary = $normalizedCommandLine.Contains($expectedDshBin.Replace('/', '\\'))
        $isThreatDsh = $existing -and $existing.Name -eq 'node.exe' -and
            $isExpectedBinary -and $normalizedCommandLine -match '--profile\s+threat-static'
        if (-not $isThreatDsh) {
            throw "Port $DshPort is already in use by an unrelated process (pid=$($listener.OwningProcess)); refusing to open a different DSH instance."
        }
        if (-not $foreignSessionState -and $ownedPid -eq $existing.ProcessId -and $runningBuildId -eq $script:threatWorkbenchBuildId -and (Test-ThreatWorkbenchRuntime)) {
            # Reuse only the process recorded by this product's PID file. This
            # keeps a second checkout or stale profile from being presented as
            # the current workbench even when it uses the same DSH profile name.
            Write-Host "[Threat Workbench] Reusing running threat-static process owned by this Threat Workbench (pid=$($existing.ProcessId))." -ForegroundColor DarkCyan
            return $existing
        }
        # A matching executable/profile without valid ownership or product
        # bootstrap identity is stale. Replace it because it is bound to this
        # exact pinned DSH binary and fixed product port.
        Write-Host "[Threat Workbench] Replacing stale or non-product Threat Workbench process (pid=$($existing.ProcessId))." -ForegroundColor DarkCyan
        Stop-Process -Id $existing.ProcessId -Force -ErrorAction SilentlyContinue
    }
    return $null
}

function Ensure-IsolatedDshHome {
    # The DSH launcher resolves profiles and durable session storage below
    # DSH_HOME. Keep this home product-owned and never copy the user's old
    # sessions, credentials, or storage into it.
    $profilesRoot = Join-Path $threatDshHome 'profiles'
    $profileDir = Join-Path $profilesRoot 'threat-static'
    $profileAgentLink = Join-Path $profileDir 'agent'
    $presetDir = Join-Path $threatDshHome '.agent-presets\threat-static'
    New-Item -ItemType Directory -Force $profileDir | Out-Null
    New-Item -ItemType Directory -Force $profilesRoot | Out-Null

    $sourceProfile = Join-Path $projectRoot 'threat-dsh-workbench\profiles\threat-static'
    $sourceManifest = Join-Path $sourceProfile 'package.json'
    $sourcePatch = Join-Path $sourceProfile 'cordis.patch.yml'
    $sourcePreset = Join-Path $sourceProfile 'agent-presets\threat-static\agent.cordis.yml'
    if (-not (Test-Path -LiteralPath $sourceManifest) -or -not (Test-Path -LiteralPath $sourcePatch) -or -not (Test-Path -LiteralPath $sourcePreset)) {
        throw "Threat Workbench profile is incomplete: $sourceProfile"
    }

    # Use a home-local manifest so profile resolution works with the isolated
    # DSH_HOME. Its link:agent dependencies point back to this repository.
    $manifest = Get-Content -Raw -LiteralPath $sourceManifest | ConvertFrom-Json
    $manifest.name = 'dsh-profile-threat-static'
    $manifest.dependencies = [ordered]@{}
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'threat-dsh-workbench\packages') -Directory |
        ForEach-Object {
            $package = Get-Content -Raw -LiteralPath (Join-Path $_.FullName 'package.json') | ConvertFrom-Json
            if ($package.name -and $package.name.StartsWith('@threat-dsh/')) {
                $manifest.dependencies[$package.name] = "link:agent/threat-dsh-workbench/packages/$($_.Name)"
            }
        }
    $manifestJson = $manifest | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText(
        (Join-Path $profileDir 'package.json'),
        $manifestJson + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
    Copy-Item -LiteralPath $sourcePatch -Destination (Join-Path $profileDir 'cordis.patch.yml') -Force
    $workspaceConfig = @"
packages:
  - .

nodeLinker: hoisted
autoInstallPeers: false
"@
    [System.IO.File]::WriteAllText(
        (Join-Path $profileDir 'pnpm-workspace.yaml'),
        $workspaceConfig,
        [System.Text.UTF8Encoding]::new($false)
    )

    # DSH profile boot keeps its shipped preset root authoritative. Publishing
    # this product-owned preset in the isolated user root makes the configured
    # `threat-static` default discoverable while leaving the pinned DSH tree
    # untouched. Refresh it on every launch so edits to the repository profile
    # are reflected without copying sessions or credentials.
    New-Item -ItemType Directory -Force -Path $presetDir | Out-Null
    Copy-Item -LiteralPath $sourcePreset -Destination (Join-Path $presetDir 'agent.cordis.yml') -Force

    # Test-Path follows links and returns false for a broken junction. Read the
    # directory entry with -Force first so a stale link can be replaced rather
    # than causing New-Item to fail with an opaque "already exists" error.
    $link = Get-Item -LiteralPath $profileAgentLink -Force -ErrorAction SilentlyContinue
    if ($null -eq $link) {
        if (Test-DirectoryLinkEntry $profileAgentLink) {
            & cmd.exe /d /c rmdir /s /q "$profileAgentLink"
            if ($LASTEXITCODE -ne 0 -or (Test-DirectoryLinkEntry $profileAgentLink)) {
                throw "Unable to remove broken isolated profile agent link: $profileAgentLink"
            }
        }
        New-Item -ItemType Junction -Path $profileAgentLink -Target $projectRoot | Out-Null
    } else {
        if ($link.LinkType -eq 'Junction' -and (Normalize-PathForComparison $link.Target) -ne (Normalize-PathForComparison $projectRoot)) {
            # This path is inside the marker-protected, product-owned DSH home.
            # Remove only the stale junction itself; never touch its target.
            # PowerShell 7 can throw NullReferenceException when removing a
            # directory junction. `rmdir` removes only the link, never its
            # target, when given this explicit product-owned path.
            & cmd.exe /d /c rmdir /s /q "$profileAgentLink"
            if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $profileAgentLink)) {
                throw "Unable to replace stale isolated profile agent link: $profileAgentLink"
            }
            New-Item -ItemType Junction -Path $profileAgentLink -Target $projectRoot | Out-Null
        } elseif ($link.LinkType -ne 'Junction') {
            throw "Isolated profile agent link is not a Junction: $profileAgentLink"
        }
    }

    # Resolve out-of-tree Threat packages from the repository without running
    # pnpm or touching the old user's profile. The package directories already
    # contain their workspace dependency links.
    $threatModules = Join-Path $profilesRoot 'node_modules\@threat-dsh'
    New-Item -ItemType Directory -Force $threatModules | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'threat-dsh-workbench\packages') -Directory |
        ForEach-Object {
            $packageManifest = Join-Path $_.FullName 'package.json'
            if (-not (Test-Path -LiteralPath $packageManifest)) { return }
            $package = Get-Content -Raw -LiteralPath $packageManifest | ConvertFrom-Json
            if (-not $package.name -or -not $package.name.StartsWith('@threat-dsh/')) { return }
            $linkPath = Join-Path $threatModules ($package.name.Substring('@threat-dsh/'.Length))
            if (Test-Path -LiteralPath $linkPath) {
                $existing = Get-Item -LiteralPath $linkPath
                if ($existing.LinkType -eq 'Junction' -and (Normalize-PathForComparison $existing.Target) -ne (Normalize-PathForComparison $_.FullName)) {
                    # Module links live below the same marker-protected product
                    # home. Replace only a stale junction, never its target.
                    & cmd.exe /d /c rmdir /s /q "$linkPath"
                    if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $linkPath)) {
                        throw "Unable to replace stale isolated DSH module link: $linkPath"
                    }
                    New-Item -ItemType Junction -Path $linkPath -Target $_.FullName | Out-Null
                } elseif ($existing.LinkType -ne 'Junction') {
                    throw "Isolated DSH module link is not a Junction: $linkPath"
                }
            } else {
                New-Item -ItemType Junction -Path $linkPath -Target $_.FullName | Out-Null
            }
        }
}

function Ensure-ThreatDshPeerLinks {
    # Threat packages are linked into the isolated profile, but their runtime
    # imports also need the pinned DSH session package. Link only this exact
    # read-only peer from the configured Harness checkout; never run an
    # install against the user's global profile or copy its state.
    $target = Join-Path $dshRoot 'node_modules\.pnpm\node_modules\@deepseek-ai\dsh-session'
    if (-not (Test-Path -LiteralPath $target)) {
        throw "Pinned DSH session package is missing: $target"
    }
    $linkRoot = Join-Path $projectRoot 'node_modules\@deepseek-ai'
    $link = Join-Path $linkRoot 'dsh-session'
    New-Item -ItemType Directory -Force -Path $linkRoot | Out-Null
    if (Test-Path -LiteralPath $link) {
        $existing = Get-Item -LiteralPath $link
        if ($existing.LinkType -eq 'Junction' -and (Normalize-PathForComparison $existing.Target) -eq (Normalize-PathForComparison $target)) { return }
        if ($existing.LinkType -ne 'Junction') { throw "Threat DSH peer link is not a Junction: $link" }
        & cmd.exe /d /c rmdir /s /q "$link"
        if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $link)) { throw "Unable to replace stale Threat DSH peer link: $link" }
    }
    New-Item -ItemType Junction -Path $link -Target $target | Out-Null
}

if (-not (Test-Path -LiteralPath $tsx) -or -not (Test-Path -LiteralPath $tsxLoader) -or -not (Test-Path -LiteralPath $dshBin)) {
    throw "Pinned DeepSeek Harness checkout is missing: $dshRoot"
}

Initialize-ThreatOwnedState
Ensure-ThreatDefaultSettings
Ensure-IsolatedDshHome
Ensure-ThreatDshPeerLinks
Write-Host "[Threat Workbench] Using isolated DSH_HOME: $threatDshHome" -ForegroundColor DarkCyan

if ($PrepareOnly) {
    # Deterministic diagnostics/tests can validate profile ownership without
    # starting Docker, workers, or the DSH web process.
    Write-Host "[Threat Workbench] Profile preparation succeeded." -ForegroundColor Green
    exit 0
}

$existingDsh = $null
if (-not $BuildApi -and -not $BuildGhidra -and (Test-ThreatWorkbenchRuntime) -and (Test-ThreatBackendRuntime)) {
    Write-Host "[Threat Workbench] Stack looks healthy; skipping a full restart if backend workers are up..." -ForegroundColor DarkCyan
    $skipArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'start-threat-report-agent.ps1'), '-NoBrowser', '-SkipIfRunning')
    $skipArgs += @('-DockerTimeoutSeconds', "$DockerTimeoutSeconds")
    & powershell.exe @skipArgs
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[Threat Workbench] Stack already running; opening http://127.0.0.1:$DshPort/" -ForegroundColor Green
        Write-Host "[Threat Workbench] Backend API: $($env:THREAT_BACKEND_URL)" -ForegroundColor Green
        if (-not $NoBrowser) { Start-Process "http://127.0.0.1:$DshPort/" }
        exit 0
    }
    Write-Host "[Threat Workbench] Backend is not reusable; continuing with a full backend start." -ForegroundColor DarkCyan
}

$script:threatWorkbenchBuildId = Get-ThreatWorkbenchBuildId
Write-Host "[Threat Workbench] Product source build: $($script:threatWorkbenchBuildId.Substring(0, 12))" -ForegroundColor DarkCyan

if (-not $existingDsh) {
    $existingDsh = Stop-StaleThreatDsh
}
Quarantine-ForeignDshSessions
Write-Host "[Threat Workbench] Starting backend services..." -ForegroundColor Cyan
$backendArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'start-threat-report-agent.ps1'), '-NoBrowser')
if ($BuildApi) { $backendArgs += '-BuildApi' }
if ($BuildGhidra) { $backendArgs += '-BuildGhidra' }
$backendArgs += @('-DockerTimeoutSeconds', "$DockerTimeoutSeconds")
& powershell.exe @backendArgs
if ($LASTEXITCODE -ne 0) { throw "Threat backend failed to start" }

Write-Host "[Threat Workbench] Starting DSH threat-static on http://127.0.0.1:$DshPort ..." -ForegroundColor Cyan
$dshProcess = if ($existingDsh) {
    $existingDsh
} else {
    # ESM resolution of @deepseek-ai/cordis (FiberState) follows process cwd.
    # Product checkout node_modules do not export FiberState; the pinned Harness
    # tree does. Analyst workspace remains DSH_HOME plus the compose mount, not
    # this cwd.
    Start-Process -FilePath (Get-Command node.exe -ErrorAction Stop).Source `
        -ArgumentList @('--import', $tsxLoaderUrl, $dshBin, '--profile', 'threat-static', '--host', '127.0.0.1', '--port', "$DshPort") `
        -WorkingDirectory $dshRoot -RedirectStandardOutput $dshStdout -RedirectStandardError $dshStderr `
        -PassThru -WindowStyle Hidden
}
$dshProcessId = if ($existingDsh) {
    [int]$existingDsh.ProcessId
} else {
    [int]$dshProcess.Id
}
$pidFileDir = Split-Path -Parent $pidFile
New-Item -ItemType Directory -Force $pidFileDir | Out-Null
Set-Content -LiteralPath $pidFile -Value $dshProcessId -Encoding ascii

$deadline = (Get-Date).AddSeconds($DshTimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    if (Test-ThreatWorkbenchRuntime) { $ready = $true; break }
    $runningProcess = Get-Process -Id $dshProcessId -ErrorAction SilentlyContinue
    if (-not $runningProcess) {
        $stderrTail = if (Test-Path -LiteralPath $dshStderr) {
            (Get-Content -LiteralPath $dshStderr -Tail 40 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
        } else { "<no DSH stderr log>" }
        throw "DSH exited before becoming ready (pid=$dshProcessId). stderr: $stderrTail"
    }
    Start-Sleep -Seconds 1
}
if (-not $ready) { throw "Timed out waiting for the Threat Workbench product identity on port $DshPort; refusing to open an unverified page." }

Set-Content -LiteralPath $buildFile -Value $script:threatWorkbenchBuildId -Encoding ascii

Write-Host "[Threat Workbench] Ready: http://127.0.0.1:$DshPort/" -ForegroundColor Green
Write-Host "[Threat Workbench] Backend API: $($env:THREAT_BACKEND_URL)" -ForegroundColor Green
if (-not $NoBrowser) { Start-Process "http://127.0.0.1:$DshPort/" }
