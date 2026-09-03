[CmdletBinding()]
param(
    [switch]$BuildApi,
    [switch]$BuildGhidra,
    [int]$DshPort = 3080,
    [int]$DockerTimeoutSeconds = 180,
    [int]$DshTimeoutSeconds = 60,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$dshRoot = if ($env:DSH_HARNESS_ROOT) { $env:DSH_HARNESS_ROOT } else { Join-Path $env:USERPROFILE 'Desktop\deepseek-harness' }
$threatDshHome = if ($env:THREAT_DSH_HOME) { [System.IO.Path]::GetFullPath($env:THREAT_DSH_HOME) } else { Join-Path $projectRoot '.data\dsh-threat-static' }
$tsx = Join-Path $dshRoot 'node_modules\tsx\dist\cli.mjs'
$dshBin = Join-Path $dshRoot 'apps\cli\src\bin.ts'
$pidFile = Join-Path $projectRoot '.scratch\dsh-threat-static.pid'
$dshStdout = Join-Path $projectRoot '.scratch\dsh-threat-static-stdout.log'
$dshStderr = Join-Path $projectRoot '.scratch\dsh-threat-static-stderr.log'
$threatHomeMarker = Join-Path $threatDshHome '.threat-workbench-home-v1'
$env:THREAT_BACKEND_URL = if ($env:THREAT_BACKEND_URL) { $env:THREAT_BACKEND_URL } else { 'http://127.0.0.1:8000' }
$env:THREAT_DSH_PRESETS_ROOT = Join-Path $projectRoot 'threat-dsh-workbench\profiles\threat-static\agent-presets'
$env:DSH_HOME = $threatDshHome

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

function Stop-StaleThreatDsh {
    $listeners = Get-NetTCPConnection -LocalPort $DshPort -State Listen -ErrorAction SilentlyContinue
    foreach ($listener in $listeners) {
        $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
        $isThreatDsh = $existing -and $existing.Name -eq 'node.exe' -and
            $existing.CommandLine -match 'apps[\\/]cli[\\/]src[\\/]bin\.ts' -and
            $existing.CommandLine -match '--profile\s+threat-static'
        if (-not $isThreatDsh) {
            throw "Port $DshPort is already in use by an unrelated process (pid=$($listener.OwningProcess))."
        }
        # Reuse a healthy product instance. Killing it here can interrupt an
        # active analysis and discard the browser's live event connection.
        Write-Host "[Threat Workbench] Reusing running threat-static process (pid=$($existing.ProcessId))." -ForegroundColor DarkCyan
        return $existing
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

    if (-not (Test-Path -LiteralPath $profileAgentLink)) {
        New-Item -ItemType Junction -Path $profileAgentLink -Target $projectRoot | Out-Null
    } else {
        $link = Get-Item -LiteralPath $profileAgentLink
        if ($link.LinkType -eq 'Junction' -and [System.IO.Path]::GetFullPath($link.Target) -ne $projectRoot) {
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
                if ($existing.LinkType -eq 'Junction' -and [System.IO.Path]::GetFullPath($existing.Target) -ne $_.FullName) {
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
        if ($existing.LinkType -eq 'Junction' -and [System.IO.Path]::GetFullPath($existing.Target) -eq [System.IO.Path]::GetFullPath($target)) { return }
        if ($existing.LinkType -ne 'Junction') { throw "Threat DSH peer link is not a Junction: $link" }
        & cmd.exe /d /c rmdir /s /q "$link"
        if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $link)) { throw "Unable to replace stale Threat DSH peer link: $link" }
    }
    New-Item -ItemType Junction -Path $link -Target $target | Out-Null
}

if (-not (Test-Path -LiteralPath $tsx) -or -not (Test-Path -LiteralPath $dshBin)) {
    throw "Pinned DeepSeek Harness checkout is missing: $dshRoot"
}

Initialize-ThreatOwnedState
Ensure-IsolatedDshHome
Ensure-ThreatDshPeerLinks
Write-Host "[Threat Workbench] Using isolated DSH_HOME: $threatDshHome" -ForegroundColor DarkCyan

 $existingDsh = Stop-StaleThreatDsh
Write-Host "[Threat Workbench] Starting backend services..." -ForegroundColor Cyan
$backendArgs = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'start-threat-report-agent.ps1'), '-NoBrowser')
if ($BuildApi) { $backendArgs += '-BuildApi' }
if ($BuildGhidra) { $backendArgs += '-BuildGhidra' }
& powershell.exe @backendArgs
if ($LASTEXITCODE -ne 0) { throw "Threat backend failed to start" }

Write-Host "[Threat Workbench] Starting DSH threat-static on http://127.0.0.1:$DshPort ..." -ForegroundColor Cyan
$dshProcess = if ($existingDsh) {
    $existingDsh
} else {
    Start-Process -FilePath (Get-Command node.exe -ErrorAction Stop).Source `
        -ArgumentList @('--import', 'tsx/esm', $dshBin, '--profile', 'threat-static', '--host', '127.0.0.1', '--port', "$DshPort") `
        -WorkingDirectory $dshRoot -RedirectStandardOutput $dshStdout -RedirectStandardError $dshStderr `
        -PassThru -WindowStyle Hidden
}
$pidFileDir = Split-Path -Parent $pidFile
New-Item -ItemType Directory -Force $pidFileDir | Out-Null
Set-Content -LiteralPath $pidFile -Value $dshProcess.Id -Encoding ascii

$deadline = (Get-Date).AddSeconds($DshTimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$DshPort/" -TimeoutSec 3 -UseBasicParsing
        if ($response.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    if ($dshProcess.HasExited) {
        $stderrTail = if (Test-Path -LiteralPath $dshStderr) {
            (Get-Content -LiteralPath $dshStderr -Tail 40 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
        } else { "<no DSH stderr log>" }
        throw "DSH exited before becoming ready (pid=$($dshProcess.Id)). stderr: $stderrTail"
    }
    Start-Sleep -Seconds 1
}
if (-not $ready) { throw "Timed out waiting for DSH Web on port $DshPort" }

Write-Host "[Threat Workbench] Ready: http://127.0.0.1:$DshPort/" -ForegroundColor Green
Write-Host "[Threat Workbench] Backend API: $($env:THREAT_BACKEND_URL)" -ForegroundColor Green
if (-not $NoBrowser) { Start-Process "http://127.0.0.1:$DshPort/" }
