[CmdletBinding()]
param(
    [switch]$BuildApi,
    [switch]$BuildGhidra,
    [switch]$NoBrowser,
    [switch]$SkipIfRunning,
    [int]$DockerTimeoutSeconds = 180,
    [int]$ApiTimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

# Docker Desktop creates Windows AF_UNIX sockets under LOCALAPPDATA.  Keep
# that small runtime state on an ASCII path; the Docker WSL data disk remains
# at F:\DockerDesktop\wsl via CustomWslDistroDir.
$dockerRuntimeRoot = 'C:\DockerRuntime'
$dockerRuntimeLocal = Join-Path $dockerRuntimeRoot 'Local'
$dockerRuntimeRoaming = Join-Path $dockerRuntimeRoot 'Roaming'
if ((Test-Path -LiteralPath $dockerRuntimeLocal) -and (Test-Path -LiteralPath $dockerRuntimeRoaming)) {
    $env:LOCALAPPDATA = $dockerRuntimeLocal
    $env:APPDATA = $dockerRuntimeRoaming
}

$env:THREAT_DSH_PRESETS_ROOT = Join-Path $projectRoot 'threat-dsh-workbench\profiles\threat-static\agent-presets'

function Write-Step([string]$Message) {
    Write-Host "[Threat Report Agent] $Message" -ForegroundColor Cyan
}

function Fail([string]$Message) {
    Write-Host "[Threat Report Agent] Startup failed: $Message" -ForegroundColor Red
    Write-Host "Keep this window for diagnostics. Do not run docker compose down -v." -ForegroundColor Yellow
    exit 1
}

$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCommand) {
    $dockerPath = $dockerCommand.Source
} else {
    $dockerPath = Join-Path ${env:ProgramFiles} "Docker\Docker\resources\bin\docker.exe"
    if (-not (Test-Path -LiteralPath $dockerPath)) {
        Fail "docker.exe was not found. Install Docker Desktop and add its CLI to PATH."
    }
}

function Invoke-Docker([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments) {
    & $dockerPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') exited with code $LASTEXITCODE"
    }
}

function Test-DockerDaemon {
    try {
        # Native docker failures are terminating errors under the script's
        # strict error policy; convert them into the boolean probe result so
        # the caller can start Docker Desktop and retry.
        & $dockerPath info --format '{{json .ServerVersion}}' *> $null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Get-DockerDiagnostic {
    $context = (& $dockerPath context show 2>$null | Out-String).Trim()
    $info = (& $dockerPath info --format '{{json .ServerVersion}}' 2>&1 | Out-String).Trim()
    if (-not $context) { $context = "<unknown>" }
    if (-not $info) { $info = "<unavailable>" }
    return "context=$context; info=$info"
}

function Get-BackendSourceDigest {
    # Clicking the BAT must pick up Python/compose changes without requiring -BuildApi.
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $parts = New-Object System.Collections.Generic.List[string]
    $roots = @(
        (Join-Path $projectRoot "pyproject.toml"),
        (Join-Path $projectRoot "docker-compose.yml"),
        (Join-Path $projectRoot "Dockerfile"),
        (Join-Path $projectRoot "tool-worker\Dockerfile.emu")
    )
    $pythonRoot = Join-Path $projectRoot "src\threat_report_agent"
    $files = @(
        $roots |
            Where-Object { Test-Path -LiteralPath $_ }
        Get-ChildItem -LiteralPath $pythonRoot -Recurse -File -Filter *.py -ErrorAction Stop |
            Sort-Object FullName |
            ForEach-Object { $_.FullName }
    )
    foreach ($path in $files) {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $digest = $hasher.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($digest) -replace '-', '')
        [void]$parts.Add("$($path.ToLowerInvariant())=$hash")
    }
    $payload = [System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n"))
    $combined = $hasher.ComputeHash($payload)
    return ([System.BitConverter]::ToString($combined) -replace '-', '').ToLowerInvariant()
}

function Test-DockerDesktopProcess {
    return $null -ne (Get-Process "Docker Desktop" -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Test-ApiHealthy {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/healthz" -TimeoutSec 3
        return $health.status -eq "ok"
    } catch {
        return $false
    }
}

function Test-EmuWorkerRunning {
    try {
        $emuStatus = (& $dockerPath inspect threat-report-agent-emu-worker-1 --format "{{.State.Status}}" 2>$null | Out-String).Trim()
        if (-not $emuStatus) {
            $emuStatus = (& $dockerPath compose ps emu-worker --format "{{.State}}" 2>$null | Out-String).Trim()
        }
        return $emuStatus -match "running|Up"
    } catch {
        return $false
    }
}

# Why a per-queue check and not just "is the API up".
#
# The previous early exit tested the API and emu-worker only.  Measured on 2026-09-18:
# `threat-report-agent-control-worker-1` - the container that polls `static-control`, the queue the
# primary workflow STARTS on - was in Docker `Created` state, never started.  A BAT click reported
# "Backend already healthy; skipping Docker compose." and exited 0.  Every submission was then
# accepted (HTTP 202 in 0.1 s), parked on a queue with no consumer, and written off 105 s later as
# FAILED with `TEMPORAL_WORKFLOW_TIMEOUT` and ZERO evidence.  Six tasks were lost that way, three of
# them Resume runs that had already recovered 38,413 evidence rows, and from the task row alone the
# failure is indistinguishable from a real analysis failure.
#
# The queues below are the ones the pipeline calls; each must have a live poller on the worker side
# AND on the activity side, because the workflow itself is started on `static-control`.
$script:RequiredTaskQueues = @(
    "static-control",
    "static-intake",
    "static-parser",
    "static-script",
    "static-document",
    "static-ghidra",
    "static-emu"
)

function Get-WorkerContainerProblems {
    $problems = @()
    foreach ($service in @("control-worker", "intake-worker", "parser-worker", "script-worker", "document-worker", "ghidra-worker", "emu-worker")) {
        $container = "threat-report-agent-$service-1"
        $status = ""
        try {
            $status = (& $dockerPath inspect $container --format "{{.State.Status}}" 2>$null | Out-String).Trim()
        } catch {
            $status = ""
        }
        if (-not $status) {
            # Not created at all is a problem too: compose has never made this worker.
            $problems += "$service (missing)"
        } elseif ($status -notmatch "^(running|Up)") {
            $problems += "$service ($status)"
        }
    }
    return $problems
}

function Get-UnpolledTaskQueues {
    # Ask Temporal directly.  `temporal task-queue describe` prints a Pollers table; the workflow row
    # matters for static-control (the workflow is started there) and the activity row for every queue
    # that runs activities.  A queue with an empty table is a queue nothing consumes.
    $unpolled = @()
    foreach ($queue in $script:RequiredTaskQueues) {
        $raw = ""
        try {
            $raw = (& $dockerPath exec threat-report-agent-temporal-1 temporal task-queue describe `
                --task-queue $queue --namespace default --address temporal:7233 2>&1 | Out-String)
        } catch {
            $raw = ""
        }
        $sawPoller = $false
        $inPollers = $false
        foreach ($line in ($raw -split "`n")) {
            if ($line -match "^\s*Pollers:") { $inPollers = $true; continue }
            if ($inPollers -and $line -match "\b(workflow|activity)\b") { $sawPoller = $true }
        }
        if (-not $sawPoller) { $unpolled += $queue }
    }
    return $unpolled
}

function Test-PipelineConsumable {
    # A second click is a success only when the whole pipeline can consume work, not just the API.
    $problems = Get-WorkerContainerProblems
    if ($problems.Count -gt 0) {
        Write-Step ("Worker containers not running: " + ($problems -join ", "))
        return $false
    }
    $unpolled = Get-UnpolledTaskQueues
    if ($unpolled.Count -gt 0) {
        Write-Step ("Task queues with no live poller: " + ($unpolled -join ", "))
        return $false
    }
    return $true
}

try {
    if ($SkipIfRunning -and -not $BuildApi -and -not $BuildGhidra) {
        # A live pipeline is a successful second click. Do not hash the dirty
        # worktree or rebuild images just because another agent edited Python;
        # -BuildApi remains the explicit rebuild path.  "Live" means every worker
        # container is up AND every queue the pipeline calls has a live poller -
        # an API that answers /healthz while a worker sits in `Created` state
        # accepts submissions it can never run (see Test-PipelineConsumable).
        if ((Test-ApiHealthy) -and (Test-EmuWorkerRunning) -and (Test-PipelineConsumable)) {
            Write-Step "Backend already healthy and every task queue is polled; skipping Docker compose."
            exit 0
        }
    }

    if (-not (Test-DockerDaemon)) {
        $desktopCandidates = @(
            (Join-Path ${env:ProgramFiles} "Docker\Docker\Docker Desktop.exe"),
            (Join-Path ${env:LOCALAPPDATA} "Docker\Docker Desktop.exe")
        ) | Where-Object { Test-Path -LiteralPath $_ }
        if (-not $desktopCandidates) {
            Fail "Docker daemon is not running and Docker Desktop was not found."
        }
        $desktopPath = $desktopCandidates | Select-Object -First 1
        if (Test-DockerDesktopProcess) {
            Write-Step "Docker Desktop is running; waiting for the Linux engine..."
        } else {
            Write-Step "Starting Docker Desktop..."
            Start-Process -FilePath $desktopPath -WindowStyle Hidden | Out-Null
        }
    }

    $deadline = (Get-Date).AddSeconds($DockerTimeoutSeconds)
    while (-not (Test-DockerDaemon)) {
        if ((Get-Date) -gt $deadline) {
            Fail "Timed out waiting for the Docker Desktop Linux engine ($DockerTimeoutSeconds seconds). $(Get-DockerDiagnostic) Start Docker Desktop, wait until it reports Ready, then retry."
        }
        Start-Sleep -Seconds 2
    }
    Write-Step "Docker daemon is ready."

    try {
        $null = & $dockerPath image inspect threat-report-agent-ghidra-worker:latest *> $null
        $ghidraImageExists = $LASTEXITCODE -eq 0
    } catch {
        # A missing image is a probe result, not a reason to bypass BuildGhidra.
        $ghidraImageExists = $false
    }
    if ($BuildGhidra) {
        Write-Step "Rebuilding the Ghidra worker from the verified local archive..."
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build-ghidra-worker.ps1")
        if ($LASTEXITCODE -ne 0) {
            throw "verified Ghidra worker build exited with code $LASTEXITCODE"
        }
        $ghidraImageExists = $true
    }
    if (-not $ghidraImageExists) {
        $localArchive = Join-Path $projectRoot ".tools\ghidra_12.1.2_PUBLIC_20260605.zip"
        if (-not (Test-Path -LiteralPath $localArchive)) {
            Fail "Ghidra image and local archive are both missing: $localArchive"
        }
        Fail "Ghidra worker image is missing. Re-run this launcher with -BuildGhidra to build from the verified local archive."
    }

    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot ".env"))) {
        Write-Host "[Threat Report Agent] .env was not found; Compose development defaults will be used." -ForegroundColor Yellow
    }

    try {
        $null = & $dockerPath image inspect threat-report-agent-emu-worker:latest *> $null
        $emuImageExists = $LASTEXITCODE -eq 0
    } catch {
        $emuImageExists = $false
    }
    if (-not $emuImageExists) {
        Write-Step "Building the isolated emulator worker..."
        Invoke-Docker compose build emu-worker
        if ($LASTEXITCODE -ne 0) {
            throw "emulator worker build exited with code $LASTEXITCODE"
        }
    }

    $scratchDir = Join-Path $projectRoot ".scratch"
    New-Item -ItemType Directory -Force -Path $scratchDir | Out-Null
    $apiDigestFile = Join-Path $scratchDir "api-image-source.sha256"
    $backendDigest = Get-BackendSourceDigest
    $previousDigest = if (Test-Path -LiteralPath $apiDigestFile) {
        (Get-Content -Raw -LiteralPath $apiDigestFile).Trim()
    } else { "" }
    $needApiBuild = $BuildApi -or ($backendDigest -ne $previousDigest)
    if ($needApiBuild) {
        Write-Step "Building API and emu-worker so a BAT click runs the current analysis path..."
        $buildContext = (& $dockerPath context show | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $buildContext) { throw "Docker build context is unavailable." }
        Invoke-Docker --context $buildContext compose build --builder default api emu-worker
        Set-Content -LiteralPath $apiDigestFile -Value $backendDigest -Encoding ascii
    }

    Write-Step "Starting API, workers, PostgreSQL, MinIO, Temporal and emu-worker..."
    Invoke-Docker compose up --detach

    $healthDeadline = (Get-Date).AddSeconds($ApiTimeoutSeconds)
    $healthy = $false
    while (-not $healthy) {
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/healthz" -TimeoutSec 5
            $healthy = $health.status -eq "ok"
        } catch {
            $healthy = $false
        }
        if (-not $healthy) {
            if ((Get-Date) -gt $healthDeadline) {
                Write-Host "[Threat Report Agent] API health check failed. Current services:" -ForegroundColor Yellow
                & $dockerPath compose ps
                Fail "Timed out waiting for http://127.0.0.1:8000/healthz."
            }
            Start-Sleep -Seconds 2
        }
    }

    Write-Step "System is ready: http://127.0.0.1:8000/"
    Write-Step "API docs: http://127.0.0.1:8000/docs"
    $emuDeadline = (Get-Date).AddSeconds(60)
    $emuStatus = ""
    do {
        $emuStatus = (& $dockerPath inspect threat-report-agent-emu-worker-1 --format "{{.State.Status}}" 2>$null | Out-String).Trim()
        if (-not $emuStatus) {
            $emuStatus = (& $dockerPath compose ps emu-worker --format "{{.State}}" | Out-String).Trim()
        }
        if ($emuStatus -match "running|Up") { break }
        if ((Get-Date) -gt $emuDeadline) { break }
        Start-Sleep -Seconds 2
    } while ($true)
    if ($emuStatus -notmatch "running|Up") {
        Fail "Isolated emulator worker is not running (status='$emuStatus'). Compose must start emu-worker."
    }
    Write-Step "Isolated emulator worker is up ($emuStatus)."
    if (-not $NoBrowser) { Start-Process "http://127.0.0.1:8000/" }
} catch {
    Fail $_.Exception.Message
}
