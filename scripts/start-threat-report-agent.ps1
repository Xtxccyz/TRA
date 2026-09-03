[CmdletBinding()]
param(
    [switch]$BuildApi,
    [switch]$BuildGhidra,
    [switch]$NoBrowser,
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

function Test-DockerDesktopProcess {
    return $null -ne (Get-Process "Docker Desktop" -ErrorAction SilentlyContinue | Select-Object -First 1)
}

try {
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
            Start-Process -FilePath $desktopPath | Out-Null
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

    $null = & $dockerPath image inspect threat-report-agent-ghidra-worker *> $null
    $ghidraImageExists = $LASTEXITCODE -eq 0
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

    if ($BuildApi) {
        Write-Step "Building the API image..."
        Invoke-Docker compose build api
    }

    Write-Step "Starting API, workers, PostgreSQL, MinIO and Temporal..."
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
    if (-not $NoBrowser) { Start-Process "http://127.0.0.1:8000/" }
} catch {
    Fail $_.Exception.Message
}
