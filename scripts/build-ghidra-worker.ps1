[CmdletBinding()]
param(
    [int]$ArchiveServerTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

function Fail([string]$Message) {
    throw "Ghidra worker build failed: $Message"
}

function Get-DotEnvValue([string]$Name) {
    $environmentValue = [Environment]::GetEnvironmentVariable($Name, "Process")
    if (-not [string]::IsNullOrWhiteSpace($environmentValue)) {
        return $environmentValue.Trim()
    }

    $envFile = Join-Path $projectRoot ".env"
    if (-not (Test-Path -LiteralPath $envFile)) {
        return ""
    }
    foreach ($line in Get-Content -LiteralPath $envFile) {
        if ($line -match "^\s*$([regex]::Escape($Name))\s*=\s*(.*)\s*$") {
            $value = $Matches[1].Trim()
            if ($value.Length -ge 2 -and
                (($value.StartsWith('"') -and $value.EndsWith('"')) -or
                 ($value.StartsWith("'") -and $value.EndsWith("'")))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            return $value
        }
    }
    return ""
}

function Quote-ProcessArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-Docker([string[]]$Arguments) {
    & $script:dockerPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') exited with code $LASTEXITCODE"
    }
}

$dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
if (-not $dockerCommand) {
    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
}
if (-not $dockerCommand) {
    Fail "docker.exe was not found. Start Docker Desktop and retry."
}
$dockerPath = $dockerCommand.Source

& $dockerPath info --format '{{json .ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) {
    Fail "the Docker Desktop Linux engine is not ready"
}

$version = Get-DotEnvValue "GHIDRA_VERSION"
$expectedHash = (Get-DotEnvValue "GHIDRA_SHA256").ToUpperInvariant()
if ($version -notmatch '^[0-9][0-9A-Za-z._-]*$') {
    Fail "GHIDRA_VERSION must be set to a safe explicit version"
}
if ($expectedHash -notmatch '^[A-F0-9]{64}$') {
    Fail "GHIDRA_SHA256 must be a 64-character SHA-256 value"
}

$archive = Join-Path $projectRoot ".tools\ghidra_$($version)_PUBLIC_20260605.zip"
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    Fail "the trusted local archive is missing: $archive"
}
if (-not ([System.IO.Path]::GetFileName($archive).StartsWith("ghidra_$version`_", [System.StringComparison]::OrdinalIgnoreCase))) {
    Fail "the local archive name does not match GHIDRA_VERSION=$version"
}
$actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actualHash -ne $expectedHash) {
    Fail "the local archive SHA-256 does not match GHIDRA_SHA256"
}

$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $pythonCommand) {
    Fail "Python 3 is required to serve the verified local archive during this build"
}

$assetServer = Join-Path $PSScriptRoot "serve_build_asset.py"
if (-not (Test-Path -LiteralPath $assetServer)) {
    Fail "archive server helper is missing: $assetServer"
}

$scratch = Join-Path $projectRoot ".scratch"
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$buildToken = [Guid]::NewGuid().ToString("N")
$readyFile = Join-Path $scratch "ghidra-archive-$buildToken.port"
$stdoutFile = Join-Path $scratch "ghidra-archive-$buildToken.stdout.log"
$stderrFile = Join-Path $scratch "ghidra-archive-$buildToken.stderr.log"
$archiveServerProcess = $null
$priorValues = @{}
foreach ($name in @("GHIDRA_VERSION", "GHIDRA_ZIP_URL", "GHIDRA_SHA256")) {
    $priorValues[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    # Port 0 chooses an unused port atomically.  The helper reports that port
    # only after binding loopback, avoiding races and exposing no directory.
    $serverArguments = @(
        "-u", $assetServer, $archive, "--bind", "127.0.0.1", "--port", "0", "--ready-file", $readyFile
    ) | ForEach-Object { Quote-ProcessArgument $_ }
    $archiveServerProcess = Start-Process -FilePath $pythonCommand.Source `
        -ArgumentList ($serverArguments -join " ") `
        -WorkingDirectory $projectRoot `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile `
        -PassThru `
        -WindowStyle Hidden

    $deadline = (Get-Date).AddSeconds($ArchiveServerTimeoutSeconds)
    $port = 0
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $readyFile) {
            $rawPort = (Get-Content -Raw -LiteralPath $readyFile).Trim()
            if ([int]::TryParse($rawPort, [ref]$port) -and $port -gt 0 -and $port -le 65535) {
                break
            }
        }
        if ($archiveServerProcess.HasExited) {
            $stderr = if (Test-Path -LiteralPath $stderrFile) {
                (Get-Content -LiteralPath $stderrFile -Tail 40 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
            } else { "<no archive-server stderr>" }
            Fail "the loopback archive server exited before readiness. stderr: $stderr"
        }
        Start-Sleep -Milliseconds 200
    }
    if ($port -eq 0) {
        Fail "timed out waiting for the loopback archive server"
    }

    $localArchiveUri = "http://127.0.0.1:$port/$([System.IO.Path]::GetFileName($archive))"
    $head = Invoke-WebRequest -Uri $localArchiveUri -Method Head -UseBasicParsing -TimeoutSec 5
    if ($head.StatusCode -ne 200 -or [int64]$head.Headers["Content-Length"] -ne (Get-Item -LiteralPath $archive).Length) {
        Fail "the loopback archive server did not expose the expected verified asset"
    }

    [Environment]::SetEnvironmentVariable("GHIDRA_VERSION", $version, "Process")
    [Environment]::SetEnvironmentVariable("GHIDRA_SHA256", $expectedHash, "Process")
    [Environment]::SetEnvironmentVariable(
        "GHIDRA_ZIP_URL",
        "http://host.docker.internal:$port/$([System.IO.Path]::GetFileName($archive))",
        "Process"
    )
    Write-Host "[Threat Report Agent] Building Ghidra worker from the verified loopback archive..." -ForegroundColor Cyan
    Invoke-Docker @("compose", "-f", "docker-compose.yml", "-f", "docker-compose.ghidra-build.yml", "build", "ghidra-worker")
    Invoke-Docker @("image", "inspect", "threat-report-agent-ghidra-worker")
    Write-Host "[Threat Report Agent] Ghidra worker image is ready." -ForegroundColor Green
} finally {
    foreach ($name in $priorValues.Keys) {
        [Environment]::SetEnvironmentVariable($name, $priorValues[$name], "Process")
    }
    if ($archiveServerProcess -and -not $archiveServerProcess.HasExited) {
        Stop-Process -Id $archiveServerProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $readyFile -Force -ErrorAction SilentlyContinue
}
