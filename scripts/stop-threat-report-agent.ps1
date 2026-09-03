$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$pidFile = Join-Path $projectRoot '.scratch\dsh-threat-static.pid'
if (Test-Path -LiteralPath $pidFile) {
    $dshPid = 0
    [int]::TryParse((Get-Content -Raw -LiteralPath $pidFile), [ref]$dshPid) | Out-Null
    if ($dshPid -gt 0) {
        $process = Get-Process -Id $dshPid -ErrorAction SilentlyContinue
        if ($process) { Stop-Process -Id $dshPid -ErrorAction SilentlyContinue }
    }
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
}
# The DSH web host may have re-execed after the pid file was written. Stop
# only a process whose command line proves it is this product's threat-static
# profile; unrelated services on 3080 are never touched.
$listeners = Get-NetTCPConnection -LocalPort 3080 -State Listen -ErrorAction SilentlyContinue
foreach ($listener in $listeners) {
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
    $isThreatDsh = $existing -and $existing.Name -eq 'node.exe' -and
        $existing.CommandLine -match 'apps[\\/]cli[\\/]src[\\/]bin\.ts' -and
        $existing.CommandLine -match '--profile\s+threat-static'
    if ($isThreatDsh) {
        Stop-Process -Id $existing.ProcessId -Force -ErrorAction SilentlyContinue
    }
}
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    throw "docker.exe was not found."
}
& $docker.Source compose stop
if ($LASTEXITCODE -ne 0) {
    throw "docker compose stop exited with code $LASTEXITCODE"
}
Write-Host "Services stopped. Data volumes were not deleted." -ForegroundColor Green
