@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stop-threat-report-agent.ps1"
if errorlevel 1 pause
endlocal
