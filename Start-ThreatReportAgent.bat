@echo off
setlocal
title Threat Report Agent - Threat Workbench
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-dsh-threat-workbench.ps1" %*
if errorlevel 1 (
  echo.
  echo Threat Report Agent failed to start. Review the message above.
  pause
)
endlocal
