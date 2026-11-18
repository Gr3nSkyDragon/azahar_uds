@echo off
rem Checks whether upstream Azahar and mGBA commits merge into uds-real / mgba-ldn without breaking them.
rem Options are passed through, e.g.:  merge-check.cmd -Target mgba -Quick
rem See merge-check.ps1 for all of them (Get-Help .\merge-check.ps1 -Full).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0merge-check.ps1" %*
set RC=%ERRORLEVEL%
if "%~1"=="" pause
exit /b %RC%
