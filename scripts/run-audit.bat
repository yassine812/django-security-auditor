@echo off
rem Usage:  scripts\run-audit.bat  C:\path\to\django-project
setlocal
cd /d %~dp0..
if "%~1"=="" (
  echo Usage: scripts\run-audit.bat PATH\TO\DJANGO\PROJECT
  pause
  exit /b 1
)
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
security-audit full "%~1" --yes
echo.
echo Reports are in workdir\audits\<audit-id>\reports\
pause
