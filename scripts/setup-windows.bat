@echo off
rem ============================================================
rem  Django Security Auditor - Windows setup (one-click)
rem  Creates a virtual environment, installs everything and
rem  runs the test suite. Requires Python 3.10+ on PATH.
rem ============================================================
setlocal
cd /d %~dp0..

where py >nul 2>nul
if %errorlevel%==0 (
  set "PYCMD=py -3"
) else (
  where python >nul 2>nul
  if %errorlevel%==0 (set "PYCMD=python") else (
    echo [ERROR] Python was not found on PATH.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during installation.
    pause
    exit /b 1
  )
)

echo === Python ===
%PYCMD% --version

if not exist .venv (
  echo === Creating virtual environment ===
  %PYCMD% -m venv .venv || (echo [ERROR] could not create .venv & pause & exit /b 1)
)

echo === Installing dependencies ===
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul
pip install -e ".[api,dev]" || (echo [ERROR] dependency install failed & pause & exit /b 1)

echo === Running test suite ===
python -m pytest tests/ -q

echo.
echo ============================================================
echo  Setup complete.
echo.
echo  Start the dashboard:   scripts\run-dashboard.bat
echo  Run an audit:          .venv\Scripts\security-audit full PATH\TO\PROJECT --yes
echo  Default login:         admin / admin-audit-2026  (change it!)
echo ============================================================
pause
