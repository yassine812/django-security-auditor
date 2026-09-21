@echo off
rem Starts the API + dashboard on http://127.0.0.1:8300
setlocal
cd /d %~dp0..
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
security-audit serve --host 127.0.0.1 --port 8300
pause
