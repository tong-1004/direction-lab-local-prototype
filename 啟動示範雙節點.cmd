@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" run_local_pair.py %*
) else (
  python run_local_pair.py %*
)
if errorlevel 1 pause
