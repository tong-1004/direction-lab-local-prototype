@echo off
cd /d "%~dp0"
if not exist "data\peers\direction-lab-genesis.json" (
  echo Missing data\peers\direction-lab-genesis.json
  echo Create and download a public-key test genesis from the local node page first.
  pause
  exit /b 1
)
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" run_local_pair.py --public-genesis "data\peers\direction-lab-genesis.json"
) else (
  python run_local_pair.py --public-genesis "data\peers\direction-lab-genesis.json"
)
if errorlevel 1 pause
