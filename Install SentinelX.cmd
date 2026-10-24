@echo off
setlocal
cd /d "%~dp0"
where py.exe >nul 2>nul
if errorlevel 1 (
  echo Install Python 3.12 with the Windows Python launcher, then retry.
  pause
  exit /b 1
)
py -3.12 -c "import sys; sys.exit(0 if sys.version_info[:2] == (3,12) else 1)" >nul 2>nul
if errorlevel 1 (
  echo Python 3.12 is required. Install it and reopen this installer.
  pause
  exit /b 1
)
py -3.12 scripts\setup_windows.py --start
set "setupResult=%errorlevel%"
if not "%setupResult%"=="0" echo Setup stopped. Read the error above; existing private settings were preserved.
pause
exit /b %setupResult%
