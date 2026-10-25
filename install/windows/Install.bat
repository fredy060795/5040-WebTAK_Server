@echo off
rem Installs WebTAK Server as a background service that starts with Windows.
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking for administrator rights ...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
"%~dp0webtak-server.exe" install
echo.
pause
