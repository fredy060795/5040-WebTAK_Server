@echo off
rem Removes the WebTAK Server background service. Your data stays in C:\ProgramData\WebTAK Server.
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking for administrator rights ...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
"%~dp0webtak-server.exe" uninstall
echo.
pause
