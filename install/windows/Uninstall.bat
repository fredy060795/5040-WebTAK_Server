@echo off
rem Removes the WebTAK Server background service. Your data stays in C:\ProgramData\WebTAK Server.
cd /d "%~dp0"
if exist "%~dp0webtak-server.exe" goto haveexe
echo webtak-server.exe is not in this folder - run Uninstall.bat from the folder of the downloaded program.
pause
exit /b 1
:haveexe
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking for administrator rights ...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
"%~dp0webtak-server.exe" uninstall
echo.
pause
