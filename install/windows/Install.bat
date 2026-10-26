@echo off
rem Installs WebTAK Server as a background service that starts with Windows.
cd /d "%~dp0"
if exist "%~dp0webtak-server.exe" goto haveexe
echo.
echo webtak-server.exe is not in this folder.
echo This happens with GitHub "Code - Download ZIP": that zip only contains the source code.
echo Downloading the ready-made program from the GitHub releases ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol='Tls12'; $z=Join-Path $env:TEMP 'webtak-server.zip'; $d=Join-Path $env:TEMP 'webtak-server-dl'; Invoke-WebRequest -UseBasicParsing 'https://github.com/fredy060795/5040-WebTAK_Server/releases/latest/download/WebTAK-Server-Windows-amd64.zip' -OutFile $z; if (Test-Path $d) { Remove-Item -Recurse -Force $d }; Expand-Archive $z $d; Get-ChildItem $d -Recurse -Include *.exe,*.txt | Copy-Item -Destination '%~dp0' -Force"
if exist "%~dp0webtak-server.exe" goto haveexe
echo.
echo The download did not work. Please download WebTAK-Server-Windows-amd64.zip from
echo   https://github.com/fredy060795/5040-WebTAK_Server/releases
echo unzip it and run Install.bat from that folder.
pause
exit /b 1
:haveexe
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking for administrator rights ...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
"%~dp0webtak-server.exe" install
echo.
pause
