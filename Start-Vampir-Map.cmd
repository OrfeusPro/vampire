@echo off
powershell.exe -NoProfile -File "%~dp0phone-exit\bots\vampir\start-map-server.ps1"
if errorlevel 1 pause
