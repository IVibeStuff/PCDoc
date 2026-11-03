@echo off
:: PCDoc launcher - asks for administrator rights, then runs the read-only scan
:: including a Windows Update check. Nothing is installed or changed.
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-PCDoc.ps1" -CheckWindowsUpdate
echo.
pause
