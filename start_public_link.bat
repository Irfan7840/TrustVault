@echo off
title TrustVault - Public HTTPS Link Launcher
cd /d "%~dp0"

echo ========================================================
echo        TRUSTVAULT - PUBLIC HTTPS LINK LAUNCHER
echo ========================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found in .venv!
    pause
    exit /b 1
)

echo [1/3] Ensuring database is up to date...
call .venv\Scripts\activate.bat
flask db upgrade

echo.
echo [2/3] Starting TrustVault application server on port 5000...
start "TrustVault App Server (Do Not Close)" cmd /k "call .venv\Scripts\activate.bat && python run.py"

echo.
echo [3/3] Creating Instant Public HTTPS Tunnel...
echo --------------------------------------------------------
echo An online HTTPS URL will appear below in a few seconds.
echo You can share this URL with anyone to access TrustVault!
echo --------------------------------------------------------
echo.

:: Use Pinggy SSH tunnel (requires no software installation, uses built-in Windows OpenSSH)
ssh -p 443 -o StrictHostKeyChecking=no -R0:localhost:5000 a.pinggy.io

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Pinggy tunnel exited. Trying fallback via localtunnel...
    npx --yes localtunnel --port 5000
)

pause
