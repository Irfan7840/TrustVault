# TrustVault - Public HTTPS Link Launcher (PowerShell)
Set-Location $PSScriptRoot

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       TRUSTVAULT - PUBLIC HTTPS LINK LAUNCHER          " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[ERROR] Virtual environment not found in .venv!" -ForegroundColor Red
    Pause
    exit 1
}

Write-Host "[1/3] Ensuring database migrations are up to date..." -ForegroundColor Yellow
& .\.venv\Scripts\flask.exe db upgrade

Write-Host ""
Write-Host "[2/3] Starting TrustVault application server on http://localhost:5000..." -ForegroundColor Yellow
Start-Process -FilePath "cmd.exe" -ArgumentList "/k call .venv\Scripts\activate.bat && python run.py"

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "[3/3] Establishing instant public HTTPS tunnel..." -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "Your live HTTPS link will appear below in 2-3 seconds." -ForegroundColor White
Write-Host "You can open this URL anywhere on mobile, desktop, or share with evaluators." -ForegroundColor White
Write-Host "--------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host ""

# Pinggy works with Windows native OpenSSH client on port 443 with zero install
& ssh.exe -p 443 -o StrictHostKeyChecking=no -R0:localhost:5000 a.pinggy.io
