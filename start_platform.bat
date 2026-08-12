@echo off
setlocal
title Seniors Platform - Server + Public Link
cd /d "D:\thanaweya-platform (18)\thanaweya-platform"

echo.
echo ============================================
echo   Starting platform server + public link
echo ============================================
echo.

REM [1/2] Start Flask server in background (auto-restarts if it crashes)
start "" /min cmd /c "run_server.bat"
timeout /t 5 /nobreak >nul
echo [1/2] Server is running on port 5000.

REM [2/2] Start Cloudflare quick tunnel in background
if exist tunnel.log del tunnel.log
start "" /min cmd /c "cloudflared tunnel --no-autoupdate --url http://localhost:5000 >> tunnel.log 2>&1"
echo [2/2] Waiting for public URL...

set URL=
set tries=0
:wait
if exist tunnel.log (
    for /f "usebackq delims=" %%L in (`powershell -NoProfile -Command "Select-String -Path tunnel.log -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Last 1"`) do set URL=%%L
)
if not defined URL (
    set /a tries+=1
    if %tries% GEQ 40 goto fail
    timeout /t 2 /nobreak >nul
    goto wait
)

echo.
echo ======================================================================
echo   PUBLIC URL - open this from anywhere in the world:
echo   %URL%
echo ======================================================================
echo %URL% > public_url.txt
echo.
echo NOTE: The URL changes every time you run this script.
echo The server and tunnel keep running in the background. You can close
echo this window now.
echo.
pause
exit /b

:fail
echo Could not detect the URL. Open tunnel.log and look for the line
echo containing trycloudflare.com
pause
exit /b
