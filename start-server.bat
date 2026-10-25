@echo off
REM Ghost Proxy server launcher for Windows
REM Put this file in the same folder as ghost-server.exe
REM Put a file named ghost.env in the same folder with one line:
REM   GHOST_PSK=your64characterhexkey

cd /d "%~dp0"

if exist ghost.env (
    for /f "usebackq tokens=1,2 delims==" %%A in ("ghost.env") do set %%A=%%B
)

if "%GHOST_PSK%"=="" (
    echo GHOST_PSK is not set.
    echo Create a file named ghost.env next to this script containing:
    echo   GHOST_PSK=your64characterhexkey
    pause
    exit /b 1
)

if not exist ghost-server.exe (
    echo ghost-server.exe not found in this folder.
    pause
    exit /b 1
)

echo Starting ghost-server on 127.0.0.1:8443...
ghost-server.exe -listen 127.0.0.1:8443
pause
