@echo off
cd /d "%~dp0"

if not exist GhostProxy-Server.exe (
    echo GhostProxy-Server.exe was not found in this folder.
    pause
    exit /b 1
)

echo Close the running gateway window before changing these settings.
echo.
GhostProxy-Server.exe --setup-only
pause
