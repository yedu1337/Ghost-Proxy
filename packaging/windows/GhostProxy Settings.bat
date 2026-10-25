@echo off
cd /d "%~dp0"

if not exist GhostProxy.exe (
    echo GhostProxy.exe was not found in this folder.
    pause
    exit /b 1
)

echo Close the running Ghost Proxy window before changing these settings.
echo.
GhostProxy.exe --setup-only
pause
