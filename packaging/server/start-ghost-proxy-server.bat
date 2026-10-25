@echo off
cd /d "%~dp0"

if exist ghost.env (
    for /f "usebackq tokens=1,2 delims==" %%A in ("ghost.env") do set "%%A=%%B"
)

if not exist GhostProxy-Server.exe (
    echo GhostProxy-Server.exe was not found in this folder.
    pause
    exit /b 1
)

GhostProxy-Server.exe %*
pause
