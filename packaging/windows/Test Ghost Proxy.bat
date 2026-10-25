@echo off
cd /d "%~dp0"

if not exist GhostProxy.exe (
    echo GhostProxy.exe was not found in this folder.
    pause
    exit /b 1
)

echo Testing the connection through Ghost Proxy...
echo.
GhostProxy.exe --check %*
set "STATUS=%ERRORLEVEL%"
echo.
if "%STATUS%"=="0" (
    echo Ghost Proxy is working.
) else (
    echo The connection test failed. Read the message above, then try again.
)
pause
exit /b %STATUS%
