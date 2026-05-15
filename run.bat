@echo off
chcp 65001 > nul
title SNI Scanner v2.0

REM Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+ and add it to PATH.
    pause
    exit /b 1
)

REM Check Python version
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [INFO] Python version: %PYVER%

REM Check / install requirements only when needed
if exist requirements.txt (
    python dependency_check.py
) else (
    echo [WARN] requirements.txt not found, skipping install.
)

REM Create required data directories
if not exist "data" mkdir "data"
if not exist "data\sni_lists" mkdir "data\sni_lists"
if not exist "data\results" mkdir "data\results"

REM Create default SNI list if missing
if not exist "data\sni_lists\default_sni.txt" (
    echo [INFO] Creating default SNI list...
    (
        echo # Default SNI list - add your domains below
        echo cloudflare.com
        echo cdn.cloudflare.com
        echo workers.dev
        echo pages.dev
        echo www.cloudflare.com
        echo dash.cloudflare.com
        echo react.dev
        echo nextjs.org
        echo vercel.com
        echo app.vercel.com
        echo github.com
        echo raw.githubusercontent.com
    ) > "data\sni_lists\default_sni.txt"
    echo [INFO] Default SNI list created at data\sni_lists\default_sni.txt
)

REM Launch app
echo.
echo [INFO] Starting SNI Scanner...
echo.
python main.py
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application exited with error code %errorlevel%.
)

echo.
pause
