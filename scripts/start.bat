@echo off
REM Start the WITNESS backend from cmd.exe, then print how to start the console.
REM   scripts\start.bat            (http://127.0.0.1:8000; set WITNESS_PORT to change)

setlocal enabledelayedexpansion

for %%i in ("%~dp0..") do set "PROJ_ROOT=%%~fi"
set "BACKEND=%PROJ_ROOT%\backend"
if "%WITNESS_PORT%"=="" (set "PORT=8000") else (set "PORT=%WITNESS_PORT%")
set "LOG=%TEMP%\witness-backend.log"

where python >nul 2>&1
if errorlevel 1 (
    where python3 >nul 2>&1
    if errorlevel 1 (
        echo Error: python not found in PATH. Install Python 3.11+ from https://python.org
        exit /b 1
    )
    set "PYTHON=python3"
) else (
    set "PYTHON=python"
)
for /f "delims=" %%v in ('!PYTHON! --version 2^>^&1') do echo Using %%v

REM Install from requirements.txt (the single source of truth) if anything is missing.
!PYTHON! -c "import fastapi, sqlalchemy, greenlet, aiosqlite, pydantic_settings" >nul 2>&1
if errorlevel 1 (
    echo Installing Python dependencies from backend\requirements.txt ...
    !PYTHON! -m pip install --quiet -r "%BACKEND%\requirements.txt"
    if errorlevel 1 (
        echo pip install failed
        exit /b 1
    )
)

if not exist "%PROJ_ROOT%\data" mkdir "%PROJ_ROOT%\data"

REM Stop a previous backend listening on the port (best-effort).
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
    echo Stopping existing process on port %PORT% ^(PID %%a^)
    taskkill /F /PID %%a >nul 2>&1
)

curl -s -o nul --max-time 2 http://127.0.0.1:%PORT%/ >nul 2>&1
if not errorlevel 1 (
    echo Error: port %PORT% is already in use by another program. Set WITNESS_PORT to a free port.
    exit /b 1
)

echo Starting WITNESS backend on http://127.0.0.1:%PORT% ...
pushd "%BACKEND%"
start "WITNESS backend" /B cmd /c "!PYTHON! -m uvicorn witness.api.app:app --host 0.0.0.0 --port %PORT% --log-level warning > "%LOG%" 2>&1"
popd

set I=0
:wait_loop
REM ping instead of timeout: timeout fails when stdin is redirected (CI, IDE terminals).
ping -n 2 127.0.0.1 >nul
curl -fsS http://127.0.0.1:%PORT%/health >nul 2>&1
if errorlevel 1 (
    set /a I+=1
    if !I! lss 30 goto wait_loop
    echo Backend did not come up in time. Log: %LOG%
    type "%LOG%"
    exit /b 1
)
echo Backend is up.
curl -fsS http://127.0.0.1:%PORT%/health
echo.
echo.
echo Console (separate terminal):  cd "%PROJ_ROOT%" ^&^& bun install ^&^& bun run dev   (or npm)
echo API docs:                     http://127.0.0.1:%PORT%/docs
echo Flagship demo:                curl -X POST http://127.0.0.1:%PORT%/demo/flagship -H "Content-Type: application/json" -d "{\"max_iterations\": 5}"
echo Benchmark (CLI):              cd "%BACKEND%" ^&^& python -m witness.benchmark
echo Log:                          %LOG%
endlocal
