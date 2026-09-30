@echo off
REM KryxAI one-command launcher (Windows).
REM
REM Creates an isolated virtualenv, installs the engine with the extras the
REM demo actually needs, generates the synthetic corpus, and starts the API and
REM the dashboard. Safe to re-run; use --recreate to rebuild the venv.
REM
REM   run_kryxai.bat                start everything
REM   run_kryxai.bat --recreate     rebuild the virtualenv from scratch
REM   run_kryxai.bat --no-frontend  engine and API only (no Node required)
REM
REM The [all] extra is deliberate. Installing the base package alone gives a
REM working `kryxai` CLI but no uvicorn and no FastAPI, so the API silently
REM fails to start. That failure cost us a debugging session once already.

setlocal enabledelayedexpansion

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
pushd "%REPO_ROOT%" || exit /b 1

set "RECREATE=0"
set "WITH_FRONTEND=1"
set "API_PORT=8000"
set "WEB_PORT=5173"

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="--recreate"    set "RECREATE=1"     & shift & goto parse
if /i "%~1"=="--no-frontend" set "WITH_FRONTEND=0" & shift & goto parse
if /i "%~1%"~"--api-port=*"  set "API_PORT=%~1:~11%" & shift & goto parse
if /i "%~1%"~"--web-port=*"  set "WEB_PORT=%~1:~11%" & shift & goto parse
if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
echo unknown argument: %~1
popd & exit /b 2

:usage
echo KryxAI one-command launcher.
echo   run_kryxai.bat [--recreate] [--no-frontend] [--api-port=N] [--web-port=N]
exit /b 0

:parsed

set "VENV=%REPO_ROOT%\.venv"
set "PY=%VENV%\Scripts\python.exe"

echo.
echo [kryxai] locating a Python 3.11+ interpreter
set "NEEDVENV=0"
if exist "%PY%" (
    echo [kryxai] reusing existing venv at .venv
) else (
    set "NEEDVENV=1"
    set "BASE_PY="
    where py >nul 2>&1 && set "BASE_PY=py -3"
    if not defined BASE_PY where python >nul 2>&1 && set "BASE_PY=python"
    if not defined BASE_PY (
        echo [kryxai] no Python found on PATH. Install Python 3.11 or newer.
        popd & exit /b 1
    )
)

if "%RECREATE%"=="1" (
    echo [kryxai] removing existing venv
    if exist "%VENV%" rmdir /s /q "%VENV%"
    set "NEEDVENV=1"
)

if "%NEEDVENV%"=="1" (
    echo [kryxai] creating virtualenv
    %BASE_PY% -m venv "%VENV%"
    if errorlevel 1 ( echo [kryxai] venv creation failed & popd & exit /b 1 )
)

if not exist "%PY%" (
    echo [kryxai] %PY% is missing after venv creation
    popd & exit /b 1
)

echo [kryxai] installing kryxai[all] ^(the step that makes the API work^)
"%PY%" -m pip install --quiet --upgrade pip
REM Editable so a judge can read the source they are demoing.
"%PY%" -m pip install --quiet -e ".[all]"
if errorlevel 1 ( echo [kryxai] install failed & popd & exit /b 1 )

REM Verify rather than assume: this check is the one whose absence cost us an hour.
echo [kryxai] verifying the API extra is actually importable
"%PY%" -c "import fastapi, uvicorn" 2>nul
if errorlevel 1 (
    echo [kryxai] fastapi/uvicorn missing so the API cannot start.
    echo [kryxai] re-run with --recreate, or: pip install -e .[all]
    popd & exit /b 1
)

set "CORPUS_DIR=%REPO_ROOT%\demo_captures"
echo [kryxai] generating the synthetic demo corpus
"%VENV%\Scripts\kryxai.exe" corpus "%CORPUS_DIR%"
if errorlevel 1 ( echo [kryxai] corpus generation failed & popd & exit /b 1 )

echo [kryxai] starting API on 127.0.0.1:%API_PORT%
start "KryxAI API" cmd /k "cd /d ""%REPO_ROOT%"" && ""%PY%"" -m uvicorn kryxai.api:app --host 127.0.0.1 --port %API_PORT%"

REM Wait for readiness instead of sleeping a fixed amount, so the dashboard is
REM never pointed at an API that has not finished booting.
echo [kryxai] waiting for the API to become ready
set "READY=0"
for /l %%i in (1,1,60) do (
    if "!READY!"=="0" (
        "%PY%" -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%API_PORT%/health',timeout=1).status==200 else 1)" >nul 2>&1
        if !errorlevel! equ 0 set "READY=1"
        if "!READY!"=="0" timeout /t 1 /nobreak >nul
    )
)

if "!READY!"=="1" (
    echo [kryxai] API is ready
) else (
    echo [kryxai] API did not become ready on port %API_PORT%
    popd & exit /b 1
)

if "%WITH_FRONTEND%"=="1" (
    where npm >nul 2>&1
    if errorlevel 1 (
        echo [kryxai] npm not found. API is running; dashboard skipped.
        echo           API only: http://127.0.0.1:%API_PORT%/health
        popd & exit /b 0
    )
    if not exist "%REPO_ROOT%\frontend\node_modules" (
        echo [kryxai] installing dashboard dependencies
        pushd frontend
        call npm install --no-fund --no-audit
        popd
    )
    echo [kryxai] starting dashboard on 127.0.0.1:%WEB_PORT%
    set "VITE_API_TARGET=http://127.0.0.1:%API_PORT%"
    start "KryxAI Dashboard" cmd /k "cd /d ""%REPO_ROOT%\frontend"" && set VITE_API_TARGET=http://127.0.0.1:%API_PORT% && npm run dev -- --port %WEB_PORT% --host 127.0.0.1"
) else (
    set "VITE_API_TARGET=http://127.0.0.1:%API_PORT%"
)

echo.
echo   Dashboard : http://127.0.0.1:%WEB_PORT%
echo   API       : http://127.0.0.1:%API_PORT%/health
echo   Corpus    : %CORPUS_DIR%
echo.
echo   Pick a capture in demo_captures\ and scan it.
echo   01_healthy_smtp_tls12.pcap and 13_pop3_healthy.pcap are clean baselines;
echo   02_star_ttlssuppressed_vodafone_style.pcap shows a suppressed STARTTLS
echo   capability. Close the two windows to stop.
echo.
popd
exit /b 0
