@echo off
echo ============================================================
echo   InjeXion (v2.0.0) Windows Setup
echo ============================================================
echo.

uv --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Detected uv package manager!
    echo [*] Running fast environment sync with uv...
    uv sync
    if %errorlevel% neq 0 (
        echo [ERROR] uv sync failed.
        pause
        exit /b 1
    )
    echo.
    echo [*] Running diagnostic check...
    uv run python -m injexion doctor
    echo.
    echo ============================================================
    echo   Installation complete!
    echo   Run InjeXion using: uv run injx scan "http://target-url"
    echo   Or interactive mode: uv run python launcher_windows.py
    echo ============================================================
    pause
    exit /b 0
)

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Neither uv nor Python was found in PATH.
    echo Please install Python 3.9+ from https://python.org or uv from https://docs.astral.sh/uv/
    pause
    exit /b 1
)

echo [*] Installing InjeXion dependencies via pip...
pip install -e .

if %errorlevel% neq 0 (
    echo [ERROR] Installation failed.
    pause
    exit /b 1
)

echo.
echo [*] Running diagnostic check...
python -m injexion doctor

echo.
echo ============================================================
echo   Installation complete!
echo   Run InjeXion using: injx scan "http://target-url"
echo   Or interactive mode: python launcher_windows.py
echo ============================================================
pause
