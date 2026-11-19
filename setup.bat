@echo off
echo ============================================================
echo   InjeXion (v2.0.0) Windows Setup
echo ============================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

echo [*] Installing InjeXion dependencies...
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
