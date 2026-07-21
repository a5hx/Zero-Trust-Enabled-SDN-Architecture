@echo off
REM Windows batch file to launch trust convergence demo in WSL
REM Usage: run_demo.bat

echo ========================================================================
echo          Trust Convergence Demo - Windows WSL Launcher
echo ========================================================================
echo.
echo This will launch the demonstration in WSL (Windows Subsystem for Linux)
echo.
echo Requirements:
echo   - WSL installed and configured
echo   - Python 3 installed in WSL
echo   - sudo privileges in WSL
echo.

REM Get the current directory in Windows format
set CURRENT_DIR=%CD%

REM Convert Windows path to WSL path
REM C:\Users\... becomes /mnt/c/Users/...
for /f "tokens=1,* delims=:" %%a in ("%CURRENT_DIR%") do (
    set DRIVE=%%a
    set REST=%%b
)

REM Convert to lowercase
for %%a in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    call set DRIVE=%%DRIVE:%%a=%%a%%
)

REM Replace backslashes with forward slashes
set REST=%REST:\=/%

set WSL_PATH=/mnt/%DRIVE%%REST%

echo WSL Path: %WSL_PATH%
echo.

echo Choose an option:
echo   1. Quick run (60s, default settings)
echo   2. Extended run (120s, more events)
echo   3. Verbose mode (see all events)
echo   4. Custom settings
echo.

set /p CHOICE="Enter choice (1-4): "

if "%CHOICE%"=="1" (
    echo Running quick demo...
    wsl -e bash -c "cd '%WSL_PATH%' && sudo bash run_demo.sh"
) else if "%CHOICE%"=="2" (
    echo Running extended demo...
    wsl -e bash -c "cd '%WSL_PATH%' && sudo bash run_demo.sh --duration 120 --event-rate 3.0"
) else if "%CHOICE%"=="3" (
    echo Running verbose demo...
    wsl -e bash -c "cd '%WSL_PATH%' && sudo bash run_demo.sh --verbose"
) else if "%CHOICE%"=="4" (
    set /p DURATION="Enter duration (seconds): "
    set /p RATE="Enter event rate (events/sec): "
    echo Running custom demo...
    wsl -e bash -c "cd '%WSL_PATH%' && sudo bash run_demo.sh --duration %DURATION% --event-rate %RATE%"
) else (
    echo Invalid choice. Defaulting to quick run...
    wsl -e bash -c "cd '%WSL_PATH%' && sudo bash run_demo.sh"
)

echo.
echo ========================================================================
echo                         Demo Complete
echo ========================================================================
echo.
echo Generated files:
echo   - trust_evolution.json     (Raw data)
echo   - convergence_report.txt   (Analysis)
echo   - *.png files              (Visualizations)
echo.
pause
