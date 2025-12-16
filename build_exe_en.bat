@echo off
echo ================================
echo Building English Port Killer Tool...
echo ================================

:: Install dependencies
echo.
echo [1/3] Installing dependencies...
pip install -r requirements.txt

:: Package to exe
echo.
echo [2/3] Packaging to exe file...
pyinstaller --onefile --windowed --name="PortKiller_EN" port_killer_en.py

:: Check if successful
echo.
echo [3/3] Checking build result...
if exist "dist\PortKiller_EN.exe" (
    echo.
    echo ================================
    echo Build successful!
    echo File location: dist\PortKiller_EN.exe
    echo ================================
    echo.
    pause
    start "" "dist"
) else (
    echo.
    echo ================================
    echo Build failed! Please check error messages.
    echo ================================
    echo.
    pause
)