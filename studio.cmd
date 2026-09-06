@echo off
setlocal
cd /d "%~dp0"

set "STUDIO_PY=.venv\Scripts\python.exe"
set "PYTHONPATH=%CD%\src;%PYTHONPATH%"

if not exist "%STUDIO_PY%" (
  echo [Secure Boot Studio] Ilk kullanim ortami hazirlaniyor...
  where py >nul 2>&1
  if errorlevel 1 (
    echo HATA: Python Launcher ^(py.exe^) bulunamadi. Python 3.10 veya uzerini kurun.
    pause
    exit /b 2
  )
  py -3 -m venv .venv
  if errorlevel 1 goto :failed
)

"%STUDIO_PY%" -c "import am64x_secure_toolkit, PySide6" >nul 2>&1
if errorlevel 1 (
  echo [Secure Boot Studio] Eksik paketler bir kez kuruluyor...
  "%STUDIO_PY%" -m pip install -e ".[dev,gui]"
  if errorlevel 1 goto :failed
)

"%STUDIO_PY%" -c "from am64x_secure_toolkit.gui import main; raise SystemExit(main())"
exit /b %errorlevel%

:failed
echo HATA: Secure Boot Studio ortami hazirlanamadi.
pause
exit /b 2
