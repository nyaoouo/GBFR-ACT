@REM only intended to be used via steam launch options
@echo off
setlocal enabledelayedexpansion
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "%~s0", %params%, "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )
for /f "delims=" %%i in ('where python') do (
    for /f "delims=" %%v in ('"%%i" -VV') do (
        set "output=%%v"
        !output!
        echo !output! | findstr /C:"3.11" >nul && echo !output! | findstr /C:"64 bit" >nul
        if !errorlevel! equ 0 (
            echo Found Python 3.11 64-bit at %%i
            start "" "act_ws.html"
            start "act_ws.py" %%i "act_ws.py"
            echo script ended with exit code !errorlevel!
            goto :end
        )
    )
)
echo Python 3.11 64-bit not found, please install it or add it to your PATH.
:end
for /F "delims=" %%i in ("%params%") do (
    cd /d "%%~di%%~pi" && powershell -noprofile -Command "Start-Process -FilePath ""%params%"""
)
endlocal
exit
