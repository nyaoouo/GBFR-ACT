@echo off
setlocal enabledelayedexpansion
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% >nul 2>&1 || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~dp0"" && ""%~s0"" !params!", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )
set "try_download=1"

:find_python
for /f "delims=" %%i in ('where python') do (
    for /f "delims=" %%v in ('"%%i" -VV') do (
        set "output=%%v"
        !output!
        echo !output! | findstr /C:"3.11" >nul && echo !output! | findstr /C:"64 bit" >nul
        if !errorlevel! equ 0 (
            set "python=%%i"
            goto :start
        )
    )
)
if %try_download% equ 1 goto :download_python
echo Python 3.11 64-bit not found, please install it manually and add it to PATH.
goto :end

:download_python
echo Python 3.11 64-bit not found, try to download...
mkdir "temp"
cd "temp"
curl -L -o python-3.11.6-amd64.exe https://www.python.org/ftp/python/3.11.6/python-3.11.6-amd64.exe
if %errorlevel% neq 0 (
    echo Failed to download Python 3.11 64-bit, please install it manually and add it to PATH.
    goto :end
)
./python-3.11.6-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
if %errorlevel% neq 0 (
    echo Failed to install Python 3.11 64-bit, please install it manually and add it to PATH.
    goto :end
)
cd ..
rmdir /s /q "temp"
set "try_download=0"
goto :find_python

:start
echo Found Python 3.11 64-bit at %python%
"%python%" "act_ws.py"

:end
endlocal
pause
exit
