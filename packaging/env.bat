@echo off
rem Put the Oboro toolchain first on PATH.
rem
rem   call <oboro>\env.bat
rem
rem Optional: set OBORO_NDK=C:\path\to\android-ndk before calling, so the CMake
rem toolchain file picks it up automatically.

set "OBORO_ROOT=%~dp0"
if "%OBORO_ROOT:~-1%"=="\" set "OBORO_ROOT=%OBORO_ROOT:~0,-1%"
set "PATH=%OBORO_ROOT%\bin;%PATH%"
echo Oboro %OBORO_ROOT%
