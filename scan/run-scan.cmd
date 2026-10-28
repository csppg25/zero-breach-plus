@echo off
setlocal enabledelayedexpansion

rem Launcher behind the desktop shortcut. Runs the default read-only scan only:
rem no --arm, no --deep, nothing that writes to the system. The window is kept
rem open at the end, because a report that flashes past and closes is no report.

title adint-scan - spyware indicator check

rem Run from this script's own folder, so the default IOC path resolves.
cd /d "%~dp0"

rem Find Python: the PATH first, then the py launcher.
set "PY="
where python >nul 2>&1
if %errorlevel%==0 set "PY=python"
if not defined PY (
  where py >nul 2>&1
  if !errorlevel!==0 set "PY=py"
)
if not defined PY (
  echo.
  echo  Python was not found on this PC.
  echo.
  echo  Install Python from https://www.python.org/downloads/ and tick
  echo  "Add python.exe to PATH" in the installer, then run this again.
  echo.
  pause
  exit /b 1
)

rem Timestamp for the saved report, via Python so the format is not locale-dependent.
set "STAMP="
for /f "delims=" %%T in ('%PY% -c "import datetime;print(datetime.datetime.now().strftime('%%Y%%m%%d-%%H%%M%%S'))"') do set "STAMP=%%T"
if not defined STAMP set "STAMP=latest"

rem Resolve ..\findings to a real absolute path, so the "Saved:" lines printed at
rem the end read as a path someone can actually copy, not one containing "..".
for %%I in ("%~dp0..\findings") do set "OUTDIR=%%~fI"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
set "TXT=%OUTDIR%\scan-%STAMP%.txt"
set "JSON=%OUTDIR%\scan-%STAMP%.json"

cls
echo ========================================================================
echo   adint-scan - checking this PC for published spyware indicators
echo ========================================================================
echo.
echo  This only READS your files. It changes nothing, needs no administrator,
echo  and never contacts anything over the internet.
echo.
echo  It takes a while - it fingerprints tens of thousands of files. Progress
echo  appears below as it goes. You can close this window at any time without
echo  any harm, since nothing is being modified.
echo.
echo ========================================================================
echo.

rem Human report to a file (shown below when done); progress streams to screen.
%PY% -X utf8 adint-scan.py --json "%JSON%" > "%TXT%"
set "RC=%errorlevel%"

echo.
type "%TXT%"
echo.
echo ========================================================================
if "%RC%"=="2" (
  echo   RESULT: something matched. Read the report above - a match means
  echo   INVESTIGATE, not "you are infected". The referral links above are
  echo   the right next step.
) else if "%RC%"=="0" (
  echo   RESULT: no known indicators found. Read the closing line above -
  echo   it is not a clean bill of health.
) else (
  echo   The scan could not run properly. The report above says why.
)
echo.
echo   Saved:  %TXT%
echo           %JSON%
echo ========================================================================
echo.
pause
endlocal
