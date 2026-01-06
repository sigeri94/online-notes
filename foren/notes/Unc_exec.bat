@echo off
REM =========================================================
REM  Generic UNC Execution / Installation Detection
REM  No hardcoded hostname
REM =========================================================

SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUTDIR=output_unc_generic

mkdir %OUTDIR% 2>nul

echo.
echo [*] Detecting GENERIC execution from UNC paths
echo [*] Pattern : \\server\share\file
echo.

REM ---------------------------------------------------------
REM 1. PROCESS CREATION FROM UNC PATH (KEY EVIDENCE)
REM ---------------------------------------------------------
echo [+] Checking process execution from UNC paths
%EVTEXE% -d %EVTXDIR% ^
 --eid 4688 ^
 --inc "\\\\" ^
 --csv %OUTDIR% --csvf UNC_Process_Execution.csv

REM ---------------------------------------------------------
REM 2. SMB FILE ACCESS (ANY SHARE)
REM ---------------------------------------------------------
echo [+] Checking SMB file access (any share)
%EVTEXE% -d %EVTXDIR% ^
 --eid 5140,5145 ^
 --csv %OUTDIR% --csvf UNC_SMB_Access.csv

REM ---------------------------------------------------------
REM 3. NETWORK LOGON RELATED TO UNC ACTIVITY
REM ---------------------------------------------------------
echo [+] Checking network logons
%EVTEXE% -d %EVTXDIR% ^
 --eid 4624 ^
 --inc "Logon Type: 3" ^
 --csv %OUTDIR% --csvf UNC_Network_Logon.csv

REM ---------------------------------------------------------
REM 4. SERVICE INSTALLATION (INSTALLER FROM NETWORK)
REM ---------------------------------------------------------
echo [+] Checking service installation
%EVTEXE% -d %EVTXDIR% ^
 --eid 7045 ^
 --csv %OUTDIR% --csvf Service_Installation.csv

echo.
echo [✓] Generic UNC execution detection completed
echo.
echo [Correlation Guide]
echo  - 5145 (read *.exe/*.msi) -> 4688 (UNC path) = EXECUTION
echo  - 4688 (UNC) -> 7045 = INSTALLER / PERSISTENCE
echo.
pause
