@echo off
REM =========================================================
REM  EvtxECmd - PsExec / Service-Based Forensics
REM =========================================================

SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUTDIR=output_psexec

IF NOT EXIST %OUTDIR% (
    mkdir %OUTDIR%
)

echo.
echo [*] Starting PsExec / Service-Based Analysis
echo.

REM ---------------------------------------------------------
REM 1. NETWORK LOGON (LATERAL MOVEMENT)
REM ---------------------------------------------------------
echo [+] Extracting Network Logon (4624,4648)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4624,4648 ^
 --csv %OUTDIR% --csvf Network_Logon.csv

REM ---------------------------------------------------------
REM 2. PROCESS CREATION (SERVICE CONTEXT)
REM ---------------------------------------------------------
echo [+] Extracting Process Creation (4688)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4688 ^
 --csv %OUTDIR% --csvf Process_Create.csv

REM ---------------------------------------------------------
REM 3. SERVICE INSTALLATION (SMOKING GUN)
REM ---------------------------------------------------------
echo [+] Extracting Service Installation (7045)
%EVTEXE% -f "%EVTXDIR%\System.evtx" ^
 --eid 7045 ^
 --csv %OUTDIR% --csvf Services_Installed.csv

REM ---------------------------------------------------------
REM 4. SERVICE STATE CHANGE
REM ---------------------------------------------------------
echo [+] Extracting Service State Changes (7036)
%EVTEXE% -f "%EVTXDIR%\System.evtx" ^
 --eid 7036 ^
 --csv %OUTDIR% --csvf Services_State.csv

REM ---------------------------------------------------------
REM 5. ADMIN PRIVILEGE
REM ---------------------------------------------------------
echo [+] Extracting Admin Privileges (4672)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4672 ^
 --csv %OUTDIR% --csvf Admin_Privileges.csv

echo.
echo [✓] PsExec Analysis Completed
echo [✓] Key Indicators:
echo     - Service created (7045)
echo     - Process parent = services.exe
echo     - Network logon (type 3)
echo.
pause
