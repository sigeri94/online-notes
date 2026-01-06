@echo off
REM =========================================================
REM  EvtxECmd - WMI Forensic Analysis
REM  Purpose : Detect WMI execution & persistence
REM =========================================================

SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUTDIR=output_wmi

IF NOT EXIST %OUTDIR% (
    mkdir %OUTDIR%
)

echo.
echo [*] Starting WMI Forensic Analysis
echo [*] EVTX Source : %EVTXDIR%
echo [*] Output Dir  : %OUTDIR%
echo.

REM ---------------------------------------------------------
REM 1. WMI OPERATION LOG (SMOKING GUN)
REM ---------------------------------------------------------
echo [+] Extracting WMI Activity (5857-5861)
%EVTEXE% -f "%EVTXDIR%\Microsoft-Windows-WMI-Activity%%4Operational.evtx" ^
 --eid 5857,5858,5859,5860,5861 ^
 --csv %OUTDIR% --csvf WMI_Activity.csv

REM ---------------------------------------------------------
REM 2. PROCESS CREATION VIA WMI
REM ---------------------------------------------------------
echo [+] Extracting Process Creation (4688)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4688 ^
 --csv %OUTDIR% --csvf Process_Create.csv

REM ---------------------------------------------------------
REM 3. NETWORK LOGON RELATED TO WMI
REM ---------------------------------------------------------
echo [+] Extracting Network Logon (4624)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4624 ^
 --csv %OUTDIR% --csvf Network_Logon.csv

REM ---------------------------------------------------------
REM 4. ADMIN PRIVILEGE ASSIGNMENT
REM ---------------------------------------------------------
echo [+] Extracting Admin Privileges (4672)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4672 ^
 --csv %OUTDIR% --csvf Admin_Privileges.csv

REM ---------------------------------------------------------
REM 5. SERVICE & PERSISTENCE (OPTIONAL WMI)
REM ---------------------------------------------------------
echo [+] Extracting Service Installation (7045)
%EVTEXE% -f "%EVTXDIR%\System.evtx" ^
 --eid 7045 ^
 --csv %OUTDIR% --csvf Services.csv

REM ---------------------------------------------------------
REM 6. ANTI-FORENSIC CHECK
REM ---------------------------------------------------------
echo [+] Extracting Log Clearing Events
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 1102 ^
 --csv %OUTDIR% --csvf Log_Cleared_Security.csv

%EVTEXE% -f "%EVTXDIR%\System.evtx" ^
 --eid 104 ^
 --csv %OUTDIR% --csvf Log_Cleared_System.csv

echo.
echo [✓] WMI Forensic Extraction Completed
echo [✓] Review:
echo     - WMI_Activity.csv   (5858 = execution)
echo     - Process_Create.csv (Parent = WmiPrvSE.exe)
echo     - Network_Logon.csv  (LogonType 3)
echo.
pause
