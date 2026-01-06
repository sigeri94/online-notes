@echo off
REM =========================================================
REM  EvtxECmd Forensic Batch
REM  Author  : DFIR Use
REM  Purpose : Extract key forensic Event IDs
REM =========================================================

SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUTDIR=output

IF NOT EXIST %OUTDIR% (
    mkdir %OUTDIR%
)

echo.
echo [*] Starting EVTX Forensic Extraction...
echo [*] EVTX Source : %EVTXDIR%
echo [*] Output Dir  : %OUTDIR%
echo.

REM ---------------------------------------------------------
REM 1. PROCESS EXECUTION
REM ---------------------------------------------------------
echo [+] Extracting Process Creation (4688)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" --eid 4688 --csv %OUTDIR% --csvf 4688_ProcessCreation.csv

REM ---------------------------------------------------------
REM 2. AUTHENTICATION & PRIVILEGE
REM ---------------------------------------------------------
echo [+] Extracting Logon Events (4624,4625)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" --eid 4624,4625 --csv %OUTDIR% --csvf Auth_Logon.csv

echo [+] Extracting Admin Privilege Logon (4672)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" --eid 4672 --csv %OUTDIR% --csvf Admin_Logon.csv

echo [+] Extracting Explicit Credentials Usage (4648)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" --eid 4648 --csv %OUTDIR% --csvf Explicit_Creds.csv

REM ---------------------------------------------------------
REM 3. POWERSHELL
REM ---------------------------------------------------------
echo [+] Extracting PowerShell Activity (4104,4103)
%EVTEXE% -f "%EVTXDIR%\Microsoft-Windows-PowerShell%%4Operational.evtx" --eid 4104,4103 --csv %OUTDIR% --csvf PowerShell.csv

REM ---------------------------------------------------------
REM 4. RDP ACTIVITY
REM ---------------------------------------------------------
echo [+] Extracting RDP Events (21,24,25)
%EVTEXE% -f "%EVTXDIR%\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx" --eid 21,24,25 --csv %OUTDIR% --csvf RDP_Sessions.csv

REM ---------------------------------------------------------
REM 5. PERSISTENCE
REM ---------------------------------------------------------
echo [+] Extracting Service Installation (7045)
%EVTEXE% -f "%EVTXDIR%\System.evtx" --eid 7045 --csv %OUTDIR% --csvf Service_Install.csv

echo [+] Extracting Scheduled Tasks (106,140,200)
%EVTEXE% -f "%EVTXDIR%\Microsoft-Windows-TaskScheduler%%4Operational.evtx" --eid 106,140,200 --csv %OUTDIR% --csvf Scheduled_Tasks.csv

REM ---------------------------------------------------------
REM 6. FILE ACCESS (IF ENABLED)
REM ---------------------------------------------------------
echo [+] Extracting File Access Events (4663,4660)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" --eid 4663,4660 --csv %OUTDIR% --csvf File_Access.csv

REM ---------------------------------------------------------
REM 7. ANTI-FORENSIC
REM ---------------------------------------------------------
echo [+] Extracting Log Clearing Events (1102,104)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" --eid 1102 --csv %OUTDIR% --csvf Log_Cleared_Security.csv
%EVTEXE% -f "%EVTXDIR%\System.evtx" --eid 104 --csv %OUTDIR% --csvf Log_Cleared_System.csv

echo.
echo [✓] EVTX extraction completed.
echo [✓] CSV files saved in %OUTDIR%
echo.

REM ---------------------------------------------------------
REM 8. SYSTEM LOG ANALYSIS
REM ---------------------------------------------------------
echo [+] Extracting System Events (Service, Driver, Boot)

EvtxECmd.exe -f "%EVTXDIR%\System.evtx" --eid 7045,7036,7000,7022,7011 --csv %OUTDIR% --csvf System_Services.csv

EvtxECmd.exe -f "%EVTXDIR%\System.evtx" --eid 6,219 --csv %OUTDIR% --csvf System_Drivers.csv

EvtxECmd.exe -f "%EVTXDIR%\System.evtx" --eid 6005,6006,6008,1074 --csv %OUTDIR% --csvf System_Boot_Shutdown.csv

EvtxECmd.exe -f "%EVTXDIR%\System.evtx" --eid 104,1101 --csv %OUTDIR% --csvf System_Log_Tamper.csv


REM ---------------------------------------------------------
REM 9. APPLICATION LOG ANALYSIS
REM ---------------------------------------------------------
echo [+] Extracting Application Crash & Errors

EvtxECmd.exe -f "%EVTXDIR%\Application.evtx" --eid 1000,1001,1026 --csv %OUTDIR% --csvf Application_Crash.csv

EvtxECmd.exe -f "%EVTXDIR%\Application.evtx" --eid 11707,11708 --csv %OUTDIR% --csvf Application_MSI.csv

EvtxECmd.exe -f "%EVTXDIR%\Application.evtx" --eid 1309,3005 --csv %OUTDIR% --csvf Application_IIS.csv
