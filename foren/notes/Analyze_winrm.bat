@echo off
REM =========================================================
REM  EvtxECmd - WinRM / PowerShell Remoting Forensics
REM =========================================================

SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUTDIR=output_winrm

IF NOT EXIST %OUTDIR% (
    mkdir %OUTDIR%
)

echo.
echo [*] Starting WinRM / PowerShell Remoting Analysis
echo.

REM ---------------------------------------------------------
REM 1. NETWORK LOGON
REM ---------------------------------------------------------
echo [+] Extracting Network Logon (4624)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4624 ^
 --csv %OUTDIR% --csvf Network_Logon.csv

REM ---------------------------------------------------------
REM 2. PROCESS CREATION (WinRM CHILD)
REM ---------------------------------------------------------
echo [+] Extracting Process Creation (4688)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4688 ^
 --csv %OUTDIR% --csvf Process_Create.csv

REM ---------------------------------------------------------
REM 3. POWERSHELL LOGGING
REM ---------------------------------------------------------
echo [+] Extracting PowerShell Logs (4104,4103)
%EVTEXE% -f "%EVTXDIR%\Microsoft-Windows-PowerShell%%4Operational.evtx" ^
 --eid 4104,4103 ^
 --csv %OUTDIR% --csvf PowerShell.csv

REM ---------------------------------------------------------
REM 4. WINRM SERVICE ACTIVITY
REM ---------------------------------------------------------
echo [+] Extracting WinRM Service Events
%EVTEXE% -f "%EVTXDIR%\System.evtx" ^
 --eid 7036 ^
 --csv %OUTDIR% --csvf WinRM_Service.csv

REM ---------------------------------------------------------
REM 5. ADMIN PRIVILEGE
REM ---------------------------------------------------------
echo [+] Extracting Admin Privileges (4672)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4672 ^
 --csv %OUTDIR% --csvf Admin_Privileges.csv

echo.
echo [✓] WinRM Analysis Completed
echo [✓] Key Indicators:
echo     - Parent process = wsmprovhost.exe
echo     - PowerShell 4104 content
echo     - Network logon (type 3)
echo.
pause
