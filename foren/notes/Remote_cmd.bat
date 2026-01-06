@echo off
REM =========================================================
REM  Remote Execution Forensics
REM  Scope : WMI / PsExec / WinRM
REM  Tool  : EvtxECmd
REM =========================================================

SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUTDIR=output_remote_exec

IF NOT EXIST %OUTDIR% (
    mkdir %OUTDIR%
)

echo.
echo [*] Remote Execution Forensic Analysis
echo [*] EVTX Source : %EVTXDIR%
echo [*] Output Dir  : %OUTDIR%
echo.

REM =========================================================
REM 1. COMMON AUTHENTICATION (REMOTE LOGON)
REM =========================================================
echo [+] Extracting Remote Logon Activity
%EVTEXE% -d %EVTXDIR% ^
 --eid 4624,4625 ^
 --inc "Logon Type: 3" ^
 --csv %OUTDIR% --csvf Remote_Logon.csv

REM =========================================================
REM 2. WMI EXECUTION
REM =========================================================
echo [+] Extracting WMI Process Execution
%EVTEXE% -d %EVTXDIR% ^
 --eid 4688 ^
 --inc "wmiprvse.exe" ^
 --csv %OUTDIR% --csvf WMI_Process.csv

echo [+] Extracting WMI Subscription Activity
%EVTEXE% -f "%EVTXDIR%\Microsoft-Windows-WMI-Activity%4Operational.evtx" ^
 --eid 5857,5858,5861 ^
 --csv %OUTDIR% --csvf WMI_Subscription.csv

REM =========================================================
REM 3. PSEXEC EXECUTION
REM =========================================================
echo [+] Extracting PsExec Service Installation
%EVTEXE% -d %EVTXDIR% ^
 --eid 7045 ^
 --inc "PSEXESVC" ^
 --csv %OUTDIR% --csvf PsExec_Service.csv

echo [+] Extracting PsExec Process Execution
%EVTEXE% -d %EVTXDIR% ^
 --eid 4688 ^
 --inc "psexecsvc.exe" ^
 --csv %OUTDIR% --csvf PsExec_Process.csv

REM =========================================================
REM 4. WINRM / POWERSHELL REMOTING
REM =========================================================
echo [+] Extracting WinRM Spawned Processes
%EVTEXE% -d %EVTXDIR% ^
 --eid 4688 ^
 --inc "wsmprovhost.exe" ^
 --csv %OUTDIR% --csvf WinRM_Process.csv

echo [+] Extracting WinRM Connections
%EVTEXE% -f "%EVTXDIR%\Microsoft-Windows-WinRM%4Operational.evtx" ^
 --eid 91 ^
 --csv %OUTDIR% --csvf WinRM_Connection.csv

REM =========================================================
REM 5. POWERSHELL PAYLOAD (REMOTE)
REM =========================================================
echo [+] Extracting PowerShell Script Execution
%EVTEXE% -f "%EVTXDIR%\Windows PowerShell.evtx" ^
 --eid 4104 ^
 --inc "Invoke,EncodedCommand,DownloadString" ^
 --csv %OUTDIR% --csvf PowerShell_Remote.csv

echo.
echo [✓] Remote Execution Analysis Completed
echo.
echo [Correlation Guide]
echo  - 4624 (Type 3) -> 4688 (wmiprvse.exe)        = WMI Exec
echo  - 7045 (PSEXESVC) -> 4688 (psexecsvc.exe)    = PsExec
echo  - 4688 (wsmprovhost.exe) -> 4104             = WinRM
echo.
pause
