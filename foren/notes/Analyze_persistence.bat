@echo off
REM =========================================================
REM  EvtxECmd - User Account Persistence Forensics
REM =========================================================

SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUTDIR=output_user_persistence

IF NOT EXIST %OUTDIR% (
    mkdir %OUTDIR%
)

echo.
echo [*] Starting User Account Persistence Analysis
echo [*] EVTX Source : %EVTXDIR%
echo [*] Output Dir  : %OUTDIR%
echo.

REM ---------------------------------------------------------
REM 1. USER ACCOUNT LIFECYCLE
REM ---------------------------------------------------------
echo [+] Extracting User Account Events (Create / Enable / Disable)
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4720,4722,4725 ^
 --csv %OUTDIR% --csvf User_Lifecycle.csv

REM ---------------------------------------------------------
REM 2. PASSWORD CHANGES & RESETS
REM ---------------------------------------------------------
echo [+] Extracting Password Change / Reset Events
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4723,4724 ^
 --csv %OUTDIR% --csvf Password_Changes.csv

REM ---------------------------------------------------------
REM 3. USER ACCOUNT MODIFICATION
REM ---------------------------------------------------------
echo [+] Extracting User Account Modifications
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4738 ^
 --csv %OUTDIR% --csvf User_Modified.csv

REM ---------------------------------------------------------
REM 4. GROUP MEMBERSHIP CHANGES (PRIV ESC / PERSISTENCE)
REM ---------------------------------------------------------
echo [+] Extracting Group Membership Changes
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4732,4733,4728,4729,4756,4757 ^
 --csv %OUTDIR% --csvf Group_Membership.csv

REM ---------------------------------------------------------
REM 5. ADMIN PRIVILEGE ASSIGNMENT
REM ---------------------------------------------------------
echo [+] Extracting Admin Privilege Assignment
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4672 ^
 --csv %OUTDIR% --csvf Admin_Privileges.csv

REM ---------------------------------------------------------
REM 6. LOGON ACTIVITY (AFTER CHANGES)
REM ---------------------------------------------------------
echo [+] Extracting Logon Activity
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4624,4625 ^
 --csv %OUTDIR% --csvf Logon_Activity.csv

REM ---------------------------------------------------------
REM 7. ACCOUNT LOCK / UNLOCK
REM ---------------------------------------------------------
echo [+] Extracting Account Lock / Unlock Events
%EVTEXE% -f "%EVTXDIR%\Security.evtx" ^
 --eid 4740,4767 ^
 --csv %OUTDIR% --csvf Account_Lock_Unlock.csv

echo.
echo [✓] User Persistence Analysis Completed
echo [✓] Key Correlation Paths:
echo     - 4722 -> 4732 -> 4672 -> 4624  (Backdoor admin)
echo     - 4724 -> 4624 -> 4672          (Account takeover)
echo     - 4720 + no 4624                (Dormant persistence)
echo.
pause
