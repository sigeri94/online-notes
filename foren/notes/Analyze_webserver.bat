@echo off
SET EVTEXE=EvtxECmd.exe
SET EVTXDIR=evtx
SET OUT=output_filtered

mkdir %OUT% 2>nul

REM --- RCE from Web Services ---
%EVTEXE% -d %EVTXDIR% ^
 --eid 4688 ^
 --inc "httpd.exe,tomcat,apache,php-cgi" ^
 --csv %OUT% --csvf Web_RCE.csv

REM --- Bruteforce ---
%EVTEXE% -d %EVTXDIR% ^
 --eid 4625 ^
 --csv %OUT% --csvf Logon_Failure.csv

REM --- Success after brute ---
%EVTEXE% -d %EVTXDIR% ^
 --eid 4624 ^
 --csv %OUT% --csvf Logon_Success.csv
