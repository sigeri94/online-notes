```powershell

kape.exe ^
 --tsource C: ^
 --tdest D:\KAPE\Collect ^
 --target !EventLogs,!Prefetch,!Amcache,!AppCompatCache,!LNKFiles,!JLECmd,!PowerShell,!SRUM,!ScheduledTasks,!RegistryHives,!UserAssist ^
 --vhdx Collect.vhdx ^
 --md5 --sha1 --sha256 ^
 --compress
```
