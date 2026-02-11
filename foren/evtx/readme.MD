# Windows DFIR Log Collection & Analysis Playbook

# 1 Initial Preparation

## Set Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```
---

# 2 Global Variable

```powershell
$source = "artefak\winevt\Logs"
```

---

# 3 System Log Analysis

## Export Full System Log Timeline

```powershell
Get-WinEvent -Path "$source\System.evtx" |
Select-Object TimeCreated, Id, ProviderName, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\System_Log_Timeline.csv" -NoTypeInformation
```

```powershell
$ids=@(7045,7036,7040,7031,7034); $excludeServices=@("Background Intelligent Transfer Service","Windows Modules Installer"); Get-WinEvent -Path "$source\System.evtx" | Where-Object { $ids -contains $_.Id -and !($_.Id -eq 7040 -and $excludeServices -contains $_.Properties[0].Value) } | Select TimeCreated,Id,ProviderName,@{n='ServiceName';e={$_.Properties[0].Value}},Message | Sort TimeCreated

```
---

## 🔎 Event ID 5038 – Code Integrity Failure

Mendeteksi:

* Driver tidak sah
* Binary unsigned
* Potensi kernel compromise

 Event dari EDR/AV legitimate (contoh: SentinelOne) dikecualikan.

```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=5038 } |
Where-Object { $_.Properties[0].Value -notmatch "SentinelOne" } |
Select-Object TimeCreated,
    @{Name='File';Expression={$_.Properties[0].Value}},
    @{Name='Process';Expression={$_.Properties[1].Value}}
```

---

# 4 Application Log Analysis

## Export Full Application Log

```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Select-Object TimeCreated, Id, ProviderName, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\Application_Log_Timeline.csv" -NoTypeInformation
```

---

## Filter Specific Application Event IDs

```powershell
$ids = @(1033,1040,1042)

Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $ids -contains $_.Id } |
Select-Object TimeCreated, Id, ProviderName, Message |
Sort-Object TimeCreated
```

---

## Oracle Log Analysis

```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $_.ProviderName -like "Oracle*" } |
Select-Object TimeCreated, Id, ProviderName,
    @{Name="OracleData";Expression={$_.Properties[0].Value}} |
Export-Csv ".\Oracle_Application_Events.csv" -NoTypeInformation -Encoding UTF8
```

---

## VNC Log Analysis

```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $_.ProviderName -like "*VNC*" } |
Select-Object TimeCreated,
    LevelDisplayName,
    ProviderName,
    LogName,
    @{Name="VNC_Data";Expression={
        ($_.Properties | ForEach-Object { $_.Value }) -join " | "
    }} |
Export-Excel -Path ".\VNC_Application_Events.xlsx" -AutoSize
```

---

## TightVNC Log Analysis

```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $_.ProviderName -like "*tvnserver*" } |
Select-Object TimeCreated,
    LevelDisplayName,
    ProviderName,
    LogName,
    @{Name="TightVNC_Data";Expression={
        ($_.Properties | ForEach-Object { $_.Value }) -join " | "
    }} |
Export-Excel -Path ".\TightVNC_Application_Events.xlsx" -AutoSize
```

---

# 5 Security Log Analysis

---

## Process Creation – Event ID 4688

```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4688 } |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Sort-Object TimeCreated |
Export-Csv ".\Security_ProcessCreation_4688_Timeline.csv" -NoTypeInformation
```

---

## Logon Statistics – Event ID 4624

```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4624 } |
Group-Object { $_.Properties[8].Value } |
Select-Object Count, Name
```

### Logon Type Reference

| Logon Type | Description                 |
| ---------- | --------------------------- |
| 2          | Interactive (Console / RDP) |
| 3          | Network                     |
| 4          | Batch (Scheduled Task)      |
| 5          | Service                     |
| 7          | Unlock Workstation          |

 **Logon Type 2 & 3 dianggap sensitif pada server**

---

## Filter Sensitive Logon (Type 2 & 3)

```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4624 } |
Where-Object { $_.Properties[8].Value -in 2,3 } |
Select-Object TimeCreated,
    @{Name='LogonType';Expression={$_.Properties[8].Value}},
    @{Name='Account';Expression={$_.Properties[5].Value}},
    @{Name='SourceIP';Expression={$_.Properties[18].Value}}
```

---

## Failed Logon Statistics – Event ID 4625

```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4625 } |
Group-Object { $_.Properties[19].Value } |
Sort-Object Count -Descending |
Select-Object Count, Name
```

---

## Explicit Credential Usage – Event ID 4648

Digunakan untuk mendeteksi:

* `runas`
* Service account misuse
* Automation abuse
* Credential harvesting attempt

 Event dari `svchost.exe` umumnya normal, Fokus pada proses non-system seperti:

* powershell.exe
* cmd.exe
* wscript.exe

```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4648 } |
Where-Object { $_.Properties[11].Value -notmatch "svchost.exe" } |
Select-Object TimeCreated,
    @{Name='TargetAccount';Expression={$_.Properties[5].Value}},
    @{Name='CallingProcess';Expression={$_.Properties[11].Value}}
```

---

# 6 PowerShell & Lateral Movement Logs

---

## PowerShell Operational

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-PowerShell%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv ".\PowerShell_Operational_Timeline.csv" -NoTypeInformation
```

---

## PowerShell Classic

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-PowerShell.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv ".\PowerShell_Classic_Timeline.csv" -NoTypeInformation
```

---

## WMI Activity

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-WMI-Activity%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv ".\WMI_Activity_Timeline.csv" -NoTypeInformation
```

---

## WinRM Activity

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-WinRM%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv ".\WinRM_Operational_Timeline.csv" -NoTypeInformation
```

---

## Task Scheduler (Persistence)

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-TaskScheduler%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv ".\ScheduledTask_Operational_Timeline.csv" -NoTypeInformation
```

---

## Shell-Core Operational

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-Shell-Core%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv ".\ShellCore_Operational_Timeline.csv" -NoTypeInformation
```

---

## Shell AppDefaults

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-Shell-Core%4AppDefaults.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv ".\Shell_AppDefaults_Timeline.csv" -NoTypeInformation
```

---

## Program Telemetry

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-Application-Experience%4Program-Telemetry.evtx" |
Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
Sort-Object TimeCreated |
Export-Csv ".\Program_Execution_Telemetry_Timeline.csv" -NoTypeInformation
```
---
# Antivirus
```powershell
Get-WinEvent -Path "$source\Kaspersky Endpoint Security.evtx" |
Select TimeCreated, Id, LevelDisplayName, Message |
Sort TimeCreated |
Export-Csv ".\Kaspersky_Endpoint_Timeline.csv" -NoTypeInformation

Get-WinEvent -Path "$source\Kaspersky Event Log.evtx" |
Select TimeCreated, Id, LevelDisplayName, Message |
Sort TimeCreated |
Export-Csv ".\Kaspersky_EventLog_Timeline.csv" -NoTypeInformation
```

---
---

# 7 Log Correlation with LogParser

```powershell
LogParser.exe "
SELECT a.TimeGenerated AS FailedLoginTime,
       b.TimeGenerated AS SuccessfulLoginTime,
       a.Message AS FailedLoginMessage,
       b.Message AS SuccessfulLoginMessage
INTO Correlated_Logins.csv
FROM FailedLogins.evtx a
JOIN SuccessfulLogins.evtx b
ON a.User = b.User
WHERE a.EventID = 4625 AND b.EventID = 4624
" -i:EVT -o:CSV
```

Digunakan untuk:

* Korelasi brute force → login sukses
* Credential stuffing detection
* Suspicious authentication chain

---
