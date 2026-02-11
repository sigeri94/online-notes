### Copy sysvol 
```powershell
robocopy "K:\Windows\SYSVOL\domain\Policies" "C:\foren\sysvol" /E /COPYALL /R:0 /W:0 /XJ
```

# Windows Event Log Extraction – Oracle & Shell Core

### Persiapan Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
````
---

### Analisa Log System
```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -Path "$source\System.evtx" | Select-Object TimeCreated, Id, ProviderName,Message| Sort-Object TimeCreated |Export-Csv -Path ".\system.csv" -NoTypeInformation
```

## Analisa (Event ID 5038)
Mendeteksi:
* Driver tidak sah
* Binary unsigned
* Potensi kernel-level compromise
Event dari **EDR/AV legitimate (SentinelOne)** dikecualikan.

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=5038 } | Where-Object {
    $_.Properties[0].Value -notmatch "SentinelOne"
} | Select TimeCreated, @{Name='File';Expression={$_.Properties[0].Value}}, @{Name='Process';Expression={$_.Properties[1].Value}}
```

### Analisa Log Aplikasi
```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -Path "$source\Application.evtx" | Select-Object TimeCreated, Id, ProviderName,Message| Sort-Object TimeCreated |Export-Csv -Path ".\app.csv" -NoTypeInformation
$ids = @(1033,1040,1042); Get-WinEvent -Path "$source\Application.evtx" | Where-Object { $ids -contains $_.Id } | Select TimeCreated, Id, ProviderName, Message | Sort TimeCreated
```

## Analisa Log Oracle
```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $_.ProviderName -like "Oracle*" } |
Select-Object TimeCreated, Id, ProviderName,
    @{Name="OracleData";Expression={$_.Properties[0].Value}} |
Export-Csv oracle_events.csv -NoTypeInformation -Encoding UTF8
```
## Analisa Log VNC

```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $_.ProviderName -like "*VNC*" } |
Select-Object `
    TimeCreated,
    LevelDisplayName,
    ProviderName,
    LogName,
    @{Name="VNC_Data";Expression={
        ($_.Properties | ForEach-Object { $_.Value }) -join " | "
    }} |
Export-Excel -Path .\koko_log_vnc.xlsx -AutoSize
```
## Analisa Log TightVNC

```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $_.ProviderName -like "*tvnserver*" } |
Select-Object `
    TimeCreated,
    LevelDisplayName,
    ProviderName,
    LogName,
    @{Name="tvnserver";Expression={
        ($_.Properties | ForEach-Object { $_.Value }) -join " | "
    }} |
Export-Excel -Path .\koko_log_tvn.xlsx -AutoSize
```

## Analisa Log Security

##Prosess Creation
```powershell
 Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4688 } | select-object TimeCreated,id, LevelDisplayName, Message | Sort-Object TimeCreated | Export-Csv .\koko_4688.csv
```
### Statistik Logon
```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4624 } | Group-Object { $_.Properties[8].Value } | Select Count, Name
````

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4625 } | Group-Object { $_.Properties[19].Value } | Sort Count -Descending | Select Count, Name
```

### Interpretasi Logon Type

| Logon Type | Arti                        |
| ---------- | --------------------------- |
| 2          | Interactive (Console / RDP) |
| 3          | Network                     |
| 4          | Batch (Scheduled Task)      |
| 5          | Service                     |
| 7          | Unlock workstation          |

📌 **Logon Type 2 & 3 dianggap sensitif pada server**

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4624 } | Where-Object { $_.Properties[8].Value -in 2,3 } | Select TimeCreated, @{Name='LogonType';Expression={$_.Properties[8].Value}}, @{Name='Account';Expression={$_.Properties[5].Value}}, @{Name='SourceIP';Expression={$_.Properties[18].Value}}
```

## Explicit Credential Usage (Event ID 4648)

Mengidentifikasi penggunaan credential eksplisit (`runas`, service account,automation).

⚠️ Event dari `svchost.exe` umumnya **normal**
⚠️ Fokus pada proses non-system

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4648 } | Where-Object { $_.Properties[11].Value -notmatch "svchost.exe" } | Select TimeCreated, @{Name='TargetAccount';Expression={$_.Properties[5].Value}}, @{Name='CallingProcess';Expression={$_.Properties[11].Value}}
```
🔴 Proses seperti `powershell.exe`, `cmd.exe`, `wscript.exe` perlu investigasi.

---
# Windows Event Log Extraction Playbook
## DFIR / Incident Response Collection Guide

Dokumen ini berisi perintah PowerShell untuk mengekstrak berbagai Windows Event Log penting
untuk kebutuhan:

- Incident Response
- Threat Hunting
- Timeline Reconstruction
- Lateral Movement Detection
- Persistence Detection

Semua output diurutkan berdasarkan waktu (TimeCreated) dan diekspor ke CSV
dengan nama file yang mencerminkan isi log.

---

# PowerShell Operational Log

## Kegunaan

- Script Block Logging (Event ID 4104)
- Module Logging (4103)
- Command execution detail
- Suspicious encoded command detection

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-PowerShell%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\PowerShell_Operational_Log_Timeline.csv" -NoTypeInformation

# PowerShell Classic Log

## Kegunaan

* Engine lifecycle
* Basic execution logging
* Host activity

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-PowerShell.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\PowerShell_Classic_Log_Timeline.csv" -NoTypeInformation
```
---
# Shell-Core Operational Log

## Kegunaan

* Explorer activity
* User interaction artifacts
* File execution hints

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-Shell-Core%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\Shell_Core_Operational_Timeline.csv" -NoTypeInformation
```

---

# Task Scheduler Operational Log

## Kegunaan

* Scheduled task creation (Persistence)
* Task modification
* Task execution
* Malicious scheduled task detection

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-TaskScheduler%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\Scheduled_Task_Operational_Timeline.csv" -NoTypeInformation
```

---

# Shell-Core AppDefaults Log

## Kegunaan

* Default application changes
* File association changes
* Potential hijacking detection

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-Shell-Core%4AppDefaults.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\Shell_AppDefaults_Timeline.csv" -NoTypeInformation
```

---

# WMI Activity Operational Log

## Kegunaan

* Remote WMI execution
* Suspicious WMI queries
* Lateral movement detection
* Process creation via WMI

## Command

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-WMI-Activity%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\WMI_Activity_Operational_Timeline.csv" -NoTypeInformation
```

---

# WinRM Operational Log

## Kegunaan

* Remote PowerShell sessions
* WinRM-based lateral movement
* Authentication over WSMan

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-WinRM%4Operational.evtx" |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\WinRM_Operational_Timeline.csv" -NoTypeInformation
```

---

# Program Telemetry Log

## Kegunaan

* Program execution artifacts
* Malware execution detection
* Suspicious binary tracking
* Timeline enrichment

```powershell
Get-WinEvent -Path "$source\Microsoft-Windows-Application-Experience%4Program-Telemetry.evtx" |
Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
Sort-Object TimeCreated |
Export-Csv ".\Program_Execution_Telemetry_Timeline.csv" -NoTypeInformation
```

---

# LogParser

```powershell
LogParser.exe "SELECT a.TimeGenerated AS FailedLoginTime, b.TimeGenerated AS SuccessfulLoginTime, a.Message AS FailedLoginMessage, b.Message AS
SuccessfulLoginMessage INTO CorrelatedLogins.csv FROM FailedLogins.evtx a JOIN SuccessfulLogins.evtx b ON a.User=b.User WHERE a.EventID=4625 AND b.EventID=4624" -i:EVT -o:CSV
```

---
