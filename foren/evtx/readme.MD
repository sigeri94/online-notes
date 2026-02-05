#copy sysvol 
```powershell
robocopy "K:\Windows\SYSVOL\domain\Policies" "C:\foren\sysvol" /E /COPYALL /R:0 /W:0 /XJ
```

# Windows Event Log Extraction – Oracle & Shell Core

## 1. Persiapan Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
````
---

## 2. Ekstraksi Oracle Event Log (Application.evtx)

Oracle di Windows **tidak menulis data ke field `Message`**, melainkan ke
`EventData`. Oleh karena itu, data Oracle diambil dari `Properties[0].Value`.

```powershell
Get-WinEvent -Path "$source\Application.evtx" |
Where-Object { $_.ProviderName -like "Oracle*" } |
Select-Object TimeCreated, Id, ProviderName,
    @{Name="OracleData";Expression={$_.Properties[0].Value}} |
Export-Csv oracle_events.csv -NoTypeInformation -Encoding UTF8
```

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
Export-Excel -Path .\VNC_Connections.xlsx -AutoSize

```

---

## 3. Ekstraksi Shell Core Operational Log

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -Path "$source\Microsoft-Windows-Shell-Core%4Operational.evtx" | Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated | Export-Csv -Path ".\shell.csv" -NoTypeInformation
```
---
```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -Path "$source\System.evtx" | Select-Object TimeCreated, Id, ProviderName,Message| Sort-Object TimeCreated |Export-Csv -Path ".\system.csv" -NoTypeInformation
Get-WinEvent -Path "$source\Application.evtx" | Select-Object TimeCreated, Id, ProviderName,Message| Sort-Object TimeCreated |Export-Csv -Path ".\app.csv" -NoTypeInformation
$ids = @(1033,1040,1042); Get-WinEvent -Path "$source\Application.evtx" | Where-Object { $ids -contains $_.Id } | Select TimeCreated, Id, ProviderName, Message | Sort TimeCreated

```

## 1. Analisa Login Berhasil (Event ID 4624)

### Tujuan
Mengidentifikasi pola login pada sistem dan memastikan dominasi login
service/batch dibanding login interaktif.

### Statistik Logon Type
```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4624 } |
Group-Object { $_.Properties[8].Value } |
Select Count, Name
````

### Interpretasi Logon Type

| Logon Type | Arti                        |
| ---------- | --------------------------- |
| 2          | Interactive (Console / RDP) |
| 3          | Network                     |
| 4          | Batch (Scheduled Task)      |
| 5          | Service                     |
| 7          | Unlock workstation          |

📌 **Logon Type 2 & 3 dianggap sensitif pada server**

---

## 2. Detail Logon Type 2 & 3 (IMPORTANT)

### Tujuan

Mengidentifikasi:

* User yang login interaktif
* Sumber koneksi jaringan
* Aktivitas admin manual

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4624 } | Where-Object { $_.Properties[8].Value -in 2,3 } | Select TimeCreated, @{Name='LogonType';Expression={$_.Properties[8].Value}}, @{Name='Account';Expression={$_.Properties[5].Value}}, @{Name='SourceIP';Expression={$_.Properties[18].Value}}
```

📌 Event di luar jam kerja perlu perhatian khusus.

---

## 3. Analisa Login Gagal (Event ID 4625)

### Tujuan

Mendeteksi:

* Brute force attempt
* Credential misconfiguration
* Account abuse

```powershell
LogParser.exe "SELECT a.TimeGenerated AS FailedLoginTime, b.TimeGenerated AS SuccessfulLoginTime, a.Message AS FailedLoginMessage, b.Message AS
SuccessfulLoginMessage INTO CorrelatedLogins.csv FROM FailedLogins.evtx a JOIN SuccessfulLogins.evtx b ON a.User=b.User WHERE a.EventID=4625 AND b.EventID=4624" -i:EVT -o:CSV
```

### Statistik berdasarkan Source IP

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4625 } | Group-Object { $_.Properties[19].Value } | Sort Count -Descending | Select Count, Name
```

📌 Source IP dengan volume tinggi perlu diinvestigasi.

---

## 4. Explicit Credential Usage (Event ID 4648)

### Tujuan

Mengidentifikasi penggunaan credential eksplisit (`runas`, service account,
automation).

⚠️ Event dari `svchost.exe` umumnya **normal**
⚠️ Fokus pada proses non-system

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4648 } | Where-Object { $_.Properties[11].Value -notmatch "svchost.exe" } | Select TimeCreated, @{Name='TargetAccount';Expression={$_.Properties[5].Value}}, @{Name='CallingProcess';Expression={$_.Properties[11].Value}}
```

🔴 Proses seperti `powershell.exe`, `cmd.exe`, `wscript.exe` perlu investigasi.

---
## 5. Code Integrity Violation (Event ID 5038)

### Tujuan

Mendeteksi:

* Driver tidak sah
* Binary unsigned
* Potensi kernel-level compromise

### Exclusion

Event dari **EDR/AV legitimate (SentinelOne)** dikecualikan.

```powershell
$source="artefak\winevt\Logs"
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=5038 } | Where-Object {
    $_.Properties[0].Value -notmatch "SentinelOne"
} | Select TimeCreated, @{Name='File';Expression={$_.Properties[0].Value}}, @{Name='Process';Expression={$_.Properties[1].Value}}
```
---
