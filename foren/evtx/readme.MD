# Windows DFIR Log Collection & Analysis Playbook

# Analisa security application dan kaspersky

Event ID 4724: "An attempt was made to reset an account's password"
Deskripsi: Event ini tercatat saat seseorang (Subject) mencoba mereset password pengguna lain atau akun komputer, baik di Domain Controller maupun lokal.
Relevansi Keamanan: Penting untuk memantau apakah ada administrator yang mereset password akun bernilai tinggi (seperti Domain Admin) secara tidak sah.

Event ID 4738: "A user account was changed"
Deskripsi: Event ini muncul setiap kali ada perubahan pada objek pengguna (user object), seperti perubahan grup, pengaturan "password not required", atau perubahan durasi logon.
Relevansi Keamanan: Digunakan untuk melacak modifikasi yang mencurigakan, seperti penambahan pengguna ke grup administratif.

Event ID 4798: "A user's local group membership was enumerated"
Deskripsi: Event ini tercatat ketika suatu proses atau pengguna (misalnya melalui perintah net user) menanyakan/menghitung anggota grup lokal (local group membership) pada sebuah komputer.
Relevansi Keamanan: Sering digunakan oleh penyerang (APT actors) dalam tahap reconnaissance atau pelacakan horizontal untuk memahami hak akses lokal yang telah dikompromi. 

Ringkasan Konteks Keamanan:
Kombinasi ketiga event ini memberikan visibilitas terhadap aktivitas admin/penyerang yang mencoba mengubah kredensial (4724), mengubah properti akun (4738), dan memetakan hak akses lokal (4798). 

```powershell
# ---------------------------
# Helper function to safely extract message
# ---------------------------
function Get-EventMessageSafe {
    param ($Event)

    # 1. Use standard Message if available
    if ($Event.Message -and $Event.Message.Trim() -ne "") {
        return $Event.Message
    }

    # 2. Try EventData <Data> nodes
    try {
        $xml = [xml]$Event.ToXml()

        $dataNodes = $xml.Event.EventData.Data
        if ($dataNodes) {
            $dataText = $dataNodes | ForEach-Object {
                if ($_.Name) { "$($_.Name): $($_.'#text')" } else { $_.'#text' }
            }
            if ($dataText -and ($dataText -join '') -ne '') {
                return ($dataText -join ' | ')
            }
        }

        # 3. Fallback: raw inner text
        $raw = ($xml.Event.EventData.InnerText).Trim()
        if ($raw -and $raw.Length -gt 0) {
            if ($raw.Length -gt 32000) { $raw.Substring(0,32000) } else { $raw }
        }
        else {
            return "[Message unavailable]"
        }
    }
    catch {
        return "[Message unavailable]"
    }
}

# ---------------------------
# Collect events
# ---------------------------
$events = @()

# Security.evtx: account changes, password resets, group enumeration
$events += Get-WinEvent -Path .\Security.evtx -FilterXPath "
    *[System[(EventID=4724 or EventID=4738 or EventID=4798)]]
"

# Application.evtx: MSI installs (SentinelOne, Java, etc.)
$events += Get-WinEvent -Path .\Application.evtx -FilterXPath "
    *[System[(EventID=1040 or EventID=1033)]]
"

# Kaspersky Endpoint Security.evtx: AV events
$events += Get-WinEvent -Path ".\Kaspersky Endpoint Security.evtx" -FilterXPath "
    *[System[(EventID=317)]]
"

# ---------------------------
# Sort events by time and export
# ---------------------------
# Remove old XLSX if exists
Remove-Item .\unified_timeline.xlsx -ErrorAction SilentlyContinue

$events |
Sort-Object TimeCreated |
Select @{
    Name = 'TimeCreated'
    Expression = { $_.TimeCreated.ToString('yyyy-MM-dd hh:mm:ss tt') }
},
Id,
ProviderName,
LogName,
@{
    Name = 'Message'
    Expression = { Get-EventMessageSafe $_ }
} |
Export-Excel -Path .\unified_timeline.xlsx `
             -WorksheetName Timeline `
             -AutoSize `
             -FreezeTopRow `
             -BoldTopRow

Write-Host "Unified timeline exported to unified_timeline.xlsx"
```
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


# 📌 System Log (System.evtx)

| Event ID | Kategori    | Deskripsi                 | Nilai Forensik     |
| -------- | ----------- | ------------------------- | ------------------ |
| 7045     | Persistence | New service installed     | Malware service    |
| 7036     | Service     | Service state changed     | Service start/stop |
| 1074     | System      | Shutdown / Restart        | Forced reboot      |
| 6005     | System      | Event log service started | Boot time marker   |
| 6006     | System      | Event log stopped         | Shutdown marker    |

---

## Export Full System Log Timeline

```powershell
Get-WinEvent -Path "$source\System.evtx" |
Select-Object TimeCreated, Id, ProviderName, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\System_Log_Timeline.csv" -NoTypeInformation
```
```powershell
$ids=@(
7045,7036,7040,7031,7034,   # Service activity
6005,6006,6008,41,1074,    # Boot/shutdown
6,                         # Driver load
7000,7009,7011,7022,7023,  # Service errors
104                        # Log cleared
)
```

```powershell
$ids=@(7045,7036,7040,7031,7034); $excludeServices=@("Background Intelligent Transfer Service","Windows Modules Installer"); Get-WinEvent -Path "$source\System.evtx" | Where-Object { $ids -contains $_.Id -and !($_.Id -eq 7040 -and $excludeServices -contains $_.Properties[0].Value) } | Select TimeCreated,Id,ProviderName,@{n='ServiceName';e={$_.Properties[0].Value}},Message | Sort TimeCreated

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

## Analisa instalasi

```powershell

$ids = @(1033,1034,1040,1042,11707,11724);
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

# 📌 Security Log (Security.evtx)

| Event ID | Kategori       | Deskripsi                   | Nilai Forensik                   |
| -------- | -------------- | --------------------------- | -------------------------------- |
| 4624     | Authentication | Successful logon            | Deteksi login & lateral movement |
| 4625     | Authentication | Failed logon                | Brute force / password spraying  |
| 4634     | Authentication | Logoff                      | Timeline session                 |
| 4648     | Authentication | Explicit credential use     | Pass-the-credential              |
| 4672     | Privilege      | Special privileges assigned | Login dengan hak admin           |
| 4688     | Process        | Process creation            | Eksekusi command                 |
| 4697     | Persistence    | Service installed           | Persistence via service          |
| 4698     | Persistence    | Scheduled task created      | Persistence via task             |
| 4702     | Persistence    | Scheduled task modified     | Modifikasi task                  |
| 4720     | Account Mgmt   | User account created        | Backdoor account                 |
| 4726     | Account Mgmt   | User account deleted        | Anti-forensic                    |
| 4732     | Account Mgmt   | User added to local group   | Privilege escalation             |
| 4719     | Policy Change  | Audit policy changed        | Defense evasion                  |
| 1102     | Anti-Forensic  | Security log cleared        | Log tampering                    |

---
## Process Creation – Event ID 4688

```powershell
Get-WinEvent -FilterHashtable @{ Path="$source\Security.evtx"; Id=4688 } |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Sort-Object TimeCreated |
Export-Csv ".\Security_ProcessCreation_4688_Timeline.csv" -NoTypeInformation
```
```powershell
$ids=@(1102); Get-WinEvent -Path "$source\Security.evtx" | Where-Object { $ids -contains $_.Id } | Select TimeCreated, Id, @{n='ClearedByUser';e={$_.Properties[1].Value}}, Message | Sort TimeCreated | Format-List
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

# 📌 RDP Related Logs 

TerminalServices-LocalSessionManager

| ID | Arti               |
| -- | ------------------ |
| 21 | Session login      |
| 22 | Shell start        |
| 23 | Logoff             |
| 24 | Disconnect         |
| 25 | Reconnect          |
| 39 | Disconnect manual  |
| 40 | Session switch     |
| 41 | Logoff saat switch |


```powershell
$source = "C:\forensic\logs"
$log = "$source\TerminalServices-LocalSessionManager.evtx"

$ids = @(21,22,23,24,25,39,40,41)

Get-WinEvent -Path $log |
Where-Object { $ids -contains $_.Id } |
ForEach-Object {

    $xml = [xml]$_.ToXml()

    $user      = $xml.Event.UserData.EventXML.User
    $sessionID = $xml.Event.UserData.EventXML.SessionID
    $ip        = $xml.Event.UserData.EventXML.Address

    # Bersihkan pesan agar satu baris
    $desc = ($_.Message -replace "`r|`n"," ").Trim()

    [PSCustomObject]@{
        Time        = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID     = $_.Id
        User        = $user
        SessionID   = $sessionID
        SourceIP    = $ip
        Description = $desc
    }
} | Sort-Object Time | Export-Csv "c:\users\batman\desktop\TS_Timeline.csv" -NoTypeInformation -Encoding UTF8

```

```powershell
$source = "C:\forensic\logs"
$log = "$source\TerminalServices-RemoteConnectionManager.evtx"

$ids = @(1149,1146,1147,261,263)

Get-WinEvent -Path $log |
Where-Object { $ids -contains $_.Id } |
ForEach-Object {

    $xml = [xml]$_.ToXml()

    $user = $xml.Event.UserData.Param1
    $ip   = $xml.Event.UserData.Param3

    $desc = ($_.Message -replace "`r|`n"," ").Trim()

    [PSCustomObject]@{
        Time        = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID     = $_.Id
        User        = $user
        SourceIP    = $ip
        Description = $desc
    }
} | Sort-Object Time |
Export-Csv "$source\RDP_Connection_Timeline.csv" -NoTypeInformation -Encoding UTF8

```
---

# 📌 Task Scheduler

| Event ID | Deskripsi       | Nilai Forensik           |
| -------- | --------------- | ------------------------ |
| 106      | Task registered | Persistence              |
| 140      | Task updated    | Persistence modification |

---

# 📌 Windows Defender (Microsoft-Windows-Windows Defender/Operational)

| Event ID | Kategori | Deskripsi            | Nilai Forensik  |
| -------- | -------- | -------------------- | --------------- |
| 5000     | AV       | Defender error       | AV failure      |
| 5001     | AV       | Defender disabled    | Defense evasion |
| 1116     | AV       | Malware detected     | IOC source      |
| 1117     | AV       | Malware action taken | Quarantine info |

---

# 📌 PowerShell (Microsoft-Windows-PowerShell/Operational)

| Event ID | Kategori  | Deskripsi            | Nilai Forensik            |
| -------- | --------- | -------------------- | ------------------------- |
| 400      | Execution | Engine started       | PowerShell usage          |
| 403      | Execution | Engine stopped       | Timeline                  |
| 4103     | Execution | Module logging       | Command detail            |
| 4104     | Execution | Script block logging | Fileless attack detection |

---

# 📌 WMI Activity

| Event ID | Deskripsi            | Nilai Forensik   |
| -------- | -------------------- | ---------------- |
| 5857     | WMI activity started | Lateral movement |
| 5861     | WMI permanent event  | Persistence      |

---

# 📌 BITS Client

| Event ID | Deskripsi        | Nilai Forensik   |
| -------- | ---------------- | ---------------- |
| 59       | BITS job created | Malware download |

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
