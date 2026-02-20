

# script memparsing isi folder tasks

```powershell
$taskFolder = "F:\Windows\System32\Tasks"
$targetYear = 2025
$taskFiles = Get-ChildItem -Path $taskFolder -File -Recurse
$results = @()

foreach ($file in $taskFiles) {
    try {
        [xml]$xml = Get-Content $file.FullName -ErrorAction Stop

        $triggerInfo = @()
        $eventID = ""
        $suspiciousTrigger = $false
        $includeTask = $false

        if ($xml.Task.Triggers) {
            foreach ($trigger in $xml.Task.Triggers.ChildNodes) {

                switch ($trigger.Name) {

                    "TimeTrigger" {
                        $date = [datetime]$trigger.StartBoundary
                        if ($date.Year -eq $targetYear) {
                            $includeTask = $true
                            $triggerInfo += "Time: $($trigger.StartBoundary)"
                        }
                    }

                    "DailyTrigger" {
                        $date = [datetime]$trigger.StartBoundary
                        if ($date.Year -eq $targetYear) {
                            $includeTask = $true
                            $triggerInfo += "Daily: $($trigger.StartBoundary)"
                        }
                    }

                    "WeeklyTrigger" {
                        $date = [datetime]$trigger.StartBoundary
                        if ($date.Year -eq $targetYear) {
                            $includeTask = $true
                            $triggerInfo += "Weekly: $($trigger.StartBoundary)"
                        }
                    }

                    "MonthlyTrigger" {
                        $date = [datetime]$trigger.StartBoundary
                        if ($date.Year -eq $targetYear) {
                            $includeTask = $true
                            $triggerInfo += "Monthly: $($trigger.StartBoundary)"
                        }
                    }

                    "CalendarTrigger" {
                        $date = [datetime]$trigger.StartBoundary
                        if ($date.Year -eq $targetYear) {
                            $includeTask = $true
                            $triggerInfo += "Calendar: $($trigger.StartBoundary)"
                        }
                    }

                    "EventTrigger" {
                        if ($trigger.Subscription -match "EventID=(\d+)") {
                            $eventID = $matches[1]
                        }
                    }
                }
            }
        }

        if ($includeTask) {

            $command = ""
            $arguments = ""
            $suspiciousAction = $false

            if ($xml.Task.Actions.Exec) {
                $command = $xml.Task.Actions.Exec.Command
                $arguments = $xml.Task.Actions.Exec.Arguments

                if ($command -match "powershell|cmd.exe|wscript|cscript|mshta|rundll32|regsvr32") {
                    $suspiciousAction = $true
                }
            }

            $results += [PSCustomObject]@{
                File              = $file.FullName
                Triggers          = ($triggerInfo -join "; ")
                EventID           = $eventID
                Command           = $command
                Arguments         = $arguments
                SuspiciousAction  = $suspiciousAction
            }
        }

    } catch {
        Write-Warning "Gagal membaca $($file.FullName)"
    }
}

$results | Format-Table -AutoSize
$results | Export-Csv "F:\ScheduledTask_2025_Report.csv" -NoTypeInformation -Encoding UTF8

```

---

## 1. Legitimate Software Activity

### Adobe

* **AdobeARM.exe** → Auto update Adobe Reader

### Microsoft Office 2013

* MsoSync.exe
* OLicenseHeartbeat.exe
* msoia.exe (scan upload)

### Microsoft Edge

* MicrosoftEdgeUpdate.exe /c
* MicrosoftEdgeUpdate.exe /ua /installsource scheduler

### Mozilla Firefox

* firefox.exe --backgroundtask backgroundupdate
* default-browser-agent.exe do-task

### Zoom

* Zoom.exe (user execution)

---

## 2. Windows Update & Maintenance

### Windows Update Orchestrator

* usoclient.exe StartDownload
* usoclient.exe StartInstall
* usoclient.exe StartScan
* MusNotification.exe Display / RebootDialog

### Disk & System Maintenance

* defrag.exe
* cleanmgr.exe
* srtasks.exe
* dmclient.exe
* devicecensus.exe

Semua terlihat sebagai scheduled maintenance normal.

---

## 3. Rundll32 Usage Review

Semua pemanggilan **rundll32** memanggil DLL resmi dari:

```
%windir%\system32
```

Contoh:

* Startupscan.dll,SusRunTask
* AppxDeploymentClient.dll,AppxPreStageCleanupRunTask
* sysmain.dll,PfSvWsSwapAssessmentTask
* bfe.dll,BfeOnServiceStartTypeChange

Tidak ditemukan indikasi pemanggilan DLL dari folder temp atau network path.

---

## 4. Service Control (sc.exe)

Contoh:

* sc.exe start w32time
* sc.exe start wuauserv
* sc.exe config upnphost start= auto

Tidak ditemukan create service baru atau service mencurigakan.

---

## 5. Items Requiring Validation

### SentinelOne Uninstall

```
Sentinel Agent uninstall.exe /os_upgrade /q /p {GUID}
```

Kemungkinan:

* Agent upgrade
* OS upgrade compatibility action

Perlu verifikasi change management jika tidak dalam maintenance window.

---

### Network Share Script

```
\\svr000ad02\Installer\S1\Log\Print Script.bat
```

Perlu verifikasi:

* Parent process
* User context
* Isi script
* Hash file

---

### Shutdown Execution

```
shutdown.exe /r /f
```

Kemungkinan restart akibat Windows Update.

---

## Overall Risk Assessment

| Category              | Assessment      |
| --------------------- | --------------- |
| Software Updater      | Normal          |
| Windows Maintenance   | Normal          |
| Rundll32 Usage        | Legitimate      |
| Service Control       | Legitimate      |
| SentinelOne Uninstall | Review Required |
| Network Share Script  | Review Required |

---


# 🔎 Forensik Scheduled Task yang Sudah Dihapus (Registry Analysis)

Jika **Scheduled Task dihapus**, artefaknya sering masih tersisa di **Registry TaskCache**. Ini sangat berguna dalam DFIR karena walaupun file XML di:

```
C:\Windows\System32\Tasks\
```

sudah hilang, metadata task masih bisa direcover dari registry.

---

# 📍 Lokasi Registry Task Scheduler

Task disimpan di:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
```

## Subkey penting

### 📁 Tree

```
TaskCache\Tree\
```

Berisi:

* Nama & path task
* Index
* GUID referensi
* Hidden flag

---

### 📁 Tasks

```
TaskCache\Tasks\
```

Berisi:

* GUID task
* Security Descriptor
* Trigger info
* LastRunTime
* Author & path

👉 Jika task dihapus:

* File XML hilang
* Entry Tree bisa hilang
* **GUID di Tasks sering masih ada**

Ini artefak recovery utama.

---

# 🧪 Cara Menemukan Task yang Suduh Dihapus

## ✅ 1. Enumerasi GUID Tasks yang masih tersisa

```powershell
$tasksPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"

Get-ChildItem $tasksPath | ForEach-Object {
    $guid = $_.PSChildName
    $props = Get-ItemProperty $_.PsPath
    [PSCustomObject]@{
        GUID = $guid
        Path = $props.Path
        LastRunTime = $props.LastRunTime
    }
}
```

### 🔎 Indikasi task terhapus:

✔ Path kosong atau aneh
✔ Tidak ada file XML di `System32\Tasks`
✔ Tidak muncul di Task Scheduler GUI

---

## ✅ 2. Cocokkan dengan Tree entries (deteksi orphaned tasks)

```powershell
$treePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
$tasksPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"

$treeGUIDs = Get-ChildItem -Recurse $treePath |
    Get-ItemProperty |
    Select-Object -ExpandProperty Id -ErrorAction SilentlyContinue

Get-ChildItem $tasksPath | ForEach-Object {
    $guid = $_.PSChildName
    if ($treeGUIDs -notcontains $guid) {
        Write-Output "Orphaned (possible deleted) task GUID: $guid"
    }
}
```

👉 GUID tanpa pasangan di Tree = **kemungkinan task sudah dihapus**

---

## ✅ 3. Melihat detail task orphaned

```powershell
$guid = "PASTE-GUID-DI-SINI"

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid"
```

Informasi yang bisa didapat:

* Path task asli
* LastRunTime
* Security context
* Trigger metadata

---

## 🔎 Konversi LastRunTime ke format waktu normal

Registry menyimpan waktu dalam format **FILETIME**.

```powershell
[DateTime]::FromFileTime(<value>)
```

Contoh:

```powershell
[DateTime]::FromFileTime(133123456789000000)
```

---

# 📂 Artefak Tambahan untuk Recovery

## 1️⃣ Event Log Task Scheduler

Periksa:

```
Microsoft-Windows-TaskScheduler/Operational
```

Event penting:

| Event ID | Arti         |
| -------- | ------------ |
| 106      | Task dibuat  |
| 140      | Task diubah  |
| 141      | Task dihapus |

```powershell

Get-WinEvent -Path .\Microsoft-Windows-TaskScheduler%4Operational.evtx |
Select TimeCreated, Id, Message


Where-Object {$_.Message -like "*TaskName*"} |
Select TimeCreated, Id, Message


Where-Object {$_.Id -in 100,101,102,200,201} |
Select TimeCreated, Id, Message
```

---

## 2️⃣ Security Event Log (jika auditing aktif)

| Event ID | Arti              |
| -------- | ----------------- |
| 4698     | Task dibuat       |
| 4699     | Task dihapus      |
| 4702     | Task dimodifikasi |

---

## 3️⃣ Volume Shadow Copy

Jika XML dihapus:

👉 Recover dari shadow copy.
