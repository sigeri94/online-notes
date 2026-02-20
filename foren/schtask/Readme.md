# script parsing evtx task scheduler

```powershell
$tasksPath = "C:\Windows\System32\Tasks"
$results = @()

Get-ChildItem -Path $tasksPath -Recurse -File | ForEach-Object {

    try {
        [xml]$xml = Get-Content $_.FullName -ErrorAction Stop

        # Namespace handling
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")

        # Creation date
        $created = $xml.SelectSingleNode("//t:RegistrationInfo/t:Date", $ns)
        if (-not $created) { return }

        $createdDate = [datetime]$created.InnerText
        if ($createdDate.Year -ne 2025) { return }

        # Author / User
        $author = $xml.SelectSingleNode("//t:RegistrationInfo/t:Author", $ns)
        if (-not $author) {
            $author = $xml.SelectSingleNode("//t:Principals/t:Principal/t:UserId", $ns)
        }

        # Action
        $exec = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Command", $ns)
        $args = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Arguments", $ns)

        $results += [PSCustomObject]@{
            TaskName     = $_.FullName.Replace($tasksPath + "\", "")
            CreatedDate = $createdDate
            User        = $author.InnerText
            Action      = $exec.InnerText
            Arguments   = if ($args) { $args.InnerText } else { "" }
        }

    } catch {
        # Skip unreadable or malformed XML
    }
}

$results | Sort-Object CreatedDate | Format-Table -AutoSize
```


```powershell
$tasksPath = "C:\Windows\System32\Tasks"
$outputXlsx = "$PWD\ScheduledTasks_2025.xlsx"
$results = @()

Get-ChildItem -Path $tasksPath -Recurse -File | ForEach-Object {

    try {
        [xml]$xml = Get-Content $_.FullName -ErrorAction Stop

        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")

        # Created date
        $createdNode = $xml.SelectSingleNode("//t:RegistrationInfo/t:Date", $ns)
        if (-not $createdNode) { return }

        $createdDate = [datetime]$createdNode.InnerText
        if ($createdDate.Year -ne 2025) { return }

        # User
        $authorNode = $xml.SelectSingleNode("//t:RegistrationInfo/t:Author", $ns)
        if (-not $authorNode) {
            $authorNode = $xml.SelectSingleNode("//t:Principals/t:Principal/t:UserId", $ns)
        }

        # Action
        $execNode = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Command", $ns)
        $argsNode = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Arguments", $ns)

        # Last Run
        $lastRunNode = $xml.SelectSingleNode("//t:LastRunTime", $ns)
        $lastRunTime = if ($lastRunNode -and $lastRunNode.InnerText) {
            [datetime]$lastRunNode.InnerText
        } else {
            $null
        }

        $results += [PSCustomObject]@{
            TaskName     = $_.FullName.Replace($tasksPath + "\", "")
            CreatedDate = $createdDate
            LastRunTime = $lastRunTime
            User        = if ($authorNode) { $authorNode.InnerText } else { "Unknown" }
            Action      = if ($execNode) { $execNode.InnerText } else { "" }
            Arguments   = if ($argsNode) { $argsNode.InnerText } else { "" }
        }

    } catch {
        # Skip bad XML
    }
}

# ===== Export to Excel =====
$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$workbook = $excel.Workbooks.Add()
$sheet = $workbook.Worksheets.Item(1)
$sheet.Name = "ScheduledTasks_2025"

# Header
$headers = $results[0].PSObject.Properties.Name
for ($i = 0; $i -lt $headers.Count; $i++) {
    $sheet.Cells.Item(1, $i + 1) = $headers[$i]
    $sheet.Cells.Item(1, $i + 1).Font.Bold = $true
}

# Data
$row = 2
foreach ($r in $results) {
    $col = 1
    foreach ($h in $headers) {
        $sheet.Cells.Item($row, $col) = $r.$h
        $col++
    }
    $row++
}

# Auto-fit columns
$sheet.Columns.AutoFit()

# Save
$workbook.SaveAs($outputXlsx)
$workbook.Close($true)
$excel.Quit()

[System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null

Write-Host "Excel exported to: $outputXlsx"

```

# script memparsing isi folder tasks

```powershell
Get-ChildItem "F:\windows\system32\tasks" -Recurse -File -Force -ErrorAction SilentlyContinue |
Select-Object FullName, CreationTime, LastWriteTime, Length |
Sort-Object CreationTime
```

---

```powershell
# Folder Task Scheduler
$taskFolder = "F:\Windows\System32\Tasks"

# Ambil semua file di folder (rekursif jika ada subfolder)
$taskFiles = Get-ChildItem -Path $taskFolder -File -Recurse

# Array untuk menyimpan hasil
$results = @()

foreach ($file in $taskFiles) {
    try {
        # Load XML
        [xml]$xml = Get-Content -Path $file.FullName -Encoding UTF8 -ErrorAction Stop

        # Default values
        $triggerTime = "N/A"
        $actionCommand = "N/A"
        $actionArgs = ""

        # Cek Trigger
        if ($xml.Task.Triggers.TimeTrigger) {
            $triggerTime = $xml.Task.Triggers.TimeTrigger.StartBoundary
        }
        elseif ($xml.Task.Triggers.BootTrigger) {
            $triggerTime = "At Boot"
        }
        elseif ($xml.Task.Triggers.LogonTrigger) {
            $triggerTime = "At Logon"
        }
        elseif ($xml.Task.Triggers.DailyTrigger) {
            $triggerTime = $xml.Task.Triggers.DailyTrigger.StartBoundary
        }

        # Cek Action
        if ($xml.Task.Actions.Exec) {
            $actionCommand = $xml.Task.Actions.Exec.Command
            $actionArgs = $xml.Task.Actions.Exec.Arguments
        }

        # Simpan hasil
        $results += [PSCustomObject]@{
            File       = $file.FullName
            Trigger    = $triggerTime
            Command    = $actionCommand
            Arguments  = $actionArgs
        }
    }
    catch {
        Write-Warning "Gagal membaca $($file.FullName): $_"
    }
}

# Tampilkan hasil
$results | Format-Table -AutoSize

# Opsional: simpan ke CSV
$results | Export-Csv -Path "C:\foren\tasks_summary.csv" -NoTypeInformation -Encoding UTF8
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
