```powershell
Get-ChildItem "F:\windows\system32\tasks" -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime, Length | Sort-Object CreationTime
```
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

## 1. Legitimate Software Activity

### Adobe

-   AdobeARM.exe → Auto update Adobe Reader

### Microsoft Office 2013

-   MsoSync.exe
-   OLicenseHeartbeat.exe
-   msoia.exe (scan upload)

### Microsoft Edge

-   MicrosoftEdgeUpdate.exe /c
-   MicrosoftEdgeUpdate.exe /ua /installsource scheduler

### Mozilla Firefox

-   firefox.exe --backgroundtask backgroundupdate
-   default-browser-agent.exe do-task

### Zoom

-   Zoom.exe (user execution)

------------------------------------------------------------------------

## 2. Windows Update & Maintenance

### Windows Update Orchestrator

-   usoclient.exe StartDownload
-   usoclient.exe StartInstall
-   usoclient.exe StartScan
-   MusNotification.exe Display / RebootDialog

### Disk & System Maintenance

-   defrag.exe
-   cleanmgr.exe
-   srtasks.exe
-   dmclient.exe
-   devicecensus.exe

Semua terlihat sebagai scheduled maintenance normal.

------------------------------------------------------------------------

## 3. Rundll32 Usage Review

Semua pemanggilan rundll32 memanggil DLL resmi dari: -
%windir%`\system32`{=tex}

Contoh: - Startupscan.dll,SusRunTask -
AppxDeploymentClient.dll,AppxPreStageCleanupRunTask -
sysmain.dll,PfSvWsSwapAssessmentTask -
bfe.dll,BfeOnServiceStartTypeChange

Tidak ditemukan indikasi pemanggilan DLL dari folder temp atau network
path.

------------------------------------------------------------------------

## 4. Service Control (sc.exe)

Contoh: - sc.exe start w32time - sc.exe start wuauserv - sc.exe config
upnphost start= auto

Tidak ditemukan create service baru atau service mencurigakan.

------------------------------------------------------------------------

## 5. Items Requiring Validation

### SentinelOne Uninstall

Sentinel Agent uninstall.exe /os_upgrade /q /p {GUID}

Kemungkinan: - Agent upgrade - OS upgrade compatibility action

Perlu verifikasi change management jika tidak dalam maintenance window.

### Network Share Script

\\svr000ad02`\Installer `{=tex}S1`\Log `{=tex}Print Script.bat

Perlu verifikasi: - Parent process - User context - Isi script - Hash
file

### Shutdown Execution

shutdown.exe /r /f

Kemungkinan restart akibat Windows Update.

------------------------------------------------------------------------

## Overall Risk Assessment

  Category                Assessment
  ----------------------- -----------------
  Software Updater        Normal
  Windows Maintenance     Normal
  Rundll32 Usage          Legitimate
  Service Control         Legitimate
  SentinelOne Uninstall   Review Required
  Network Share Script    Review Required

------------------------------------------------------------------------
