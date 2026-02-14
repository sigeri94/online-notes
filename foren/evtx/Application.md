```powershell

param(
    [Parameter(Mandatory=$true)]
    [string]$MountDrive
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n=== DFIR Installed Software Extraction ===`n"

$softHive = "$MountDrive`:\Windows\System32\Config\SOFTWARE"
$usersPath = "$MountDrive`:\Users"
$output = "C:\Forensic"
New-Item -ItemType Directory -Path $output -Force | Out-Null

# Load SOFTWARE hive
Write-Host "[+] Loading SOFTWARE hive..."
reg load HKLM\TempSoft $softHive | Out-Null

$results = @()

function Get-UninstallEntries($path, $source) {
    Get-ItemProperty $path | Where-Object {$_.DisplayName} | ForEach-Object {
        [PSCustomObject]@{
            Name        = $_.DisplayName
            Version     = $_.DisplayVersion
            Publisher   = $_.Publisher
            InstallDate = $_.InstallDate
            Source      = $source
        }
    }
}

Write-Host "[+] Extracting system-wide installed software..."

$results += Get-UninstallEntries "HKLM:\TempSoft\Microsoft\Windows\CurrentVersion\Uninstall\*" "System-64bit"
$results += Get-UninstallEntries "HKLM:\TempSoft\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" "System-32bit"

# Enumerate users
Write-Host "[+] Processing user profiles..."

Get-ChildItem $usersPath -Directory | ForEach-Object {

    $ntuser = "$($_.FullName)\NTUSER.DAT"
    $userName = $_.Name

    if(Test-Path $ntuser){
        Write-Host "   -> Loading hive for user: $userName"
        reg load HKU\TempUser $ntuser | Out-Null

        $results += Get-UninstallEntries "HKU:\TempUser\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" "User-$userName"

        reg unload HKU\TempUser | Out-Null
    }

    # Per-user modern apps
    $localPrograms = "$($_.FullName)\AppData\Local\Programs"
    if(Test-Path $localPrograms){
        Get-ChildItem $localPrograms -Directory | ForEach-Object {
            $results += [PSCustomObject]@{
                Name        = $_.Name
                Version     = ""
                Publisher   = ""
                InstallDate = ""
                Source      = "AppData-$userName"
            }
        }
    }
}

# Program Files inventory (portable & silent installs)
Write-Host "[+] Scanning Program Files..."

$pfPaths = @(
"$MountDrive`:\Program Files",
"$MountDrive`:\Program Files (x86)"
)

foreach($path in $pfPaths){
    if(Test-Path $path){
        Get-ChildItem $path -Directory | ForEach-Object {
            $results += [PSCustomObject]@{
                Name        = $_.Name
                Version     = ""
                Publisher   = ""
                InstallDate = ""
                Source      = "FolderInventory"
            }
        }
    }
}

# Remove duplicates & sort
$results = $results | Where-Object {$_.Name} | Sort-Object Name -Unique

# Export results
$csvPath = "$output\Installed_Programs.csv"
$results | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "`n[+] Extraction complete!"
Write-Host "[+] Output saved to: $csvPath"

# Unload hive
Write-Host "[+] Unloading registry hive..."
reg unload HKLM\TempSoft | Out-Null

Write-Host "`n=== DONE ==="

```
```powershell
param(
    [string]$EvidenceDrive = "F:",
    [string]$Output = "C:\DFIR_Services"
)

Write-Host "`n=== Service Artifact Extraction ===" -ForegroundColor Cyan

New-Item $Output -ItemType Directory -Force | Out-Null

# ----------------------------------------------------
# 1. Copy Registry Hives (Forensic Safe)
# ----------------------------------------------------
Write-Host "[+] Copying registry hives..."

Copy-Item "$EvidenceDrive\Windows\System32\Config\SYSTEM" "$Output\SYSTEM" -Force
Copy-Item "$EvidenceDrive\Windows\System32\Config\SOFTWARE" "$Output\SOFTWARE" -Force

# ----------------------------------------------------
# 2. Mount SYSTEM Hive
# ----------------------------------------------------
Write-Host "[+] Loading SYSTEM hive..."

reg load HKLM\TempSYSTEM "$Output\SYSTEM" | Out-Null

$servicesKey = "HKLM:\TempSYSTEM\ControlSet001\Services"

$services = Get-ChildItem $servicesKey

$result = foreach ($svc in $services) {

    $props = Get-ItemProperty $svc.PSPath -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        ServiceName = $svc.PSChildName
        DisplayName = $props.DisplayName
        ImagePath   = $props.ImagePath
        StartType   = $props.Start
        ServiceType = $props.Type
        ObjectName  = $props.ObjectName
    }
}

$result | Export-Csv "$Output\Services_From_Registry.csv" -NoTypeInformation

reg unload HKLM\TempSYSTEM | Out-Null

# ----------------------------------------------------
# 3. Interpret Start Type
# ----------------------------------------------------
Write-Host "[+] Translating startup types..."

Import-Csv "$Output\Services_From_Registry.csv" | ForEach-Object {

    switch ($_.StartType) {
        0 { $start="Boot" }
        1 { $start="System" }
        2 { $start="Automatic" }
        3 { $start="Manual" }
        4 { $start="Disabled" }
        default { $start="Unknown" }
    }

    $_ | Add-Member StartupMeaning $start
    $_
} | Export-Csv "$Output\Services_WithStartupType.csv" -NoTypeInformation

# ----------------------------------------------------
# 4. Extract Service Events
# ----------------------------------------------------
Write-Host "[+] Extracting service-related event logs..."

$systemLog = "$EvidenceDrive\Windows\System32\winevt\Logs\System.evtx"

$ids = 7036,7045,7000,7001,7009,7011

Get-WinEvent -Path $systemLog -ErrorAction SilentlyContinue |
Where-Object { $ids -contains $_.Id } |
Select TimeCreated, Id,
@{n="Service";e={$_.Properties[0].Value}},
@{n="Details";e={$_.Message}} |
Export-Csv "$Output\Service_Events.csv" -NoTypeInformation

# ----------------------------------------------------
# 5. Identify Suspicious Service Paths
# ----------------------------------------------------
Write-Host "[+] Flagging suspicious service binaries..."

Import-Csv "$Output\Services_WithStartupType.csv" |
Where-Object {
    $_.ImagePath -match "Users|Temp|AppData|ProgramData"
} |
Export-Csv "$Output\Suspicious_Service_Paths.csv" -NoTypeInformation

Write-Host "`n=== Completed ===" -ForegroundColor Green
Write-Host "Output: $Output"

```

```powershell

param(
    [string]$EvidenceDrive="F:",
    [string]$Output="C:\DFIR_Defender"
)

Write-Host "`n=== Defender & Firewall Analysis ===" -ForegroundColor Cyan
New-Item $Output -ItemType Directory -Force | Out-Null

# --------------------------------------------------
# 1. Copy Registry Hives
# --------------------------------------------------
Write-Host "[+] Copying registry hives..."

Copy-Item "$EvidenceDrive\Windows\System32\Config\SOFTWARE" "$Output\SOFTWARE" -Force
Copy-Item "$EvidenceDrive\Windows\System32\Config\SYSTEM" "$Output\SYSTEM" -Force

# --------------------------------------------------
# 2. Load Hives
# --------------------------------------------------
reg load HKLM\TempSOFTWARE "$Output\SOFTWARE" | Out-Null
reg load HKLM\TempSYSTEM "$Output\SYSTEM" | Out-Null

# --------------------------------------------------
# 3. Defender Status & Settings
# --------------------------------------------------
Write-Host "[+] Extracting Defender configuration..."

$defKey="HKLM:\TempSOFTWARE\Microsoft\Windows Defender"

Get-ItemProperty $defKey -ErrorAction SilentyContinue |
Select DisableAntiSpyware,DisableAntiVirus,ServiceStartStates |
Export-Csv "$Output\Defender_Status.csv" -NoTypeInformation

# Real-time protection
Get-ItemProperty "$defKey\Real-Time Protection" -ErrorAction SilentlyContinue |
Export-Csv "$Output\RealtimeProtection.csv" -NoTypeInformation

# --------------------------------------------------
# 4. Defender Exclusions (CRITICAL)
# --------------------------------------------------
Write-Host "[+] Extracting Defender exclusions..."

$exclusions="HKLM:\TempSOFTWARE\Microsoft\Windows Defender\Exclusions"

$paths = Get-ItemProperty "$exclusions\Paths" -ErrorAction SilentlyContinue
$ext   = Get-ItemProperty "$exclusions\Extensions" -ErrorAction SilentlyContinue
$proc  = Get-ItemProperty "$exclusions\Processes" -ErrorAction SilentlyContinue

$paths | Export-Csv "$Output\Exclusions_Paths.csv" -NoTypeInformation
$ext   | Export-Csv "$Output\Exclusions_Extensions.csv" -NoTypeInformation
$proc  | Export-Csv "$Output\Exclusions_Processes.csv" -NoTypeInformation

# --------------------------------------------------
# 5. Firewall Profile Status
# --------------------------------------------------
Write-Host "[+] Extracting firewall profile status..."

$fwBase="HKLM:\TempSYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"

$profiles="DomainProfile","PublicProfile","StandardProfile"

foreach($p in $profiles){
    Get-ItemProperty "$fwBase\$p" -ErrorAction SilentlyContinue |
    Select EnableFirewall,DefaultInboundAction,DefaultOutboundAction |
    Export-Csv "$Output\Firewall_${p}.csv" -NoTypeInformation
}

# --------------------------------------------------
# 6. Firewall Rules
# --------------------------------------------------
Write-Host "[+] Extracting firewall rules..."

$rulesKey="$fwBase\FirewallRules"

Get-ItemProperty $rulesKey |
Select * |
Export-Csv "$Output\FirewallRules_Raw.csv" -NoTypeInformation

# --------------------------------------------------
# 7. Copy Firewall Log
# --------------------------------------------------
Write-Host "[+] Copying firewall log..."

$fwlog="$EvidenceDrive\Windows\System32\LogFiles\Firewall\pfirewall.log"

if(Test-Path $fwlog){
    Copy-Item $fwlog "$Output\pfirewall.log"
}

# --------------------------------------------------
# 8. Defender Operational Log
# --------------------------------------------------
Write-Host "[+] Extracting Defender events..."

$defLog="$EvidenceDrive\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"

if(Test-Path $defLog){
    Get-WinEvent -Path $defLog -ErrorAction SilentlyContinue |
    Select TimeCreated,Id,LevelDisplayName,Message |
    Export-Csv "$Output\DefenderEvents.csv" -NoTypeInformation
}

# --------------------------------------------------
# Cleanup
# --------------------------------------------------
reg unload HKLM\TempSOFTWARE | Out-Null
reg unload HKLM\TempSYSTEM | Out-Null

Write-Host "`n=== Completed ===" -ForegroundColor Green
Write-Host "Output: $Output"

```
