

# Internet Explorer Artifact Collection (Mounted E01)

## Overview

This workflow provides a **forensically sound method** to extract and analyze Internet Explorer artifacts from a mounted E01 forensic image.

✔ Designed for read-only mounted evidence
✔ Copies artifacts before parsing
✔ Generates CSV outputs for timeline analysis
✔ Supports multi-user environments

---

## Requirements

### 1. Mount Evidence (Read-Only)

Example:

```
F:\
```

### 2. Required Tool

Download:

**ESEDatabaseView**

```
https://www.nirsoft.net/utils/ese_database_view.html
```

Place at:

```
C:\Tools\ESEDatabaseView.exe
```

---

## Artifacts Collected

### Browser History

Stored in:

```
WebCacheV01.dat
```

### Cookies & Sessions

Stored in:

* WebCache database
* Legacy cookie folders

### Download Records

Stored in WebCache database containers

### Browser Cache

```
INetCache\
```

### Stored Credentials (Artifacts Only)

```
Vault\
```

---

## All-in-One PowerShell Script

Save as:

```
IE_Artifact_Collector.ps1
```

### Script

```powershell
<#
IE Artifact Collector (DFIR Safe)
#>

param(
    [string]$EvidenceDrive = "F:",
    [string]$OutputRoot = "C:\DFIR_IE_Output",
    [string]$ESETool = "C:\Tools\ESEDatabaseView.exe"
)

Write-Host "`n=== IE Artifact Collector Started ===" -ForegroundColor Cyan

$dirs = @(
    "$OutputRoot",
    "$OutputRoot\WebCache",
    "$OutputRoot\CacheFiles",
    "$OutputRoot\Vault",
    "$OutputRoot\Reports"
)

foreach ($d in $dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

Write-Host "`n[+] Searching for WebCache databases..."
$webCaches = Get-ChildItem "$EvidenceDrive\Users" -Recurse -Filter WebCacheV01.dat -ErrorAction SilentlyContinue

foreach ($db in $webCaches) {
    $safeName = $db.FullName -replace "[:\\]", "_"
    Copy-Item $db.FullName "$OutputRoot\WebCache\$safeName" -Force
}

if (Test-Path $ESETool) {
    Write-Host "[+] Parsing WebCache..."
    foreach ($db in Get-ChildItem "$OutputRoot\WebCache" -Filter *.dat) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($db)
        & $ESETool /table Containers $db.FullName /scomma "$OutputRoot\Reports\${base}_Containers.csv"

        foreach ($id in 1..50) {
            & $ESETool /table "Container_$id" $db.FullName /scomma "$OutputRoot\Reports\${base}_Container_$id.csv" 2>$null
        }
    }
}

Write-Host "[+] Collecting cache files..."
$cacheDirs = Get-ChildItem "$EvidenceDrive\Users" -Recurse -Directory -Filter INetCache -ErrorAction SilentlyContinue
foreach ($dir in $cacheDirs) {
    robocopy $dir.FullName "$OutputRoot\CacheFiles" /E /R:0 /W:0 /NFL /NDL | Out-Null
}

Get-ChildItem "$OutputRoot\CacheFiles" -Recurse -File |
Select FullName, Length, CreationTime, LastWriteTime |
Export-Csv "$OutputRoot\Reports\CacheInventory.csv" -NoTypeInformation

Write-Host "[+] Finding legacy cookies..."
Get-ChildItem "$EvidenceDrive\Users" -Recurse -Include Cookies,INetCookies -ErrorAction SilentlyContinue |
Select FullName |
Export-Csv "$OutputRoot\Reports\LegacyCookieLocations.csv" -NoTypeInformation

Write-Host "[+] Collecting credential vaults..."
$vaultDirs = Get-ChildItem "$EvidenceDrive\Users" -Recurse -Directory -Include Vault -ErrorAction SilentlyContinue
foreach ($v in $vaultDirs) {
    robocopy $v.FullName "$OutputRoot\Vault" /E /R:0 /W:0 /NFL /NDL | Out-Null
}

Write-Host "[+] Enumerating downloads..."
$downloads = Get-ChildItem "$EvidenceDrive\Users" -Recurse -Directory -Filter Downloads -ErrorAction SilentlyContinue
foreach ($d in $downloads) {
    Get-ChildItem $d.FullName -File -Recurse |
    Select FullName, Length, CreationTime, LastWriteTime |
    Export-Csv "$OutputRoot\Reports\Downloads_$((Get-Random)).csv" -NoTypeInformation
}

Write-Host "[+] Building unified timeline..."
Get-ChildItem "$OutputRoot\Reports" -Filter *.csv |
ForEach-Object { Import-Csv $_ } |
Export-Csv "$OutputRoot\Reports\Unified_Timeline.csv" -NoTypeInformation

Write-Host "`n=== Completed ==="
Write-Host "Output: $OutputRoot"
```

---

## How to Run

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\IE_Artifact_Collector.ps1 -EvidenceDrive F:
```

---

## Output Structure

```
C:\DFIR_IE_Output\
 ├── WebCache\
 ├── CacheFiles\
 ├── Vault\
 └── Reports\
      *_Containers.csv
      *_Container_#.csv
      CacheInventory.csv
      LegacyCookieLocations.csv
      Downloads_*.csv
      Unified_Timeline.csv
```

---

## How to Interpret Results

### History Containers

Look for:

* visited URLs
* search queries
* timestamps

### Cookies

Identify:

* session tokens
* login persistence
* tracking identifiers

### Downloads

Check:

* executable downloads
* unusual file names
* suspicious domains

### Cache Files

May contain:

* malicious scripts
* phishing assets
* payload remnants

---

