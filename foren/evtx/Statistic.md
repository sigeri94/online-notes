```powershell
# ==========================================
# DAILY EVENT COUNT BY EVENT ID
# ==========================================

$logPath = "D:\Logs\Security.evtx"

Write-Host "Reading Security log..." -ForegroundColor Cyan
$events = Get-WinEvent -Path $logPath -ErrorAction SilentlyContinue

Write-Host "Processing statistics..." -ForegroundColor Yellow

$dailyStats = $events | ForEach-Object {
    [PSCustomObject]@{
        Date    = $_.TimeCreated.ToString("yyyy-MM-dd")
        EventID = $_.Id
    }
} | Group-Object Date, EventID | ForEach-Object {

    $date,$id = $_.Name -split ", "

    [PSCustomObject]@{
        Date     = $date
        EventID  = $id
        Count    = $_.Count
    }
}

$dailyStats |
Sort-Object Date, Count -Descending |
Format-Table -AutoSize
```

```powershell
# ==========================================
# DAILY APPLICATION LOG STATS BY PROVIDER
# ==========================================

$logPath = "D:\Logs\Application.evtx"

Write-Host "Reading Application log..." -ForegroundColor Cyan
$events = Get-WinEvent -Path $logPath -ErrorAction SilentlyContinue

Write-Host "Processing statistics..." -ForegroundColor Yellow

$dailyStats = $events | ForEach-Object {
    [PSCustomObject]@{
        Date      = $_.TimeCreated.ToString("yyyy-MM-dd")
        Provider  = $_.ProviderName
    }
} | Group-Object Date, Provider | ForEach-Object {

    $date,$provider = $_.Name -split ", ",2

    [PSCustomObject]@{
        Date      = $date
        Provider  = $provider
        Count     = $_.Count
    }
}

$dailyStats |
Sort-Object Date, Count -Descending |
Format-Table -AutoSize
```

```powershell
# ==========================================
# DAILY SYSTEM LOG STATS BY PROVIDER
# ==========================================

$logPath = "D:\Logs\System.evtx"

Write-Host "Reading System log..." -ForegroundColor Cyan
$events = Get-WinEvent -Path $logPath -ErrorAction SilentlyContinue

Write-Host "Processing statistics..." -ForegroundColor Yellow

$dailyStats = $events | ForEach-Object {
    [PSCustomObject]@{
        Date      = $_.TimeCreated.ToString("yyyy-MM-dd")
        Provider  = $_.ProviderName
    }
} | Group-Object Date, Provider | ForEach-Object {

    $date,$provider = $_.Name -split ", ",2

    [PSCustomObject]@{
        Date      = $date
        Provider  = $provider
        Count     = $_.Count
    }
}

$dailyStats |
Sort-Object Date, Count -Descending |
Format-Table -AutoSize
```
