function Get-OSRegistryInfo {

    $osReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    Write-Host "`n=== OS version Check ===" -ForegroundColor Cyan

    try {
        $item = Get-ItemProperty -Path $osReg -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to read registry path: $osReg"
        return
    }

    $info = [PSCustomObject]@{
        ProductName      = $item.ProductName
        EditionID        = $item.EditionID
        ReleaseId        = $item.ReleaseId
        DisplayVersion   = $item.DisplayVersion
        CurrentBuild     = $item.CurrentBuild
        UBR              = $item.UBR
        InstallDateUnix  = $item.InstallDate
    }

    # Convert InstallDate to human-readable
    if ($info.InstallDateUnix) {
        $info | Add-Member -NotePropertyName InstallDate `
                           -NotePropertyValue ([DateTimeOffset]::FromUnixTimeSeconds($info.InstallDateUnix).DateTime)
    }

    return $info
}

function Get-DefenderSimple {

    # 1. Cek service Windows Defender
    $svc = Get-Service WinDefend -ErrorAction SilentlyContinue
    if ($svc.Status -eq 'Running') { $defender = "Enabled" } else { $defender = "Disabled" }

    # 2. Real-time protection flag (0 = enabled, 1 = disabled)
    $rtpPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
    if (Test-Path $rtpPath) {
        $rtp = Get-ItemProperty $rtpPath
        $RTPState = if ($rtp.DisableRealtimeMonitoring -eq 1) { "Disabled" } else { "Enabled" }
    } else { $RTPState = "Unknown" }

    # 3. Cloud / MAPS
    $cloudPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet"
    if (Test-Path $cloudPath) {
        $cloud = Get-ItemProperty $cloudPath
        $CloudState = if ($cloud.SpynetReporting -gt 0) { "Enabled" } else { "Disabled" }
    } else { $CloudState = "Unknown" }

    # 4. Automatic sample submission
    if (Test-Path $cloudPath) {
        $SubmitState = if ($cloud.SubmitSamplesConsent -eq 1 -or $cloud.SubmitSamplesConsent -eq 2) { "Enabled" } else { "Disabled" }
    } else { $SubmitState = "Unknown" }

    # --- OUTPUT ---
    Write-Host "`n=== Windows Defender Status Summary ===" -ForegroundColor Cyan
    Write-Host "Defender Service        : $defender"
    Write-Host "Real-Time Protection    : $RTPState"
    Write-Host "Cloud / MAPS            : $CloudState"
    Write-Host "Sample Submission       : $SubmitState"
}

function Get-AppLockerStatus {

    # Lokasi registry AppLocker
    $alPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

    Write-Host "`n=== AppLocker Status Summary ===" -ForegroundColor Cyan

    # Jika AppLocker tidak diatur
    if (-not (Test-Path $alPath)) {
        Write-Host "AppLocker                : Disabled (No Policy Found)"
        return
    }

    Write-Host "AppLocker                : Enabled (Policy Found)"

    # List rule collections
    $collections = @{
        "EXE Rules"    = "Exe"
        "Script Rules" = "Script"
        "MSI Rules"    = "Msi"
        "DLL Rules"    = "Dll"
        "AppX Rules"   = "Appx"
    }

    foreach ($item in $collections.GetEnumerator()) {

        $path = Join-Path $alPath $item.Value

        if (Test-Path $path) {
            $props = Get-ItemProperty $path

            $mode = $props.EnforcementMode

            switch ($mode) {
                0 { $state = "Not Configured" }
                1 { $state = "Audit Mode" }
                2 { $state = "Enforced" }
                default { $state = "Unknown ($mode)" }
            }

            Write-Host ("{0,-22}: {1}" -f $item.Key, $state)

        } else {
            Write-Host ("{0,-22}: Disabled" -f $item.Key)
        }
    }
}

function Get-ConstrainedLanguage {

    Write-Host "`n=== Constrained Language Mode Check ===" -ForegroundColor Cyan

    try {
        $mode = $ExecutionContext.SessionState.LanguageMode
        if ($mode -eq "ConstrainedLanguage") {
            Write-Host "Constrained Language Mode : Enabled"
        }
        else {
            Write-Host "Constrained Language Mode : Disabled"
        }
    }
    catch {
        Write-Host "Constrained Language Mode : Unknown (Error Reading Mode)"
    }
}

Get-OSRegistryInfo
Get-ConstrainedLanguage
Get-AppLockerStatus
Get-DefenderSimple
