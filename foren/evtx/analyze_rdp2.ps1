
param (
    [Parameter(Mandatory=$true)]
    [string]$SecurityEvtx
)

# ==============================
# Validation
# ==============================
if (!(Test-Path $SecurityEvtx)) {
    Write-Error "Security.evtx not found: $SecurityEvtx"
    exit 1
}

Write-Host "Analyzing APP SERVER Security.evtx" -ForegroundColor Cyan
Write-Host "File: $SecurityEvtx`n"

# ==============================
# Event IDs of Interest
# ==============================
$TargetIDs = 4624,4672,4634,4648,4776,5379

# ==============================
# Parse EVTX
# ==============================
$Events = try {
    Get-WinEvent -FilterHashtable @{
        Path = $SecurityEvtx
        Id   = $TargetIDs
    } -ErrorAction Stop
}
catch {
    Write-Error "Failed to parse EVTX"
    exit 1
}

# ==============================
# Normalize Events
# ==============================
$Parsed = foreach ($e in $Events) {

    switch ($e.Id) {

        # -------- LOGON SUCCESS --------
        4624 {
            [PSCustomObject]@{
                TimeCreated   = $e.TimeCreated
                EventID       = 4624
                EventType     = "Logon Success"
                User          = "$($e.Properties[5].Value)\$($e.Properties[6].Value)"
                LogonType     = $e.Properties[8].Value
                LogonTypeName = switch ($e.Properties[8].Value) {
                    2  { "Interactive" }
                    3  { "Network" }
                    5  { "Service" }
                    10 { "RDP" }
                    default { "Other" }
                }
                SourceIP      = $e.Properties[18].Value
                Workstation   = $e.Properties[11].Value
                AuthPackage   = $e.Properties[10].Value
                Elevated      = $false
            }
        }

        # -------- ADMIN PRIVILEGES --------
        4672 {
            [PSCustomObject]@{
                TimeCreated   = $e.TimeCreated
                EventID       = 4672
                EventType     = "Admin Logon"
                User          = "$($e.Properties[1].Value)\$($e.Properties[2].Value)"
            }
        }

        # -------- LOGOFF --------
        4634 {
            [PSCustomObject]@{
                TimeCreated   = $e.TimeCreated
                EventID       = 4634
                EventType     = "Logoff"
                User          = "$($e.Properties[1].Value)\$($e.Properties[2].Value)"
            }
        }

        # -------- EXPLICIT CREDENTIALS --------
        4648 {
            [PSCustomObject]@{
                TimeCreated   = $e.TimeCreated
                EventID       = 4648
                EventType     = "Explicit Credentials"
                SubjectUser   = "$($e.Properties[1].Value)\$($e.Properties[2].Value)"
                TargetUser    = "$($e.Properties[5].Value)\$($e.Properties[6].Value)"
                TargetServer  = $e.Properties[8].Value
            }
        }

        # -------- NTLM --------
        4776 {
            [PSCustomObject]@{
                TimeCreated   = $e.TimeCreated
                EventID       = 4776
                EventType     = "NTLM Authentication"
                User          = $e.Properties[1].Value
                Workstation   = $e.Properties[2].Value
                Status        = $e.Properties[3].Value
            }
        }

        # -------- CREDENTIAL MANAGER --------
        5379 {
            [PSCustomObject]@{
                TimeCreated   = $e.TimeCreated
                EventID       = 5379
                EventType     = "Credential Manager Read"
                User          = "$($e.Properties[1].Value)\$($e.Properties[2].Value)"
                Target        = $e.Properties[4].Value
            }
        }
    }
}

# ==============================
# Correlate Admin Logons
# ==============================
$AdminUsers = ($Parsed | Where-Object EventID -eq 4672).User | Sort-Object -Unique

$Parsed | Where-Object { $_.EventID -eq 4624 -and $AdminUsers -contains $_.User } |
    ForEach-Object { $_.Elevated = $true }

# ==============================
# Output Files
# ==============================
$Base = Split-Path $SecurityEvtx
$TimelinePath = Join-Path $Base "AppServer_Security_Timeline.csv"
$FindingsPath = Join-Path $Base "AppServer_Findings.txt"

$Parsed |
    Sort-Object TimeCreated |
    Export-Csv $TimelinePath -NoTypeInformation

# ==============================
# Findings
# ==============================
$Findings = @()

# RDP on app server
$RDP = $Parsed | Where-Object { $_.LogonTypeName -eq "RDP" }
if ($RDP) {
    $Findings += "RDP LOGONS DETECTED (Suspicious on app servers): $($RDP.Count)"
}

# Admin interactive usage
$AdminInteractive = $Parsed |
    Where-Object { $_.Elevated -eq $true -and $_.LogonTypeName -in "Interactive","RDP" }
if ($AdminInteractive) {
    $Findings += "ADMIN INTERACTIVE LOGONS: $($AdminInteractive.Count)"
}

# Explicit credentials
$CredReuse = $Parsed |
    Where-Object { $_.EventID -eq 4648 -and $_.SubjectUser -ne $_.TargetUser }
if ($CredReuse) {
    $Findings += "CREDENTIAL REUSE EVENTS (4648): $($CredReuse.Count)"
}

# NTLM usage
$NTLM = $Parsed | Where-Object EventID -eq 4776
if ($NTLM) {
    $Findings += "NTLM AUTHENTICATION EVENTS: $($NTLM.Count)"
}

$Findings | Out-File $FindingsPath

# ==============================
# Console Summary
# ==============================
Write-Host "`nAnalysis Complete" -ForegroundColor Green
Write-Host "Timeline : $TimelinePath"
Write-Host "Findings : $FindingsPath"

Write-Host "`nHIGH RISK EVENTS:" -ForegroundColor Red
$Parsed |
    Where-Object {
        $_.LogonTypeName -eq "RDP" -or
        $_.EventType -eq "Explicit Credentials" -or
        $_.EventType -eq "Credential Manager Read"
    } |
    Sort-Object TimeCreated -Descending |
    Select-Object -First 20 |
    Format-Table -AutoSize
