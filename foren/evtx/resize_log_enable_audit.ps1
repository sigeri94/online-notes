# ==========================================
# Windows IR / DFIR Logging Baseline Script
# Author: DFIR-ready
# Run as Administrator
# ==========================================

# ---------------------------
# 1. Set Event Log Sizes
# ---------------------------
Write-Host "[+] Configuring Event Log sizes..."

$LogSizes = @{
    "Security"                                              = 1GB
    "System"                                                = 256MB
    "Application"                                           = 256MB
    "Microsoft-Windows-PowerShell/Operational"              = 4GB
    "Microsoft-Windows-TaskScheduler/Operational"           = 100MB
    "Microsoft-Windows-WinRM/Operational"                   = 100MB
    "Microsoft-Windows-Windows Defender/Operational"        = 100MB
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" = 100MB
    "Microsoft-Windows-WMI-Activity/Operational"            = 100MB
    "Microsoft-Windows-Bits-Client/Operational"             = 100MB
    "Microsoft-Windows-GroupPolicy/Operational"             = 100MB
}

foreach ($log in $LogSizes.Keys) {
    try {
        wevtutil sl "$log" /ms:$($LogSizes[$log])
        Write-Host "  [+] Set $log size to $($LogSizes[$log])"
    } catch {
        Write-Warning "  [!] Failed to set size for $log"
    }
}

# ---------------------------
# 2. Enable TaskScheduler Operational Log
# ---------------------------
Write-Host "[+] Enabling TaskScheduler Operational log..."
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true

# ---------------------------
# 3. Enable Advanced Audit Policies
# ---------------------------
Write-Host "[+] Enabling Advanced Audit Policies..."

$auditSettings = @(
    "Account Logon\Credential Validation",
    "Account Logon\Kerberos Service Ticket Operations",
    "Account Management\User Account Management",
    "Detailed Tracking\Process Creation",
    "Detailed Tracking\Process Termination",
    "Logon/Logoff\Logon",
    "Logon/Logoff\Logoff",
    "Logon/Logoff\Other Logon/Logoff Events",
    "Logon/Logoff\Special Logon",
    "Policy Change\Audit Policy Change",
    "Policy Change\Authentication Policy Change",
    "Policy Change\Authorization Policy Change",
    "System\Security State Change",
    "System\System Integrity"
)

foreach ($setting in $auditSettings) {
    auditpol /set /subcategory:"$setting" /success:enable /failure:enable | Out-Null
    Write-Host "  [+] Enabled audit: $setting"
}

# ---------------------------
# 4. Enable Command Line Logging (4688)
# ---------------------------
Write-Host "[+] Enabling command line logging for process creation..."

$procKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
If (!(Test-Path $procKey)) { New-Item -Path $procKey -Force | Out-Null }

Set-ItemProperty -Path $procKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# ---------------------------
# 5. PowerShell Logging
# ---------------------------
Write-Host "[+] Enabling PowerShell logging..."

$psKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
If (!(Test-Path $psKey)) { New-Item -Path $psKey -Force | Out-Null }

# Script Block Logging
New-Item -Path "$psKey\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$psKey\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord

# Module Logging
New-Item -Path "$psKey\ModuleLogging" -Force | Out-Null
New-Item -Path "$psKey\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$psKey\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty -Path "$psKey\ModuleLogging\ModuleNames" -Name "*" -Value "*" -Type String

# Transcription Logging
New-Item -Path "$psKey\Transcription" -Force | Out-Null
Set-ItemProperty -Path "$psKey\Transcription" -Name EnableTranscripting -Value 1 -Type DWord
Set-ItemProperty -Path "$psKey\Transcription" -Name OutputDirectory -Value "C:\PS_Transcripts" -Type String

# Create transcript directory
New-Item -ItemType Directory -Path "C:\PS_Transcripts" -Force | Out-Null
icacls "C:\PS_Transcripts" /inheritance:r /grant "Administrators:F" "SYSTEM:F" | Out-Null

# ---------------------------
# Finish
# ---------------------------
Write-Host "[!] Reboot recommended to ensure all policies take effect."
