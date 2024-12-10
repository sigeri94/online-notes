# Enable Admin$ share and configure the server for PsExec

# Function to log information to the console
function Log-Info {
    param (
        [string]$Message
    )
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

# Ensure the Server service is running
Log-Info "Ensuring the Server service is running..."
Set-Service -Name LanmanServer -StartupType Automatic
Start-Service -Name LanmanServer

# Ensure the Workstation service is running
Log-Info "Ensuring the Workstation service is running..."
Set-Service -Name LanmanWorkstation -StartupType Automatic
Start-Service -Name LanmanWorkstation

# Check and enable the Admin$ share
Log-Info "Checking if the Admin$ share is enabled..."
$shares = Get-SmbShare | Where-Object { $_.Name -eq "Admin$" }
if (-not $shares) {
    Log-Info "Admin$ share is not found. Enabling it..."
    New-SmbShare -Name "Admin$" -Path "C:\Windows" -FullAccess "Administrators"
} else {
    Log-Info "Admin$ share is already enabled."
}

# Configure registry settings for AutoShareServer
Log-Info "Configuring registry settings for AutoShareServer..."
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$autoShareValue = Get-ItemProperty -Path $registryPath -Name AutoShareServer -ErrorAction SilentlyContinue
if (-not $autoShareValue) {
    Log-Info "Setting AutoShareServer registry value..."
    New-ItemProperty -Path $registryPath -Name AutoShareServer -Value 1 -PropertyType DWORD -Force
} else {
    Log-Info "AutoShareServer registry value already configured."
}

# Restart the Server service to apply changes
Log-Info "Restarting the Server service to apply changes..."
Restart-Service -Name LanmanServer

# Ensure firewall rules for File and Printer Sharing are enabled
Log-Info "Ensuring firewall rules for File and Printer Sharing are enabled..."
$firewallRules = @("File and Printer Sharing (SMB-In)", "File and Printer Sharing (NB-Session-In)")
foreach ($rule in $firewallRules) {
    Get-NetFirewallRule -DisplayName $rule | Set-NetFirewallRule -Enabled True
}

Log-Info "Configuration complete. Admin$ share is enabled, and the server is ready for PsExec."
