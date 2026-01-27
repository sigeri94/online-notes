<# ===============================
 OFFLINE AD PRIVILEGE ANALYSIS
 From NTDS + SYSVOL (E01 image)
 =============================== #>

# ========= CONFIGURATION =========
$NTDSGroupsFile      = "C:\Forensics\AD\ntds_groups.txt"
$NTDSMembershipFile  = "C:\Forensics\AD\ntds_group_membership.txt"
$SYSVOLPath          = "C:\Forensics\AD\SYSVOL"

# Output
$OutputDir           = "C:\Forensics\AD\Analysis"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# ========= PRIVILEGED GROUPS =========
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators"
)

# ========= LOAD DATA =========
$Groups       = Get-Content $NTDSGroupsFile
$Memberships  = Get-Content $NTDSMembershipFile

# ========= DOMAIN POWERFUL USERS =========
$DomainPrivUsers = foreach ($group in $PrivilegedGroups) {
    $Memberships |
        Select-String -Pattern "^$group\s*:" |
        ForEach-Object {
            $_.Line -replace "^$group\s*:\s*", "" |
            Split-String "," |
            ForEach-Object {
                [PSCustomObject]@{
                    PrivilegeGroup = $group
                    User           = $_.Trim()
                }
            }
        }
}

$DomainPrivUsers |
    Sort PrivilegeGroup, User |
    Export-Csv "$OutputDir\Domain_Powerful_Users.csv" -NoTypeInformation

# ========= LOCAL ADMIN VIA GPO =========
$LocalAdminFindings = @()

$GptFiles = Get-ChildItem -Path $SYSVOLPath -Recurse -Filter "GptTmpl.inf" -ErrorAction SilentlyContinue

foreach ($file in $GptFiles) {
    $content = Get-Content $file.FullName

    if ($content -match "S-1-5-32-544") {
        $PolicyGUID = ($file.FullName -split "\\") | Where-Object { $_ -match "^\{.*\}$" }

        $Members = $content |
            Select-String "S-1-5-32-544__Members" -Context 0,5 |
            ForEach-Object { $_.Context.PostContext } |
            Where-Object { $_ -match "=" } |
            ForEach-Object { $_ -replace ".*=", "" } |
            ForEach-Object { $_.Trim() }

        foreach ($member in $Members) {
            $LocalAdminFindings += [PSCustomObject]@{
                PolicyGUID   = $PolicyGUID
                LocalAdmin   = $member
                SourceFile   = $file.FullName
            }
        }
    }
}

$LocalAdminFindings |
    Sort LocalAdmin |
    Export-Csv "$OutputDir\Local_Admins_via_GPO.csv" -NoTypeInformation

# ========= SUMMARY =========
Write-Host "Analysis complete"
Write-Host "-----------------"
Write-Host "Domain privileged users : $($DomainPrivUsers.Count)"
Write-Host "Local admin assignments : $($LocalAdminFindings.Count)"
Write-Host "Output directory        : $OutputDir"
