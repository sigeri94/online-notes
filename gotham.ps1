#===== initial akses
alfred (bf heapspray weakpass)
penguin (kerberoast) CIFS -- read public
bane (aseproasting - crack weakpass)
riddler (desc)
#----- privesc with pass
gordon (kdbx on folder administrator) --> dcsync
bruce (ansible enc folder public)  --> lucius (Unconstrained Delegation)
harley (ssh passprase on folder patient on hugo) --> DA
hugo (kdbx on share folder using alfred) -->winrm (local admin on arkam) --> BH
#----- turn off password complexity
#----- enable psremoting
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'

#-----
Import-Module ActiveDirectory

$domain = "gotham.local"
$baseDN = "DC=gotham,DC=local"
$ouPath = "OU=GothamLab,$baseDN"

New-ADOrganizationalUnit -Name "GothamLab" -Path $baseDN -ErrorAction SilentlyContinue

$groups = @("WayneEnterprises", "Arkham", "Rogues", "JusticeLeague")
foreach ($group in $groups) {
    New-ADGroup -Name $group -SamAccountName $group -GroupScope Global -GroupCategory Security -Path $ouPath -ErrorAction SilentlyContinue
}

$users = @(
    @{Name="alfred"; Group="WayneEnterprises"; Password="P@ssw0rd"},
    @{Name="bruce"; Group="WayneEnterprises"; Password="Bruc3Wayne!"},
    @{Name="gordon"; Group="JusticeLeague"; Password="Commiss10n3r"},
    @{Name="lucius"; Group="WayneEnterprises"; Password="P@ssw0rd2024"},
    @{Name="joker"; Group="Rogues"; Password="WhyS0Serious!"},
    @{Name="bane"; Group="Rogues"; Password="Welcome2024!"},
    @{Name="riddler"; Group="Rogues"; Password="Riddl3M3Th1s"; Description="Riddl3M3Th1s"},
    @{Name="harley"; Group="Rogues"; Password="Gotham2024!"},
    @{Name="penguin"; Group="Rogues"; Password="Penguin2024!"},
    @{Name="hugo"; Group="Arkham"; Password="Str4ngeMind!"}
)
#-- add riddler on remote management user

foreach ($user in $users) {
    $securePass = ConvertTo-SecureString $user.Password -AsPlainText -Force
    $upn = "$($user.Name)@$domain"
    $dn = "CN=$($user.Name),$ouPath"
    New-ADUser -Name $user.Name -SamAccountName $user.Name -UserPrincipalName $upn -AccountPassword $securePass -Enabled $true -Path $ouPath -PasswordNeverExpires $true
    Add-ADGroupMember -Identity $user.Group -Members $user.Name
}

#----- on arkham
net localgroup Administrators gotham\hugo /add
#----- ridller can reset hugo password
$attacker = Get-ADUser -Identity "riddler"
$sid = New-Object System.Security.Principal.SecurityIdentifier($attacker.SID)
$target = Get-ADUser -Identity "hugo"
$targetPath = "LDAP://" + $target.DistinguishedName
$entry = [ADSI]$targetPath
$acl = $entry.ObjectSecurity
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($sid, "GenericWrite", "Allow")
$acl.AddAccessRule($rule)
$entry.ObjectSecurity = $acl
$entry.CommitChanges()

#----- Kerberoast
Set-ADUser -Identity "penguin" -ServicePrincipalNames @{Add="CIFS/client01.gotham.local"}
#-- add penguin as localadmin on client01
net localgroup Administrators gotham\penguin /add
#----- AS-REP Roasting
$user = Get-ADUser bane -Properties userAccountControl
$uac = $user.userAccountControl
$newUAC = $uac -bor 4194304
Set-ADUser bane -Replace @{userAccountControl=$newUAC}

#----- ACL: bruce can GenericWrite on lucius
$attacker = Get-ADUser -Identity "bruce"
$sid = New-Object System.Security.Principal.SecurityIdentifier($attacker.SID)
$target = Get-ADUser -Identity "lucius"
$targetPath = "LDAP://" + $target.DistinguishedName
$entry = [ADSI]$targetPath
$acl = $entry.ObjectSecurity
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($sid, "GenericWrite", "Allow")
$acl.AddAccessRule($rule)
$entry.ObjectSecurity = $acl
$entry.CommitChanges()
#----- Unconstrained Delegation
Set-ADAccountControl -Identity "lucius" -TrustedForDelegation $true

#----- harley has GenericAll on Domain Admins
$da = Get-ADGroup -Identity "Domain Admins"
$ldapPath = "LDAP://" + $da.DistinguishedName
$entry = [ADSI]$ldapPath
$acl = $entry.ObjectSecurity
$harleySid = (New-Object System.Security.Principal.NTAccount("harley")).Translate([System.Security.Principal.SecurityIdentifier])
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
    $harleySid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$acl.AddAccessRule($rule)
$entry.ObjectSecurity = $acl
$entry.CommitChanges()


#----- Grant DCSync Rights to gordon on Domain Object
$domainDN = (Get-ADDomain).DistinguishedName
dsacls $domainDN /G "gordon:CA;Replicating Directory Changes" /I:S
dsacls $domainDN /G "gordon:CA;Replicating Directory Changes All" /I:S

#----- KCD
Import-Module ActiveDirectory

$sourceComputer = "arkham"
$targetComputer = "dc09"

$source = Get-ADComputer -Identity $sourceComputer
$target = Get-ADComputer -Identity $targetComputer

Set-ADComputer -Identity $sourceComputer -PrincipalsAllowedToDelegateToAccount $target.DistinguishedName

$services = @("HTTP", "CIFS")

foreach ($service in $services) {
    Set-ADComputer -Identity $sourceComputer -Add @{
        "msDS-AllowedToDelegateTo" = "TERMSRV/$targetComputer"
    }
    Write-Host "Constrained Delegation granted for service $service"
}

#----- RBCD
Import-Module ActiveDirectory

Set-ADComputer arkham$ -PrincipalsAllowedToDelegateToAccount file05$
