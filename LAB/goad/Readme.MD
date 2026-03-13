# Security Impact & Remediation

## 1. DFSCoerce / PetitPotam / PrinterBug / MSEven (Coercion Attacks)
```powershell
└─$ nxc smb 192.168.56.11  -u hodor -p 'hodor' -M coerce_plus
/home/kali/.local/pipx/venvs/netexec/lib/python3.11/site-packages/masky/lib/smb.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import resource_filename
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\hodor:hodor
COERCE_PLUS 192.168.56.11   445    WINTERFELL       VULNERABLE, DFSCoerce
COERCE_PLUS 192.168.56.11   445    WINTERFELL       VULNERABLE, PetitPotam
COERCE_PLUS 192.168.56.11   445    WINTERFELL       VULNERABLE, PrinterBug
COERCE_PLUS 192.168.56.11   445    WINTERFELL       VULNERABLE, PrinterBug
COERCE_PLUS 192.168.56.11   445    WINTERFELL       VULNERABLE, MSEven
```
### Description

Serangan **coercion** memaksa server Windows melakukan **authentication ke attacker-controlled host** menggunakan NTLM atau Kerberos. Teknik ini sering digunakan untuk:

* NTLM relay attack
* Capture NTLM hash
* Privilege escalation
* Domain takeover

Teknik ini biasanya menargetkan layanan:

* MS-EFSRPC (PetitPotam)
* MS-DFSNM (DFSCoerce)
* Print Spooler (PrinterBug)

### Impact

Jika attacker berhasil:

* NTLM hash dari **Domain Controller atau privileged account** dapat dicuri
* NTLM relay dapat digunakan untuk:

  * LDAP relay
  * SMB relay
  * AD privilege escalation
* Potensi **Domain Admin compromise**
* Potensi **Full Active Directory takeover**

### Fix / Mitigation

Disable atau batasi layanan yang rentan:

**Disable NTLM jika memungkinkan**

```powershell
Network security: Restrict NTLM: NTLM authentication in this domain
```

**Disable Print Spooler pada Domain Controller**

```powershell
Stop-Service Spooler
Set-Service Spooler -StartupType Disabled
```

**Apply Microsoft security patches**

Pastikan Windows update terbaru sudah diinstall.

**Enable SMB signing enforcement**

```powershell
Microsoft network server: Digitally sign communications (always)
```

**Restrict RPC access**

Batasi akses RPC hanya ke trusted hosts.

---

# 2. noPac Vulnerability
```powershell
─$ nxc smb 192.168.56.11  -u hodor -p 'hodor' -M nopac
/home/kali/.local/pipx/venvs/netexec/lib/python3.11/site-packages/masky/lib/smb.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import resource_filename
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\hodor:hodor
NOPAC       192.168.56.11   445    WINTERFELL       TGT with PAC size 1582
NOPAC       192.168.56.11   445    WINTERFELL       TGT without PAC size 793
NOPAC       192.168.56.11   445    WINTERFELL
NOPAC       192.168.56.11   445    WINTERFELL       VULNERABLE
NOPAC       192.168.56.11   445    WINTERFELL       Next step: https://github.com/Ridter/noPac
```
### Description

Kerentanan **noPac** adalah kombinasi dari dua vulnerability:

* CVE-2021-42278
* CVE-2021-42287

Kerentanan ini memungkinkan attacker:

1. Mengubah nama machine account
2. Memanfaatkan kelemahan Kerberos ticket validation
3. Mendapatkan **Domain Admin privileges**

### Impact

Jika berhasil dieksploitasi:

* Privilege escalation ke **Domain Admin**
* Kerberos ticket forging
* Full Active Directory compromise
* Persistent access ke domain

### Fix / Mitigation

Install patch Microsoft berikut:

* November 2021 Security Updates
* Semua patch setelahnya sudah include fix

Periksa patch status:

```powershell
systeminfo | findstr KB5008102
```

Rekomendasi tambahan:

* Monitor perubahan **machine account**
* Audit Kerberos ticket usage
* Implement **Privileged Access Workstations**

---

# 3. PrintNightmare
```powershell
─$ nxc smb 192.168.56.11  -u hodor -p 'hodor' -M printnightmare
/home/kali/.local/pipx/venvs/netexec/lib/python3.11/site-packages/masky/lib/smb.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import resource_filename
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\hodor:hodor
PRINTNIG... 192.168.56.11   445    WINTERFELL       Vulnerable, next step https://github.com/ly4k/PrintNightmare

```
### Description

**PrintNightmare (CVE-2021-34527)** adalah kerentanan pada **Windows Print Spooler** yang memungkinkan attacker menjalankan kode secara remote.

Kerentanan ini memungkinkan:

* Remote Code Execution (RCE)
* Privilege escalation
* Arbitrary DLL loading

### Impact

Jika berhasil dieksploitasi:

* Remote execution dengan **SYSTEM privileges**
* Domain Controller compromise
* Malware deployment
* Lateral movement dalam network

### Fix / Mitigation

Install patch Microsoft terkait:

```text
KB5004945
KB5005010
```

Disable Print Spooler jika tidak dibutuhkan:

```powershell
Stop-Service Spooler
Set-Service Spooler -StartupType Disabled
```

Batasi driver installation:

```powershell
Point and Print Restrictions
```

---

# 4. Spooler Service Enabled
```powershell
-$ nxc smb 192.168.56.11  -u hodor -p 'hodor' -M spooler
/home/kali/.local/pipx/venvs/netexec/lib/python3.11/site-packages/masky/lib/smb.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  from pkg_resources import resource_filename
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\hodor:hodor
SPOOLER     192.168.56.11   445    WINTERFELL       Spooler service enabled
```
### Description

Print Spooler service memungkinkan printer management pada Windows system.

Namun pada server atau Domain Controller, service ini sering menjadi **attack surface**.

### Impact

Jika Print Spooler aktif:

* PrinterBug exploitation
* PrintNightmare exploitation
* Authentication coercion

### Fix / Mitigation

Disable service jika tidak diperlukan:

```powershell
Stop-Service Spooler
Set-Service Spooler -StartupType Disabled
```

Jika tetap diperlukan:

* Batasi printer driver installation
* Monitor spooler activity
* Enable logging

---

# 5. SMB Enumeration Exposure
```powershell
─$ nxc smb 192.168.56.11 --users-export user_11.txt
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         192.168.56.11   445    WINTERFELL       Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         192.168.56.11   445    WINTERFELL       arya.stark                    2024-01-13 12:44:17 0       Arya Stark
SMB         192.168.56.11   445    WINTERFELL       sansa.stark                   2024-01-13 12:44:35 0       Sansa Stark
SMB         192.168.56.11   445    WINTERFELL       brandon.stark                 2024-01-13 12:44:39 0       Brandon Stark
SMB         192.168.56.11   445    WINTERFELL       rickon.stark                  2024-01-13 12:44:43 0       Rickon Stark
SMB         192.168.56.11   445    WINTERFELL       hodor                         2024-01-13 12:44:47 0       Brainless Giant
SMB         192.168.56.11   445    WINTERFELL       jon.snow                      2024-01-13 12:44:51 0       Jon Snow
SMB         192.168.56.11   445    WINTERFELL       samwell.tarly                 2024-01-13 12:44:55 0       Samwell Tarly (Password : Heartsbane)
SMB         192.168.56.11   445    WINTERFELL       jeor.mormont                  2024-01-13 12:44:59 0       Jeor Mormont
SMB         192.168.56.11   445    WINTERFELL       sql_svc                       2024-01-13 12:45:03 0       sql service
SMB         192.168.56.11   445    WINTERFELL       [*] Enumerated 10 local users: NORTH
SMB         192.168.56.11   445    WINTERFELL       [*] Writing 10 local users to user_11.txt

└─$ cat user_11.txt
Guest
arya.stark
sansa.stark
brandon.stark
rickon.stark
hodor
jon.snow
samwell.tarly
jeor.mormont
sql_svc

└─$ nxc smb 192.168.56.11  -u hodor -p 'hodor' --rid-brute 10000 --log rid-brute.txt
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\hodor:hodor
SMB         192.168.56.11   445    WINTERFELL       500: NORTH\Administrator (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       501: NORTH\Guest (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       502: NORTH\krbtgt (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       512: NORTH\Domain Admins (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       513: NORTH\Domain Users (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       514: NORTH\Domain Guests (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       515: NORTH\Domain Computers (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       516: NORTH\Domain Controllers (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       517: NORTH\Cert Publishers (SidTypeAlias)
SMB         192.168.56.11   445    WINTERFELL       520: NORTH\Group Policy Creator Owners (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       521: NORTH\Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       522: NORTH\Cloneable Domain Controllers (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       525: NORTH\Protected Users (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       526: NORTH\Key Admins (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       553: NORTH\RAS and IAS Servers (SidTypeAlias)
SMB         192.168.56.11   445    WINTERFELL       571: NORTH\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         192.168.56.11   445    WINTERFELL       572: NORTH\Denied RODC Password Replication Group (SidTypeAlias)
SMB         192.168.56.11   445    WINTERFELL       1000: NORTH\vagrant (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1001: NORTH\WINTERFELL$ (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1102: NORTH\DnsAdmins (SidTypeAlias)
SMB         192.168.56.11   445    WINTERFELL       1103: NORTH\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       1104: NORTH\SEVENKINGDOMS$ (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1105: NORTH\CASTELBLACK$ (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1106: NORTH\Stark (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       1107: NORTH\Night Watch (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       1108: NORTH\Mormont (SidTypeGroup)
SMB         192.168.56.11   445    WINTERFELL       1109: NORTH\AcrossTheSea (SidTypeAlias)
SMB         192.168.56.11   445    WINTERFELL       1110: NORTH\arya.stark (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1111: NORTH\eddard.stark (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1112: NORTH\catelyn.stark (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1113: NORTH\robb.stark (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1114: NORTH\sansa.stark (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1115: NORTH\brandon.stark (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1116: NORTH\rickon.stark (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1117: NORTH\hodor (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1118: NORTH\jon.snow (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1119: NORTH\samwell.tarly (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1120: NORTH\jeor.mormont (SidTypeUser)
SMB         192.168.56.11   445    WINTERFELL       1121: NORTH\sql_svc (SidTypeUser)
```
### Description

SMB memungkinkan enumerasi user dan group melalui RPC calls.

Jika tidak dikonfigurasi dengan baik, attacker dapat:

* Enumerate domain users
* Enumerate groups
* Identify service accounts
* Identify attack targets

### Impact

* Mempermudah **password spraying**
* Mempermudah **brute force attack**
* Mempermudah **credential harvesting**
* Mempermudah **privilege escalation path discovery**

### Fix / Mitigation

Batasi anonymous enumeration:

```powershell
Network access: Do not allow anonymous enumeration of SAM accounts
```

Disable null sessions:

```powershell
Network access: Restrict anonymous access
```

Audit SMB access logs.

---

# Overall Risk Assessment

| Category              | Risk Level |
| --------------------- | ---------- |
| Domain Compromise     | HIGH       |
| Remote Code Execution | HIGH       |
| Privilege Escalation  | HIGH       |
| Credential Theft      | HIGH       |

### Security Priority

1. Patch **noPac**
2. Patch **PrintNightmare**
3. Disable **Print Spooler**
4. Harden **SMB configuration**
5. Disable **NTLM where possible**

---

# References

Microsoft Security Advisory
https://msrc.microsoft.com

noPac exploit
https://github.com/Ridter/noPac

PrintNightmare exploit
https://github.com/ly4k/PrintNightmare
