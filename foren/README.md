# Windows Registry Lateral Movement Checks (Live System & E01 Forensics)

Dokumen ini menjelaskan cara mengecek konfigurasi **Windows Registry** yang sering digunakan dalam:

* Incident Response
* DFIR (Digital Forensics)
* Threat Hunting
* Malware Analysis
* Penetration Testing

Pengecekan dapat dilakukan pada:

1. **Live Windows System**
2. **Forensic Disk Image (.E01)**

Fokus utama adalah registry yang mempengaruhi **remote administration dan lateral movement**.

---

# 1. Registry Checks (Live System)

## 1.1 UAC Remote Restriction

```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy
```

### Registry

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
```

### Key

```
LocalAccountTokenFilterPolicy
```

### Behavior

| Value | Meaning                         |
| ----- | ------------------------------- |
| 0     | Remote UAC restriction enabled  |
| 1     | Remote UAC restriction disabled |

Jika `1`, local administrator dapat melakukan remote execution dengan **full token**.

Tools yang memanfaatkan kondisi ini:

```
psexec
wmiexec
smbexec
winrm
```

---

# 1.2 Administrative Shares

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v AutoShareServer
```

### Registry

```
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
```

### Key

```
AutoShareServer
```

### Behavior

| Value | Meaning                        |
| ----- | ------------------------------ |
| 1     | Administrative shares enabled  |
| 0     | Administrative shares disabled |

Share yang dibuat:

```
C$
ADMIN$
IPC$
```

---

# 2. Additional Registry Checks (Lateral Movement)

## 2.1 RDP Enabled

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections
```

| Value | Meaning      |
| ----- | ------------ |
| 0     | RDP Enabled  |
| 1     | RDP Disabled |

---

## 2.2 WinRM Enabled

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\WinRM /v Start
```

| Value | Meaning    |
| ----- | ---------- |
| 2     | Auto start |
| 3     | Manual     |
| 4     | Disabled   |

---

## 2.3 SMB Version Settings

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v SMB1
```

---

## 2.4 Remote Registry Service

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry /v Start
```

---

# 3. Forensic Analysis from E01 Image

Jika hanya tersedia **disk image `.E01`**, registry harus diambil dari **Windows registry hive**.

## 3.1 Mount E01 Image

### Linux

```
ewfmount evidence.E01 /mnt/ewf
mount -o ro,loop /mnt/ewf/ewf1 /mnt/windows
```

### Windows

Gunakan:

* FTK Imager
* Arsenal Image Mounter
* EnCase

---

# 3.2 Locate Registry Hives

Windows registry hive berada di:

```
Windows/System32/config/
```

Hive yang dibutuhkan:

| Hive     | Purpose               |
| -------- | --------------------- |
| SYSTEM   | Service configuration |
| SOFTWARE | Windows policies      |
| SAM      | User accounts         |
| SECURITY | Security policies     |

Contoh path:

```
Windows/System32/config/SYSTEM
Windows/System32/config/SOFTWARE
```

---

# 3.3 Determine Active ControlSet

Dalam hive SYSTEM:

```
reg query HKLM\ForensicSYSTEM\Select
```

Output contoh:

```
Current    REG_DWORD    0x1
Default    REG_DWORD    0x1
```

Artinya **ControlSet001** adalah yang aktif.

Mapping:

```
CurrentControlSet = ControlSet001
```

---

# 3.4 Load Registry Hive

## Load SOFTWARE

```
reg load HKLM\ForensicSOFTWARE C:\Mount\Windows\System32\config\SOFTWARE
```

## Load SYSTEM

```
reg load HKLM\ForensicSYSTEM C:\Mount\Windows\System32\config\SYSTEM
```

---

# 3.5 Run Registry Queries (Offline)

## LocalAccountTokenFilterPolicy

```
reg query HKLM\ForensicSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy
```

## AutoShareServer

```
reg query HKLM\ForensicSYSTEM\ControlSet001\Services\LanmanServer\Parameters /v AutoShareServer
```

## RDP

```
reg query HKLM\ForensicSYSTEM\ControlSet001\Control\Terminal Server /v fDenyTSConnections
```

## WinRM

```
reg query HKLM\ForensicSYSTEM\ControlSet001\Services\WinRM /v Start
```

---

# 3.6 Unload Registry Hive

Setelah selesai analisis:

```
reg unload HKLM\ForensicSOFTWARE
reg unload HKLM\ForensicSYSTEM
```

---
