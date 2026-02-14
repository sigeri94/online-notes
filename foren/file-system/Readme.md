
# File System Timeline & Persistence Hunting (PowerShell)

Dokumen ini berisi perintah PowerShell untuk:

- Mengidentifikasi file yang baru dibuat
- Menemukan persistence melalui Scheduled Tasks
- Melakukan timeline hunting berdasarkan tanggal kejadian
- Mengekspor artefak untuk analisis lanjutan

---
```powershell
Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object { $_.Attributes -match "Hidden|System" } |
Select FullName, Attributes, Length |
Export-Csv hidden_files.csv -NoTypeInformation

$paths = @(
"C:\ProgramData",
"C:\Windows\Temp",
"C:\Users",
"C:\Windows\System32\Tasks",
"c:\windows\tasks\"
)

foreach ($p in $paths) {
    Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match "Hidden" } |
    Select FullName, Attributes, Length
}

Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
ForEach-Object {
    Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
}

Get-ChildItem C:\ -Recurse -Force -File |
Where-Object { $_.Extension -eq "" } |
Select FullName, Length

Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -match "svchost|explorer|lsass|chrome|winlogon"
} |
Select FullName

Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
Sort CreationTime |
Select -Last 50 FullName, CreationTime

```
## 🔍 Enumerasi File User Directory

Menampilkan seluruh file dalam direktori user beserta timestamp penting.

```powershell
Get-ChildItem "F:\users" -Recurse -File -Force -ErrorAction SilentlyContinue |
Select-Object FullName, CreationTime, LastWriteTime, Length |
Sort-Object CreationTime
````

### 🎯 Tujuan

* Menemukan file mencurigakan di profil user
* Mengidentifikasi payload yang baru dibuat
* Melihat staging tools atau exfil file

---

## ⏰ Scheduled Tasks Persistence Check

Scheduled Tasks sering digunakan sebagai mekanisme persistence.

```powershell
Get-ChildItem "F:\Windows\system32\tasks" -Recurse -File -Force -ErrorAction SilentlyContinue |
Select-Object FullName, CreationTime, LastWriteTime, Length |
Sort-Object CreationTime
```

### 🎯 Tujuan

* Mendeteksi task berbahaya
* Menemukan task yang dibuat attacker
* Mengidentifikasi perubahan persistence

---

## 📅 Timeline Hunting Berdasarkan Tanggal

### Filter file dibuat pada **04 Desember 2025**

```powershell
$start = Get-Date "12/04/2025"
$end = $start.AddDays(1)

Get-ChildItem "F:\Users" -Recurse -Force -File -ErrorAction SilentlyContinue |
Where-Object {
    $_.CreationTime -ge $start -and $_.CreationTime -lt $end
}
```

---

## 📅 Timeline Hunting (Seluruh Drive)

### Filter file dibuat pada **03 Desember 2025** dan ekspor hasil

```powershell
$start = Get-Date "12/03/2025"
$end   = $start.AddDays(1)

Get-ChildItem "F:\" -Recurse -File -Force -ErrorAction SilentlyContinue |
Where-Object {
    $_.CreationTime -ge $start -and $_.CreationTime -lt $end
} |
Select-Object FullName, CreationTime, LastWriteTime, Length |
Sort-Object CreationTime |
Export-Csv "C:\Users\batman\Desktop\analisa-all-03122025.csv" -NoTypeInformation -Encoding UTF8
```

---

## 📁 User Activity Artifacts

### Artefak yang dikumpulkan
- UserAssist
- RecentDocs
- Shellbags
- Open / Save MRU
- Last Visited Files

### Ekstraksi Registry Hives dengan KAPE

```powershell
kape.exe ^
 --tsource E: ^
 --tdest C:\DFIR\Case01\Extracted ^
 --target RegistryHives
````

### Parsing NTUSER.DAT

```powershell
RECmd.exe -f NTUSER.DAT --kn UserAssist --csv C:\DFIR\Case01\Output
RECmd.exe -f NTUSER.DAT --kn RecentDocs --csv C:\DFIR\Case01\Output
RECmd.exe -f NTUSER.DAT --kn OpenSavePidlMRU --csv C:\DFIR\Case01\Output
RECmd.exe -f NTUSER.DAT --kn LastVisitedPidlMRU --csv C:\DFIR\Case01\Output
```
```powershell
volatility -f <memory_image> --profile=<profile> hivelist

volatility -f <memory_image> --profile=<profile> userassist -i

```
### Parsing Shellbags

```powershell
SBECmd.exe -f USRCLASS.DAT --csv C:\DFIR\Case01\Output
```

### Konversi Waktu Eksekusi ke WIB

```powershell
Import-Csv UserAssist.csv |
Select *,
@{Name="LastExecutionTime_WIB";Expression={[datetime]$_.LastExecutionTime).AddHours(7)}}
```

---

## 🖥️ Execution & Program Evidence

### BAM & ShimCache

```powershell
RECmd.exe -f SYSTEM --kn Bam --csv C:\DFIR\Case01\Output
RECmd.exe -f SYSTEM --kn ShimCache --csv C:\DFIR\Case01\Output
```

### Amcache (Program Execution History)

```powershell
AmcacheParser.exe ^
 -f E:\Windows\AppCompat\Programs\Amcache.hve ^
 --csv C:\DFIR\Case01\Output
```

### Prefetch Analysis

```powershell
PECmd.exe ^
 -d E:\Windows\Prefetch ^
 --csv C:\DFIR\Case01\Output\Prefetch
```

### Prefetch Timeline

```powershell
PECmd.exe ^
 -d E:\Windows\Prefetch ^
 --csv C:\DFIR\Case01\Output\Prefetch ^
 --timeline
```

---

## 📂 File System Timeline Artifacts

### Master File Table ($MFT)

```powershell
MFTECmd.exe ^
 -f E:\$MFT ^
 --csv C:\DFIR\Case01\Output\MFT
```

### MACB Timestamp Meaning

| Letter | Meaning         |
| ------ | --------------- |
| M      | Modified        |
| A      | Accessed        |
| C      | MFT Changed     |
| B      | Created (Birth) |

---

### USN Journal

```powershell
UsnJrnl2Csv.exe ^
 -f E:\$Extend\$UsnJrnl:$J ^
 --csv C:\DFIR\Case01\Output\USN
```

---
