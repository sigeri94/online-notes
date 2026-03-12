
# Windows Debloat & Telemetry Reduction Script

Script PowerShell ini digunakan untuk:

1. Menghapus beberapa **built-in Windows Apps (AppxPackage)** yang dianggap tidak diperlukan.
2. Menonaktifkan beberapa **Scheduled Tasks** yang berhubungan dengan telemetry, feedback, dan usage data.

Script ini biasanya digunakan pada environment **hardening, forensic lab, sandbox, atau VM testing** untuk mengurangi komponen yang tidak diperlukan.

---

# 1. Penghapusan Built-in Windows Apps

Script akan melakukan iterasi pada daftar aplikasi berikut dan mencoba menghapusnya untuk semua user:

| Package Name | Deskripsi |
|---|---|
| Microsoft.Windows.Photos | Aplikasi Photos Viewer |
| Microsoft.WindowsCamera | Aplikasi Camera |
| Microsoft.WindowsSoundRecorder | Voice Recorder |
| Microsoft.MicrosoftStickyNotes | Sticky Notes |
| Microsoft.Copilot | Microsoft Copilot |
| Microsoft.OutlookForWindows | Outlook New |
| Microsoft.Windows.DevHome | Dev Home |
| Microsoft.XboxIdentityProvider | Xbox Identity Service |
| Microsoft.XboxGameCallableUI | Xbox Gaming UI |
| AppUp.IntelGraphicsExperience | Intel Graphics Experience |
| Microsoft.MicrosoftEdgeDevToolsClient | Edge DevTools Client |
| Microsoft.Windows.SecureAssessmentBrowser | Secure Assessment Browser |
| Microsoft.Windows.NarratorQuickStart | Narrator Quick Start |
| Microsoft.Windows.PeopleExperienceHost | People Experience |
| Microsoft.Windows.ParentalControls | Parental Controls |

Metode yang digunakan:

```

Get-AppxPackage -Name <PackageName> -AllUsers
Remove-AppxPackage

```

Parameter yang digunakan:

- **-AllUsers** → mencari package untuk seluruh user
- **-ErrorAction SilentlyContinue** → menghindari error jika package tidak ada

---

# 2. Menonaktifkan Scheduled Tasks Telemetry

Script juga menonaktifkan beberapa scheduled tasks yang berkaitan dengan telemetry dan feedback Windows.

| Scheduled Task | Fungsi |
|---|---|
| ProgramDataUpdater | Update compatibility telemetry |
| StartupAppTask | Startup application tracking |
| DmClient | Telemetry upload |
| DmClientOnScenarioDownload | Telemetry download scenario |
| Sqm-Tasks | Software Quality Metrics |
| UsageDataFlushing | Flush usage telemetry |
| UsageDataReporting | Usage telemetry reporting |

Metode yang digunakan:

```

Disable-ScheduledTask

```

Script akan memisahkan **TaskName** dan **TaskPath** secara otomatis menggunakan:

```

$task.Split('')

```

---

# Cara Menjalankan Script

1. Jalankan **PowerShell sebagai Administrator**
2. Eksekusi script:

```

powershell -ExecutionPolicy Bypass -File debloat.ps1

```

---

# Verifikasi

### Cek AppxPackage

```

Get-AppxPackage -AllUsers

```

### Cek Scheduled Task

```

Get-ScheduledTask | Where-Object {$_.State -eq "Disabled"}

```

---

# Catatan

- Script ini **tidak menghapus aplikasi secara permanen dari image Windows**, hanya menghapus dari user environment.
- Beberapa aplikasi mungkin akan **install kembali setelah Windows Update atau Feature Update**.
- Beberapa package mungkin tidak ada tergantung versi Windows.

---

# Risiko

Beberapa fitur Windows mungkin tidak bekerja jika komponen terkait dihapus, misalnya:

- Xbox services
- Windows Photos viewer
- Copilot integration
- Outlook integration

Gunakan script ini **hanya pada environment testing, VM, atau system hardening yang terkontrol**.

---
