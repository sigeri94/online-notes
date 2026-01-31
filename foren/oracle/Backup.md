Siap 👍
Berikut **versi Markdown (.md)** yang rapi dan siap disimpan sebagai file dokumentasi (misalnya `oracle_19c_backup_windows.md`).

---

```md
# Oracle 19c – Daily Backup & Housekeeping (Windows)

Dokumentasi ini berisi **paket batch file DBA** yang rapi dan production-style untuk **Oracle 19c di Windows**.  
Mencakup backup log, trace, RMAN, EXPDP, serta housekeeping otomatis (rotate 30 hari).

---

## 📁 Struktur Folder (Rekomendasi)

```

D:\oracle\backup
│
├── rman
│   ├── daily
│   └── log
│
├── expdp
│   ├── daily
│   └── log
│
├── listener
│   ├── config
│   └── log
│
├── rdbms_trace
│   ├── alert
│   └── trace
│
└── script\

````

---

## 1️⃣ Batch Backup Log & Trace Penting

### 🔹 1.1 Backup `listener.log` (rotate + archive)
**File:** `backup_listener_log.cmd`

```bat
@echo off
set ORACLE_HOME=C:\oracle\product\19c\dbhome_1
set LISTENER_TRACE=C:\oracle\diag\tnslsnr\HOSTNAME\listener\trace
set DEST=D:\oracle\backup\listener\log
set DATESTR=%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%

lsnrctl set log_status off
rename "%LISTENER_TRACE%\listener.log" listener_%DATESTR%.log
lsnrctl set log_status on

move "%LISTENER_TRACE%\listener_%DATESTR%.log" "%DEST%\"

echo Listener log backup done %DATE% %TIME% >> %DEST%\listener_backup.log
````

> ⚠️ **Ganti `HOSTNAME`** sesuai folder listener di server kamu.

---

### 🔹 1.2 Backup Alert Log

**File:** `backup_alert_log.cmd`

```bat
@echo off
set TRACE_DIR=C:\oracle\diag\rdbms\SAWITDB\SAWITDB\trace
set DEST=D:\oracle\backup\rdbms_trace\alert
set DATESTR=%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%

copy "%TRACE_DIR%\alert_SAWITDB.log" "%DEST%\alert_SAWITDB_%DATESTR%.log"
```

---

### 🔹 1.3 Backup Trace Penting (`*.trc` 1 hari terakhir)

**File:** `backup_trace_important.cmd`

```bat
@echo off
set TRACE_DIR=C:\oracle\diag\rdbms\SAWITDB\SAWITDB\trace
set DEST=D:\oracle\backup\rdbms_trace\trace

forfiles /p "%TRACE_DIR%" /m *.trc /d -1 /c "cmd /c copy @file %DEST%\"
```

---

## 2️⃣ Housekeeping (Anti Disk Penuh)

### 🔹 2.1 Purge Trace & Alert via ADRCI (Rekomendasi)

**File:** `cleanup_rdbms_trace.cmd`

```bat
@echo off
adrci <<EOF
SET HOME diag\rdbms\sawitdb\SAWITDB
PURGE -AGE 720 -TYPE TRACE
PURGE -AGE 720 -TYPE ALERT
EXIT
EOF
```

⏱️ **720 jam = 30 hari**

---

### 🔹 2.2 Rotate Backup > 30 Hari

**File:** `cleanup_backup_30days.cmd`

```bat
@echo off
set BASE=D:\oracle\backup

forfiles /p %BASE% /s /d -30 /c "cmd /c del @file"
```

---

## 3️⃣ RMAN Backup Harian (Rotate 30 Hari)

### 🔹 3.1 Batch RMAN

**File:** `backup_rman_daily.cmd`

```bat
@echo off
set ORACLE_SID=SAWITDB
set DEST=D:\oracle\backup\rman\daily
set LOG=D:\oracle\backup\rman\log
set DATESTR=%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%

rman target dacen_rman/dacen123@SAWITDB log=%LOG%\rman_%DATESTR%.log <<EOF
RUN {
  BACKUP DATABASE
  FORMAT '%DEST%\db_%T_%U.bkp';
}
EXIT;
EOF
```

---

### 🔹 3.2 Rotate RMAN Backup > 30 Hari

**File:** `cleanup_rman_30days.cmd`

```bat
@echo off
forfiles /p D:\oracle\backup\rman /s /d -30 /c "cmd /c del @file"
```

---

## 4️⃣ EXPDP Backup Harian (Rotate 30 Hari)

### 🔹 4.1 EXPDP Schema

**File:** `backup_expdp_daily.cmd`

```bat
@echo off
set ORACLE_SID=SAWITDB
set DEST=D:\oracle\backup\expdp\daily
set LOG=D:\oracle\backup\expdp\log
set DATESTR=%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%

expdp dacen/dacen123@SAWITDB ^
schemas=SAWIT_LAB ^
directory=DP_BACKUP ^
dumpfile=sawit_%DATESTR%.dmp ^
logfile=sawit_%DATESTR%.log
```

---

### 🔹 4.2 Rotate EXPDP Backup > 30 Hari

**File:** `cleanup_expdp_30days.cmd`

```bat
@echo off
forfiles /p D:\oracle\backup\expdp /s /d -30 /c "cmd /c del @file"
```

---

## 5️⃣ Master Batch (Jalankan Harian)

**File:** `daily_backup_all.cmd`

```bat
call backup_listener_log.cmd
call backup_alert_log.cmd
call backup_trace_important.cmd
call backup_rman_daily.cmd
call backup_expdp_daily.cmd
call cleanup_rdbms_trace.cmd
call cleanup_backup_30days.cmd
```

---

## 6️⃣ Jadwal (Windows Task Scheduler)

| Job         | Waktu |
| ----------- | ----- |
| RMAN        | 01:00 |
| EXPDP       | 02:00 |
| Log & Trace | 03:00 |
| Cleanup     | 04:00 |

---
