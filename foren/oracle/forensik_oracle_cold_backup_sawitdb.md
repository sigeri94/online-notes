# Forensik Oracle Database (Cold Backup)

Dokumen ini menjelaskan **prosedur forensik Oracle menggunakan metode cold backup** dengan studi kasus database **SAWITDB**. Pendekatan ini bersifat **read-only / non-intrusive**, cocok untuk kebutuhan investigasi (fraud, insider threat, unauthorized access).

---

## 1. Prinsip Forensik Cold Backup

- Database **dalam kondisi shutdown bersih** (consistent)
- Seluruh file database disalin apa adanya
- Database hasil restore **tidak terhubung ke jaringan produksi**
- Aktivitas hanya untuk **analisa dan query forensik**

---

## 2. Artefak yang Dikopi dari Sistem Sumber

Pastikan database **SAWITDB** dalam kondisi shutdown normal.

### 2.1 Direktori Database

- `D:\ORACLEDB\SAWITDB`
  - datafile (`*.dbf`)
  - controlfile (`control*.ctl`)
  - redo log (`redo*.log`)

### 2.2 Direktori Admin

- `D:\ORACLEDB\admin\SAWITDB`
  - `pfile` (init.ora)
  - `adump` (audit trail OS)
  - `bdump / cdump / trace`
  - `dpdump`

> ⚠️ **Catatan penting:**
> Jangan melakukan perubahan apa pun pada file hasil copy.

---

## 3. Persiapan Environment Forensik

### 3.1 Install Oracle Software

- Versi Oracle **harus sama** dengan sistem sumber (contoh: Oracle 19c)
- Mode **Standalone / Forensic Lab**

### 3.2 Buat Oracle Service (Windows)

Gunakan `oradim` untuk membuat instance service:

```bat
oradim -new ^
  -sid SAWITDB ^
  -intpwd PasswordKuat1# ^
  -startmode auto ^
  -pfile D:\ORACLEDB\admin\SAWITDB\pfile\init.ora.10112024102819
```

### 3.3 Set Environment Variable

```bat
set ORACLE_SID=SAWITDB
```

Pastikan:
- `ORACLE_HOME` benar
- Path `init.ora` sesuai dengan lokasi hasil copy

---

## 4. Proses Startup Database Forensik

Masuk ke SQL*Plus sebagai SYSDBA:

```sql
sqlplus / as sysdba
```

### 4.1 Startup Nomount

```sql
startup nomount pfile='D:\ORACLEDB\admin\SAWITDB\pfile\init.ora.10112024102819';
```

### 4.2 Mount Database

```sql
alter database mount;
```

### 4.3 Open Database

```sql
alter database open;
```

> 🔎 Jika tujuan hanya analisa metadata dan audit, **mount saja sudah cukup**.

---

## 5. Pembuatan SPFILE (Opsional)

Untuk stabilitas instance forensik:

```sql
create spfile from pfile='D:\ORACLEDB\admin\SAWITDB\pfile\init.ora.10112024102819';
```

---

## 6. Setup SQL*Plus untuk Analisa Forensik

```sql
SET PAGES 50000
SET LINES 200
col dbusername for a15
col userhost   for a30
col action_name for a15
col event_timestamp for a25
```

---

## 7. Analisa Audit Login (Unified Audit Trail)

### 7.1 Tujuan

- Mengidentifikasi **login & logoff user**
- Menentukan **waktu, user, dan host asal**
- Korelasi dengan insiden fraud

### 7.2 Query Audit Login

```sql
SELECT
    TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_time,
    dbusername,
    userhost,
    action_name
FROM unified_audit_trail
WHERE event_timestamp >= TO_TIMESTAMP('2024-12-04 00:00:00', 'YYYY-MM-DD HH24:MI:SS')
  AND event_timestamp <  TO_TIMESTAMP('2025-12-05 00:00:00', 'YYYY-MM-DD HH24:MI:SS')
  AND action_name IN ('LOGON', 'LOGOFF')
ORDER BY event_timestamp ASC;
```
```sql
SELECT 
TO_CHAR(event_timestamp,'YYYY-MM-DD HH24:MI:SS') event_time,
    dbusername,
    userhost,
    os_username,
    client_program_name,ACTION_NAME,sql_text
FROM unified_audit_trail
WHERE event_timestamp >= TO_TIMESTAMP('2025-10-01 00:00:00','YYYY-MM-DD HH24:MI:SS');
```
---

## 8. Validasi Forensik

Checklist validasi:

- [ ] DB berjalan dari **file hasil copy**
- [ ] Tidak ada koneksi aplikasi eksternal
- [ ] Tidak ada user baru dibuat
- [ ] Tidak ada perubahan data
- [ ] Semua aktivitas tercatat di log investigator

---

## 9. Catatan Penting Investigasi

- Database forensik **bukan untuk recovery produksi**
- Jangan menjalankan:
  - `DBMS_STATS`
  - `UTLRP`
  - `CATALOG.SQL`
- Semua query bersifat **read-only**

---

## 10. Output yang Dihasilkan

- Timeline login user
- Bukti akses tidak sah
- Korelasi user – host – waktu
- Artefak pendukung laporan forensik

---

**Dokumen ini siap digunakan sebagai SOP / Checklist Investigator Oracle.**

