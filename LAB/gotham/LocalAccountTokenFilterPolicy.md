# Penjelasan Registry: LocalAccountTokenFilterPolicy

## Perintah

```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy
```

## Penjelasan Per Bagian

- **reg query**  
  Perintah untuk membaca nilai dari Windows Registry.

- **HKLM**  
  Singkatan dari *HKEY_LOCAL_MACHINE*, yaitu registry untuk konfigurasi sistem.

- **SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System**  
  Lokasi registry yang menyimpan kebijakan sistem Windows.

- **/v LocalAccountTokenFilterPolicy**  
  Menampilkan nilai spesifik bernama `LocalAccountTokenFilterPolicy`.

---

## Apa itu LocalAccountTokenFilterPolicy?

`LocalAccountTokenFilterPolicy` adalah pengaturan registry yang mengatur bagaimana Windows menangani hak akses (UAC) untuk akun lokal saat mengakses komputer melalui jaringan (remote access).

Biasanya berkaitan dengan:

- Remote Administration
- Akses via SMB (\\IP\C$)
- PsExec
- Remote WMI
- Remote Registry

---

## Nilai yang Mungkin Muncul

| Nilai | Arti |
|-------|------|
| Tidak ada / 0 | Akun lokal yang login melalui jaringan akan dibatasi (UAC filtering aktif). Hak admin tidak penuh. |
| 1 | UAC filtering dimatikan untuk akun lokal. Akun admin lokal mendapat hak penuh saat akses remote. |

---

## Dampak Keamanan

Jika diset ke **1**:

- Mempermudah remote administration
- Meningkatkan risiko keamanan
- Memungkinkan lateral movement lebih mudah dalam jaringan

Biasanya digunakan pada:

- Server internal
- Lab testing
- Sistem yang membutuhkan remote administration cepat

---

## Catatan Troubleshooting

Jika muncul error seperti:

```
Access is denied
```

Saat mengakses:

```
\\IP\C$
```

Kemungkinan penyebabnya adalah pengaturan `LocalAccountTokenFilterPolicy`.

---

## Contoh Mengaktifkan (Set ke 1)

```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

## Contoh Menonaktifkan (Set ke 0)

```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
```
