
# Forensic Notes - Suspicious PHP Files

## 1. Informasi File Awal

File yang diperiksa:

```

themes-data.php

````

Ukuran berdasarkan `wc`:

```bash
wc themes-data.php
1 25 1979497 themes-data.php
````

Keterangan:

| Lines | Words | Bytes   | File            |
| ----- | ----- | ------- | --------------- |
| 1     | 25    | 1979497 | themes-data.php |

Indikasi mencurigakan:

* File hanya **1 baris**
* Ukuran hampir **2 MB**
* Pola ini sering ditemukan pada **obfuscated PHP malware / webshell**

---

# 2. Pencarian Berdasarkan Panjang Line (>1450 karakter)

Command:

```bash
find . -type f -name "*.php" -exec grep -H '.\{1450\}' {} \; | cut -d":" -f1
```

Hasil:

```
./themes-data.php
./maintenance/css/bootstrap.css.map.php
./maintenance/js/jquery_costume.php
./default/assets/css/icomoon/fonts/icommon-tools.php
./default/assets/css login/elisyam.css.php
./default/assets/css/skins/skin-tools.php
```

Indikasi:

* Banyak malware PHP dibuat **1 line sangat panjang**
* Digunakan untuk menyembunyikan **payload base64 / eval / gzinflate**

---

# 3. Pencarian Berdasarkan Jumlah Kata / Bytes (wc)

Command:

```bash
find . -type f -name "*.php" -exec wc {} \; | egrep '1979497|1990207'
```

Hasil:

```
1 25 1979497 ./themes/themes-data.php
1 25 1990207 ./themes/maintenance/css/bootstrap.css.map.php
1 25 1990207 ./themes/maintenance/js/jquery_costume.php
2 25 1979497 ./themes/default/assets/css/icomoon/fonts/icommon-tools.php
1 25 1990207 ./themes/default/assets/css/login/elisyam.css.php
2 25 1979497 ./themes/default/assets/css/skins/skin-tools.php
```

Temuan penting:

| File                  | Lines | Words | Bytes   |
| --------------------- | ----- | ----- | ------- |
| themes-data.php       | 1     | 25    | 1979497 |
| bootstrap.css.map.php | 1     | 25    | 1990207 |
| jquery_costume.php    | 1     | 25    | 1990207 |
| icommon-tools.php     | 2     | 25    | 1979497 |
| elisyam.css.php       | 1     | 25    | 1990207 |
| skin-tools.php        | 2     | 25    | 1979497 |

Indikasi:

* Semua file memiliki **struktur hampir identik**
* Kemungkinan **satu malware disalin ke beberapa lokasi**

---

# 4. Pencarian Berdasarkan Ukuran File

Command:

```bash
find . -type f -name "*.php" -exec du {} \; | sort -n -r | head -n20
```

Hasil:

```
1944 ./themes/maintenance/js/jquery_costume.php
1944 ./themes/maintenance/css/bootstrap.css.map.php
1944 ./themes/default/assets/css/login/elisyam.css.php
1936 ./themes/themes-data.php
1936 ./themes/default/assets/css/skins/skin-tools.php
1936 ./themes/default/assets/css/icomoon/fonts/icommon-tools.php
```

Perbandingan dengan library legitimate:

```
1548 ./_public/libraries/tcpdfx/fonts/cid0kr.php
1548 ./_public/libraries/tcpdf/fonts/cid0kr.php
1268 ./_public/libraries/mpdf60/mpdf.php
```

Indikasi:

* File mencurigakan **lebih besar dari sebagian library**
* Lokasi file **tidak wajar** (di folder CSS / fonts)

Contoh lokasi aneh:

```
css/login/elisyam.css.php
fonts/icommon-tools.php
```

---

# 5. Pencarian Berdasarkan Hash (MD5)

Command:

```bash
find . -type f -name "*.php" -exec md5sum {} \; | egrep '248dab1978ca67ec9417651f1be2e3a8|a9bbdde7c631ad6cf0c3df6609518d9c|eed7188565b487cfe1a7b89872076e9f'
```

Hasil:

```
248dab1978ca67ec9417651f1be2e3a8 ./themes/themes-data.php
eed7188565b487cfe1a7b89872076e9f ./themes/maintenance/css/bootstrap.css.map.php
eed7188565b487cfe1a7b89872076e9f ./themes/maintenance/js/jquery_costume.php
a9bbdde7c631ad6cf0c3df6609518d9c ./themes/default/assets/css/icomoon/fonts/icommon-tools.php
eed7188565b487cfe1a7b89872076e9f ./themes/default/assets/css/login/elisyam.css.php
a9bbdde7c631ad6cf0c3df6609518d9c ./themes/default/assets/css/skins/skin-tools.php
```

Analisa:

| MD5                              | Jumlah File | Kemungkinan     |
| -------------------------------- | ----------- | --------------- |
| eed7188565b487cfe1a7b89872076e9f | 3           | Malware copy    |
| a9bbdde7c631ad6cf0c3df6609518d9c | 2           | Malware variant |
| 248dab1978ca67ec9417651f1be2e3a8 | 1           | Possible loader |

Indikasi:

* **File dengan hash sama muncul di beberapa lokasi**
* Kemungkinan **malware dropper menyalin payload**

---

# 6. Indikasi Kompromi

Beberapa indikator kompromi (IOC):

* File **PHP dalam folder CSS / JS**
* File **1 line sangat panjang**
* File **~2MB**
* **MD5 hash identik**
* File muncul di **banyak lokasi**

Kemungkinan:

* Obfuscated PHP malware
* Webshell loader
* SEO spam injector
* Cryptominer loader
* PHP backdoor

---

# 7. Rekomendasi Analisa Lanjutan

Langkah berikutnya:

### Dump isi file

```bash
head -c 500 themes-data.php
```

### Cari fungsi berbahaya

```bash
grep -E "eval|base64|gzinflate|str_rot13|assert" themes-data.php
```

### Decode base64

```bash
grep -o '[A-Za-z0-9+/]\{200,\}=' themes-data.php
```

### Beautify PHP

```bash
php -w themes-data.php
```

