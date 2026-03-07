
# Web Access Log Forensic Analysis

Dokumen ini berisi beberapa command untuk melakukan analisa terhadap **Apache/Nginx access log** yang sudah di-rotate dan dikompresi (`.gz`).

Log yang dianalisa:

- access.log
- access.log.1
- access.log*.gz

Teknik ini umum digunakan dalam **incident response, web compromise investigation, dan traffic analysis**.

---

# 1. Analisa User-Agent Mencurigakan

Script berikut menampilkan **jumlah request per hari berdasarkan User-Agent**.

User-Agent yang mengandung **Mozilla** akan difilter karena biasanya merupakan browser normal.

Output disimpan ke:

```

useragent.txt

````

### Command

```bash
(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | awk -F\" '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    agent=$6

    split($1,a,"[")
    split(a[2],b,":")
    split(b[1],d,"/")

    day=d[3] "-" month[d[2]] "-" d[1]

    key=day SUBSEP agent
    count[key]++
}
END{
    for(k in count){
        split(k,v,SUBSEP)
        printf "%s\t%d\t%s\n", v[1], count[k], v[2]
    }
}' | sort -k1,1 -k2,2nr | grep -v Mozilla > useragent.txt
````

### Tujuan

Mendeteksi:

* Bot
* Scanner
* Exploit framework
* Malware beacon
* Script otomatis

Contoh indikator mencurigakan:

```
curl
python-requests
masscan
sqlmap
nikto
Go-http-client
```

---

# 2. Analisa Referer

Script ini menampilkan **referer yang mengakses website per hari**.

Referer yang difilter:

* google.com
* 192.168.99.86
* udara.com

Output disimpan ke:

```
refer.txt
```

### Command

```bash
(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | awk -F\" '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    referer=$4

    split($1,a,"[")
    split(a[2],b,":")
    split(b[1],d,"/")

    day=d[3] "-" month[d[2]] "-" d[1]

    key=day SUBSEP referer
    count[key]++
}
END{
    for(k in count){
        split(k,v,SUBSEP)
        printf "%s\t%d\t%s\n", v[1], count[k], v[2]
    }
}' | sort -k1,1 -k2,2nr | egrep -v 'google.com|192.168.99.86|udara.com' > refer.txt
```

### Tujuan

Mengidentifikasi:

* Spam SEO injection
* Malicious redirect
* Suspicious campaign
* Exploit referral

Contoh referer mencurigakan:

```
casino spam
phishing site
unknown crawler
```

---

# 3. Total Download Bandwidth Per Hari

Script ini menghitung **total bandwidth download per hari**.

Output ditampilkan dalam **GB per hari**.

Output disimpan ke:

```
down.txt
```

### Command

```bash
(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | \
awk '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    split($4,a,":")
    date=substr(a[1],2)
    split(date,b,"/")

    day=b[3]"-"month[b[2]]"-"b[1]

    bytes=$10
    if(bytes=="-") bytes=0

    total[day]+=bytes
}
END{
    for(d in total){
        printf "%s\t%.2f GB\n", d, total[d]/1024/1024/1024
    }
}' | sort > down.txt
```

### Tujuan

Mengidentifikasi:

* Data exfiltration
* Download abuse
* Bot scraping
* File leakage

Contoh indikator:

```
Download tiba-tiba melonjak
Traffic abnormal
```

---

# 4. Top Download File Per Hari

Script ini menampilkan **5 file dengan download terbesar per hari**.

Output disimpan ke:

```
down_file.txt
```

### Command

```bash
(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | \
awk '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    split($4,a,":")
    date=substr(a[1],2)
    split(date,b,"/")
    day=b[3]"-"month[b[2]]"-"b[1]

    url=$7
    split(url,u,"?")
    path=u[1]

    bytes=$10
    if(bytes=="-") bytes=0

    key=day "|" path
    total[key]+=bytes
}
END{
    for(k in total){
        split(k,v,"|")
        printf "%s\t%.2f\t%s\n", v[1], total[k]/1024/1024, v[2]
    }
}' | sort -k1,1 -k2,2nr | \
awk '
{
day=$1
mb=$2
url=$3

if(day!=prev){
    if(prev!="") print ""
    print "Tanggal:",day
    n=0
}

if(n<5){
    printf "%10.2f MB  %s\n", mb, url
    n++
}

prev=day
}' > down_file.txt
```

### Tujuan

Menemukan:

* File paling banyak didownload
* Data leak
* Resource abuse
* Bot scraping

Contoh output:

```
Tanggal: 2025-12-10

    900.20 MB /backup/db.sql
    500.40 MB /uploads/video.mp4
    210.55 MB /export/customer.csv
```

---

# 5. Summary Output Files

| File          | Keterangan                        |
| ------------- | --------------------------------- |
| useragent.txt | User-Agent mencurigakan           |
| refer.txt     | Referer mencurigakan              |
| down.txt      | Total bandwidth download per hari |
| down_file.txt | Top download file per hari        |

---

# 6. Tips Forensic Investigation

Hal yang perlu diperiksa setelah analisa log:

1. IP address dengan request tinggi
2. User-Agent tidak biasa
3. Download file besar
4. Referer mencurigakan
5. Request ke file sensitif

Contoh file sensitif:

```
/backup
/.env
/config.php
/admin
/database.sql
```

---

# 7. Investigasi Lanjutan

Beberapa command tambahan untuk investigasi:

### Top IP Address

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head
```

### Top URL

```bash
awk '{print $7}' access.log | sort | uniq -c | sort -nr | head
```

### Cari Webshell Access

```bash
grep -Ei "cmd=|shell=|exec=|system=" access.log
```

