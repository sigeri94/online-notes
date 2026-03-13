# SMB Enumeration & Recon Guide

Dokumen ini berisi langkah-langkah **enumerasi host, konfigurasi Kerberos, dan reconnaissance SMB** menggunakan **NetExec (nxc)**.

---

# HOSTS

Generate file `hosts` berdasarkan hasil enumerasi SMB untuk mempermudah resolusi hostname pada environment Active Directory.

## Generate Hosts File

```bash
nxc smb 192.168.56.11 --generate-hosts hosts
nxc smb 192.168.56.10 --generate-hosts hosts
```

### Output

```bash
192.168.56.11     WINTERFELL.north.sevenkingdoms.local north.sevenkingdoms.local WINTERFELL
192.168.56.10     KINGSLANDING.sevenkingdoms.local sevenkingdoms.local KINGSLANDING
```

### Keterangan

| IP            | Hostname     | Domain                    |
| ------------- | ------------ | ------------------------- |
| 192.168.56.11 | WINTERFELL   | north.sevenkingdoms.local |
| 192.168.56.10 | KINGSLANDING | sevenkingdoms.local       |

File ini biasanya ditambahkan ke:

```bash
/etc/hosts
```

agar tool enumeration dapat melakukan **domain resolution** dengan benar.

---

# Generate Kerberos Configuration

NetExec dapat membuat file **Kerberos configuration (`krb5.conf`)** secara otomatis dari informasi domain SMB.

## Generate krb5.conf

```bash
nxc smb 192.168.56.11 --generate-krb5 krb5.conf
```

### krb5.conf

```bash
[libdefaults]
dns_lookup_kdc = false
dns_lookup_realm = false
default_realm = NORTH.SEVENKINGDOMS.LOCAL

[realms]
NORTH.SEVENKINGDOMS.LOCAL = {
    kdc = winterfell.north.sevenkingdoms.local
    admin_server = winterfell.north.sevenkingdoms.local
    default_domain = north.sevenkingdoms.local
}

[domain_realm]
.north.sevenkingdoms.local = NORTH.SEVENKINGDOMS.LOCAL
north.sevenkingdoms.local = NORTH.SEVENKINGDOMS.LOCAL
```

---

## Generate krb5.conf untuk Domain Kedua

```bash
nxc smb 192.168.56.10 --generate-krb5 krb5.conf
```

### krb5.conf

```bash
[libdefaults]
dns_lookup_kdc = false
dns_lookup_realm = false
default_realm = SEVENKINGDOMS.LOCAL

[realms]
SEVENKINGDOMS.LOCAL = {
    kdc = kingslanding.sevenkingdoms.local
    admin_server = kingslanding.sevenkingdoms.local
    default_domain = sevenkingdoms.local
}

[domain_realm]
.sevenkingdoms.local = SEVENKINGDOMS.LOCAL
sevenkingdoms.local = SEVENKINGDOMS.LOCAL
```

File ini digunakan untuk:

* Kerberos authentication
* Impacket tools
* BloodHound
* Kerberoasting
* Ticket-based attacks

---

# RECON

Tahap reconnaissance untuk menemukan host, shares SMB, user account, dan credential yang valid.

---

# Discover Hosts

Scanning network untuk menemukan host aktif.

```bash
sudo netdiscover -r 10.136.69.0/24 | awk '{print $1}'
```

---

# Enumerate SMB Shares

Enumerasi SMB shares menggunakan beberapa metode autentikasi.

## Anonymous Login

```bash
nxc smb ./hosts.txt -u '' -p '' --shares
```

## Guest Login

```bash
nxc smb ./hosts.txt -u 'guest' -p '' --shares
```

## Anonymous User

```bash
nxc smb ./hosts.txt -u 'anonymous' -p '' --shares
```

---

# SMB Share Spidering

Download seluruh file dari share SMB menggunakan module **spider_plus**.

```bash
NASIP=10.136.69.10

nxc smb ${NASIP} -u 'guest' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

Fungsi module ini:

* Enumerate file
* Download file otomatis
* Mencari credential atau sensitive data

---

# Enumerate Users

Enumerasi user dari SMB service.

```bash
nxc smb ./hosts.txt -u 'guest' -p '' --users
```

atau

```bash
nxc smb ./hosts.txt -u '' -p '' --users
```

---

# Credential Testing

Setelah menemukan credential dari tahap sebelumnya, lakukan autentikasi ke target.

```bash
TARGET_USERNAME=#[fill in the username you discovered]
TARGET_PASSWORD=#[fill in the password you discovered]

nxc smb ./hosts.txt -u "${TARGET_USERNAME}" -p "${TARGET_PASSWORD}"
```

### Example Result

```bash
SMB 192.168.56.11 445 WINTERFELL [+] north.sevenkingdoms.local\hodor:hodor
```

---

# Spooler Service Enumeration

Cek apakah **Print Spooler service** aktif pada target.

```bash
SPOOLER 192.168.56.11 445 WINTERFELL Spooler service enabled
```

Jika aktif, target kemungkinan rentan terhadap:

* PrinterBug
* PrintNightmare
* NTLM Coercion attacks

---

# Summary

Tahapan reconnaissance ini memungkinkan attacker untuk:

* menemukan host dalam network
* enumerasi SMB shares
* enumerasi user domain
* menemukan credential valid
* mengidentifikasi attack surface (seperti Print Spooler)

Tools utama yang digunakan:

* NetExec (nxc)
* netdiscover
* SMB enumeration modules

---
