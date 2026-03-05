
# Python Setup dan Virtual Environment
---

# 1. Install Python (Windows - PowerShell)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest `
  -Uri "https://www.python.org/ftp/python/3.7.0/python-3.7.0.exe" `
  -OutFile "C:\temp\python-3.7.0.exe"

C:\temp\python-3.7.0.exe /quiet InstallAllUsers=0 InstallLauncherAllUsers=0 PrependPath=1 Include_test=0
````

---

# 2. Membuat Virtual Environment

```bash
python -m venv myenv
```

---

# 3. Mengaktifkan Virtual Environment

### Windows

```bash
myenv\Scripts\activate
```

### Linux / macOS

```bash
source myenv/bin/activate
```

---

# 4. Install Package

```bash
pip install <package-name>
```

---

# 5. Menjalankan Script

### Script pertama

```bash
python3 r10.py ./pel.nessus ./vuln ./ip3.txt
```

### Script kedua

```bash
python3 final_doc.py ./pel.nessus \
'SQL Dump' \
'Git Repository' \
'phpinfo.php' \
'web.config' \
'SSL Certificate Expiry' \
'SWEET32' \
'RC4' \
'Distrusted' \
'BEAST' \
'POODLE' \
'FREAK' \
'Community' \
'rlogin' \
'Redis Server Unprotected' \
'AMQP' \
'Unencrypted Telnet Server' \
'SMB Signing not required' \
'SMB NULL Session Authentication' \
'MS09-050' \
'NLA' \
'Browsable' \
'phpMyAdmin' \
'Patch Report' \
'Terrapin' \
'Poisoning'
```
