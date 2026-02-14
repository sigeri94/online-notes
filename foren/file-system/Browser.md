Berikut **checklist artefak Firefox & Chrome untuk DFIR/Threat Hunting** + **link download tools** yang bisa langsung dipakai saat investigasi.

---

# ✅ CHECKLIST FORENSIK BROWSER

Gunakan checklist ini saat live response, disk imaging, atau timeline hunting.

---

# 🦊 Mozilla Firefox Checklist

📁 Lokasi:

```
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\
```

## ✅ Aktivitas Browsing

☐ `places.sqlite`
☐ `favicons.sqlite`

✔ History & bookmark
✔ situs phishing / C2
✔ cloud storage access

---

## ✅ Session & Activity Recovery

☐ `sessionstore.jsonlz4`
☐ `recovery.jsonlz4`

✔ tab terakhir sebelum shutdown
✔ aktivitas sebelum crash

---

## ✅ Download Evidence

☐ metadata download (di `places.sqlite`)

✔ file malware/tools
✔ staging payload

---

## ✅ Cookies & Session

☐ `cookies.sqlite`

✔ bukti login web
✔ SaaS/cloud access

---

## ✅ Credential Storage

☐ `logins.json`
☐ `key4.db`

✔ saved passwords
✔ lateral movement evidence

---

## ✅ Form & User Input

☐ `formhistory.sqlite`

✔ email
✔ username
✔ pencarian sensitif

---

## ✅ Cache Evidence

📁 `cache2\`

✔ recover file dihapus
✔ payload staging
✔ remote content

---

## ✅ Extensions & Persistence

☐ `extensions.json`
☐ `extensions\`

✔ malicious add-ons
✔ credential stealer

---

# 🌐 Google Chrome / Chromium Checklist

📁 Lokasi:

```
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\
```

---

## ✅ Browsing History

☐ `History`

✔ timeline browsing
✔ C2 traffic
✔ exfiltration

---

## ✅ Download Activity

☐ `History` → tabel downloads

✔ file diunduh
✔ sumber URL

---

## ✅ Cookies & Sessions

☐ `Cookies`

✔ bukti login
✔ cloud & SaaS access

---

## ✅ Saved Credentials

☐ `Login Data`

✔ credential storage
✔ password reuse investigation

---

## ✅ Autofill & Searches

☐ `Web Data`

✔ email & nama user
✔ search queries

---

## ✅ Session Recovery

☐ `Current Session`
☐ `Current Tabs`
☐ `Last Session`

✔ aktivitas sebelum shutdown

---

## ✅ Cache & Network Artifacts

📁 `Cache\`
📁 `Code Cache\`
📁 `GPUCache\`

✔ recover payload
✔ bukti akses file remote

---

## ✅ Extensions & Persistence

📁 `Extensions\`

✔ malicious extensions
✔ browser-based persistence

---

# ⭐ Artefak yang Masih Ada Walau History Dihapus

✔ Cookies
✔ Favicons
✔ Cache
✔ Session files
✔ DNS cache (OS)
✔ Jump Lists & Prefetch

👉 Sangat penting saat attacker mencoba anti-forensik.

---

# 🛠 TOOLS EKSTRAKSI & ANALISIS

## 🔬 All-in-One DFIR Tools

### 1️⃣ Autopsy

🔗 [https://www.sleuthkit.org/autopsy/](https://www.sleuthkit.org/autopsy/)
✔ gratis & powerful
✔ timeline + artefact parsing

---

### 2️⃣ Magnet AXIOM

🔗 [https://www.magnetforensics.com/products/magnet-axiom/](https://www.magnetforensics.com/products/magnet-axiom/)
✔ enterprise DFIR suite
✔ artefak browser sangat lengkap

---

## 🌐 Browser Artifact Specialists

### 3️⃣ Browser History Examiner

🔗 [https://www.foxtonforensics.com/browser-history-examiner/](https://www.foxtonforensics.com/browser-history-examiner/)
✔ analisis multi-browser
✔ timeline & keyword search

---

### 4️⃣ Nirsoft Browser Tools (Ringan & Cepat)

🔗 [https://www.nirsoft.net/web_browser_tools.html](https://www.nirsoft.net/web_browser_tools.html)

Tools penting:

* ChromeHistoryView
* MozillaHistoryView
* BrowsingHistoryView

✔ cepat untuk triage
✔ live response friendly

---

### 5️⃣ Hindsight (Chrome Forensics)

🔗 [https://github.com/obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight)

✔ khusus Chrome
✔ parsing artefak lengkap

---
```powershell
# ===============================
# Browser Artifact Collector
# DFIR / Incident Response Use
# ===============================

$ErrorActionPreference = "SilentlyContinue"

$destRoot = "C:\ForensicCollection"
$hostname = $env:COMPUTERNAME
$date = Get-Date -Format "yyyyMMdd_HHmmss"
$dest = "$destRoot\$hostname`_$date"

New-Item -ItemType Directory -Path $dest -Force | Out-Null

Write-Host "[*] Collecting browser artifacts..."
Write-Host "[*] Output: $dest"
Write-Host ""

# Get user profiles
$users = Get-ChildItem C:\Users -Directory | Where-Object {
    $_.Name -notmatch "Public|Default|All Users"
}

function Copy-Artifact {
    param ($source, $target)

    if (Test-Path $source) {
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        robocopy $source $target /E /R:0 /W:0 /COPY:DAT /DCOPY:T > $null
    }
}

foreach ($user in $users) {

    $u = $user.Name
    Write-Host "[+] Processing user: $u"

    $base = "$dest\$u"
    New-Item -ItemType Directory -Path $base -Force | Out-Null

    # ======================
    # CHROME
    # ======================
    $chromePath = "C:\Users\$u\AppData\Local\Google\Chrome\User Data"

    if (Test-Path $chromePath) {
        Write-Host "   - Chrome found"
        $profiles = Get-ChildItem $chromePath -Directory | Where-Object { $_.Name -match "Default|Profile" }

        foreach ($p in $profiles) {
            $pName = $p.Name
            $target = "$base\Chrome\$pName"

            Copy-Artifact "$chromePath\$pName\History" $target
            Copy-Artifact "$chromePath\$pName\Cookies" $target
            Copy-Artifact "$chromePath\$pName\Login Data" $target
            Copy-Artifact "$chromePath\$pName\Web Data" $target
            Copy-Artifact "$chromePath\$pName\Favicons" $target
            Copy-Artifact "$chromePath\$pName\Current Session" $target
            Copy-Artifact "$chromePath\$pName\Last Session" $target
            Copy-Artifact "$chromePath\$pName\Extensions" "$target\Extensions"
            Copy-Artifact "$chromePath\$pName\Cache" "$target\Cache"
        }
    }

    # ======================
    # EDGE
    # ======================
    $edgePath = "C:\Users\$u\AppData\Local\Microsoft\Edge\User Data"

    if (Test-Path $edgePath) {
        Write-Host "   - Edge found"
        $profiles = Get-ChildItem $edgePath -Directory | Where-Object { $_.Name -match "Default|Profile" }

        foreach ($p in $profiles) {
            $pName = $p.Name
            $target = "$base\Edge\$pName"

            Copy-Artifact "$edgePath\$pName\History" $target
            Copy-Artifact "$edgePath\$pName\Cookies" $target
            Copy-Artifact "$edgePath\$pName\Login Data" $target
            Copy-Artifact "$edgePath\$pName\Web Data" $target
            Copy-Artifact "$edgePath\$pName\Extensions" "$target\Extensions"
            Copy-Artifact "$edgePath\$pName\Cache" "$target\Cache"
        }
    }

    # ======================
    # FIREFOX
    # ======================
    $ffPath = "C:\Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles"

    if (Test-Path $ffPath) {
        Write-Host "   - Firefox found"
        $profiles = Get-ChildItem $ffPath -Directory

        foreach ($p in $profiles) {
            $pName = $p.Name
            $target = "$base\Firefox\$pName"

            Copy-Artifact "$ffPath\$pName\places.sqlite" $target
            Copy-Artifact "$ffPath\$pName\cookies.sqlite" $target
            Copy-Artifact "$ffPath\$pName\formhistory.sqlite" $target
            Copy-Artifact "$ffPath\$pName\logins.json" $target
            Copy-Artifact "$ffPath\$pName\key4.db" $target
            Copy-Artifact "$ffPath\$pName\sessionstore.jsonlz4" $target
            Copy-Artifact "$ffPath\$pName\extensions.json" $target
            Copy-Artifact "$ffPath\$pName\extensions" "$target\Extensions"
            Copy-Artifact "$ffPath\$pName\cache2" "$target\Cache"
        }
    }

    Write-Host ""
}

Write-Host "[✓] Collection complete!"
Write-Host "[✓] Saved to: $dest"
```
