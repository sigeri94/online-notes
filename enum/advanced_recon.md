# Advanced Recon Automation

Automated reconnaissance workflow for bug bounty / penetration testing using **Amass, Subfinder, Gau, Waybackurls, Hakrawler, and Nuclei**.

---

## 1. Overview

This script performs end‑to‑end reconnaissance:

1. Passive subdomain enumeration
2. URL discovery from historical sources
3. Crawling discovered URLs
4. Automated vulnerability scanning using Nuclei

All results are stored in a structured output directory for easy analysis.

---

## 2. Requirements

Make sure the following tools are installed and available in `$PATH`:

- `amass`
- `subfinder`
- `gau`
- `waybackurls`
- `hakrawler`
- `nuclei`

Recommended environment:
- Kali Linux / Parrot OS
- Go-based tools updated to latest versions

---

## 3. Script: `advanced_recon.sh`

```bash
#!/bin/bash

DOMAIN=$1
OUTPUT_DIR="recon_results"

if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

mkdir -p $OUTPUT_DIR

echo "[+] Running Amass..."
amass enum -passive -d $DOMAIN -o $OUTPUT_DIR/amass_results.txt

echo "[+] Running Subfinder..."
subfinder -d $DOMAIN -silent -o $OUTPUT_DIR/subfinder_results.txt

echo "[+] Consolidating Subdomains..."
cat $OUTPUT_DIR/amass_results.txt \
    $OUTPUT_DIR/subfinder_results.txt | sort -u > $OUTPUT_DIR/subdomains.txt

echo "[+] Extracting URLs with Gau and Waybackurls..."
cat $OUTPUT_DIR/subdomains.txt | gau > $OUTPUT_DIR/gau_results.txt
cat $OUTPUT_DIR/subdomains.txt | waybackurls > $OUTPUT_DIR/wayback_results.txt

cat $OUTPUT_DIR/gau_results.txt \
    $OUTPUT_DIR/wayback_results.txt | sort -u > $OUTPUT_DIR/urls.txt

echo "[+] Crawling URLs with Hakrawler..."
cat $OUTPUT_DIR/urls.txt | hakrawler -d 2 -subs -u -t 50 > $OUTPUT_DIR/crawled_urls.txt

echo "[+] Running Nuclei on Subdomains..."
nuclei -l $OUTPUT_DIR/subdomains.txt \
  -t /home/kali/santi/nuclei-templates/ \
  -rl 150 -c 50 \
  -o $OUTPUT_DIR/nuclei_subdomain_results.txt

echo "[+] Running Nuclei on URLs..."
nuclei -l $OUTPUT_DIR/crawled_urls.txt \
  -t /home/kali/santi/nuclei-templates/ \
  -rl 150 -c 50 \
  -o $OUTPUT_DIR/nuclei_url_results.txt

echo "[+] Recon Workflow Completed. Results saved in $OUTPUT_DIR."
```

---

## 4. Output Structure

```
recon_results/
├── amass_results.txt
├── subfinder_results.txt
├── subdomains.txt
├── gau_results.txt
├── wayback_results.txt
├── urls.txt
├── crawled_urls.txt
├── nuclei_subdomain_results.txt
└── nuclei_url_results.txt
```

---

## 5. Usage

### Make Script Executable

```bash
chmod +x advanced_recon.sh
```

### Run Recon

```bash
./advanced_recon.sh hackeron.com
```

> ⚠️ Do **not** include protocol (`http://` or `https://`).

---

## 6. Advanced Nuclei Usage

### 6.1 Run All Templates

Scan using the entire Nuclei template set:

```bash
nuclei -l subdomains.txt \
  -t /home/kali/santi/nuclei-templates/ \
  -o all_results.txt
```

---

### 6.2 Scan by Severity (Critical & High Only)

```bash
nuclei -l subdomains.txt \
  -severity critical,high \
  -o critical_results.txt
```

---

### 6.3 Performance Tuning

Recommended flags for large scopes:

- `-rl 150` → Rate limit
- `-c 50`   → Concurrent templates
- `-timeout 10`
- `-retries 1`

Example:

```bash
nuclei -l subdomains.txt \
  -severity critical,high \
  -rl 100 -c 25 \
  -timeout 10 \
  -o tuned_results.txt
```

---

## 7. Notes & Best Practices

- Always verify findings manually before reporting
- Respect program scope and rate limits
- Use `notify` or `nuclei -json` for automation pipelines
- Store recon data for delta comparison

---

## 8. Disclaimer

This tool is intended **only** for authorized security testing, bug bounty programs, and learning purposes.

Unauthorized use against systems you do not own or have permission to test is illegal.

---

Happy hunting ☠️

