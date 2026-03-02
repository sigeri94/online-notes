# Ultimate Wordlist Cleaner - wfuzz Directory Fuzzing Pipeline

## 🎯 **3-Stage Cleaning Pipeline**

### **Stage 1: Smart Filter (Basic Cleanup)**
```bash
grep -v '^#' /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt | \
grep -v '^$' | \
tr '[:upper:]' '[:lower:]' | \
grep -E '^[a-z][a-z0-9-]{2,18}[a-z0-9]$' | \
grep -v -E '^t[0-9]+$' | \
grep -v -E '^nt[0-9a-z]+$' | \
awk 'length >= 5 && length <= 20' | \
sort -u > smart_wordlist.txt
```

| Step | Filter | ❌ Hapus | ✅ Tetap |
|------|--------|----------|----------|
| 1 | `grep -v '^#'` | `# komentar` | `file-upload` |
| 2 | `grep -v '^$'` | baris kosong | semua |
| 3 | `tr '[:upper:]' '[:lower:]'` | `Admin` → `admin` | semua |
| 4 | `^[a-z][a-z0-9-]{2,18}[a-z0-9]$` | `123`, `_abc` | `file-upload`, `api-v1` |
| 5 | `^t[0-9]+$` | `t15540` | semua |
| 6 | `^nt[0-9a-z]+$` | `nt4jw2kd` | semua |
| 7 | `length 5-20` | terlalu pendek/panjang | `admin-panel` |

### **Stage 2: ID Pattern Killer**
```bash
grep -E '^[a-z]{2,}' smart_wordlist.txt | \
grep -v -E '^(a[0-9]+|aa[0-9]+|[a-z]{2}[0-9]{2,}|.*[0-9]{4,})' | \
grep -E '[a-z]{3,}' | \
sort -u > smart_wordlist2.txt
```

| Filter | ❌ Contoh Dihapus |
|--------|-------------------|
| `^[a-z]{2,}` | `1abc`, `a1bc` |
| `a[0-9]+` | `a001`, `a034` |
| `aa[0-9]+` | `aa080299`, `aa11` |
| `[a-z]{2}[0-9]{2,}` | `ab12`, `cd123` |
| `.*[0-9]{4,}` | `test1234`, `file2023` |

### **Stage 3: Repeated Letter Killer**
```bash
grep -v '^#' smart_wordlist2.txt | \
tr '[:upper:]' '[:lower:]' | \
grep -E '^[a-z]{2,}' | \
grep -v -E '(.)\1{1,}' | \
awk '!/^(a+|[a-z]a+)$/ && length >= 4' | \
sort -u > smart_wordlist3.txt
```

| Filter | ❌ Contoh Dihapus |
|--------|-------------------|
| `(.)\1{1,}` | `aaa`, `bbbbb`, `aaaaaaaac` |
| `!/^(a+|[a-z]a+)$/` | `aaa`, `baaaa`, `kaaaaa` |
| `length >= 4` | `ab`, `cd` |
