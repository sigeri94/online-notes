```bash
grep -v '^#' /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt | \
grep -v '^$' | \
tr '[:upper:]' '[:lower:]' | \
grep -E '^[a-z][a-z0-9-]{2,18}[a-z0-9]$' | \
grep -v -E '^t[0-9]+$' | \
grep -v -E '^nt[0-9a-z]+$' | \
awk 'length >= 4 && length <= 20' | \
sort -u > smart_wordlist.txt

```

```bash
 comm -23 <(sort smart_wordlist.txt) <(sort /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt) > unique_smart_words.txt

```
