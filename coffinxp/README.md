repo script coffinxp
| Tool/Script              | Purpose                                                      | Type              |
| ------------------------ | ------------------------------------------------------------ | ----------------- |
| `subfinder`              | Subdomain enumeration (API integrations, recursive search)   | Recon Tool        |
| `assetfinder`            | Passive subdomain enumeration                                | Recon Tool        |
| `findomain`              | Fast subdomain discovery                                     | Recon Tool        |
| `amass`                  | Passive + active subdomain & asset discovery (intel module)  | Recon Tool        |
| `crt.sh` (curl+jq)       | Fetch subdomains from Certificate Transparency logs          | Public Source     |
| `Wayback Machine` (curl) | Extract historical subdomains and URLs                       | Public Source     |
| `virustotal` (curl)      | Fetch domain siblings / IPs from VirusTotal API              | Public Source/API |
| `github-subdomains`      | Extract subdomains from GitHub repositories                  | Recon Tool        |
| `shosubgo`               | Subdomain discovery using Shodan API                         | Recon Tool        |
| `alterx`                 | Generate subdomain permutations                              | Recon Tool        |
| `dnsx`                   | DNS resolution & validation of subdomains                    | Recon Tool        |
| `ffuf`                   | Subdomain brute force, directory fuzzing, XSS/LFI testing    | Fuzzer            |
| `asnmap`                 | Map ASN to discover IP ranges and related domains            | Recon Tool        |
| `httpx-toolkit`          | Live host detection, probe ports, content-type filtering     | Web Scanner       |
| `aquatone`               | Visual reconnaissance (screenshots of hosts)                 | Recon Tool        |
| `katana`                 | Web crawling & JavaScript discovery                          | Crawler           |
| `hakrawler`              | Lightweight web crawler for endpoints                        | Crawler           |
| `gau`                    | Collect URLs from multiple archives (Wayback, CommonCrawl)   | Recon Tool        |
| `urlfinder`              | Discover URLs from a given domain                            | Recon Tool        |
| `gf` (Gf-Patterns)       | Extract URLs/params based on vuln patterns (XSS, SQLi, etc.) | Filtering Tool    |
| `nuclei`                 | Vulnerability scanner with customizable templates            | Vuln Scanner      |
| `arjun`                  | Discover hidden GET/POST parameters                          | Param Fuzzer      |
| `dirsearch`              | Directory & file brute force discovery                       | Fuzzer            |
| `wpscan`                 | WordPress recon (plugins, themes, users)                     | CMS Scanner       |
| `naabu`                  | Fast port scanning (integrates with Nmap)                    | Network Scanner   |
| `nmap`                   | Port scanning, service detection, vuln scripts               | Network Scanner   |
| `masscan`                | Ultra-fast port scanner                                      | Network Scanner   |
| `uro`                    | URL deduplication / normalization                            | URL Tool          |
| `Gxss`                   | Reflected XSS discovery helper                               | XSS Tool          |
| `dalfox`                 | Advanced XSS scanner & automation                            | XSS Tool          |
| `bxss`                   | Blind XSS testing automation                                 | XSS Tool          |
| `kxss`                   | XSS helper to find reflected params                          | XSS Tool          |
| `qsreplace`              | Replace URL parameters with payloads                         | Fuzzer Utility    |
| `Corsy`                  | Automated CORS misconfiguration scanner                      | Vuln Scanner      |
| `CORScanner`             | CORS misconfiguration detection                              | Vuln Scanner      |
| `subzy`                  | Subdomain takeover detection                                 | Takeover Scanner  |
| `curl` (manual)          | Used throughout for CORS, SSRF, file checks, etc.            | Manual Tool       |
