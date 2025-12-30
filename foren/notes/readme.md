# Forensics Tooling Setup & Usage

This README documents the setup of Python and the usage of several forensic analysis tools against Windows event logs.

## Prerequisites

* Windows system
* PowerShell
* Internet access to download required tools

## Python Installation (PowerShell)

Download and silently install Python 3.13.9 for the current user, with Python added to `PATH`.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest `
  -Uri "https://www.python.org/ftp/python/3.13.9/python-3.13.9.exe" `
  -OutFile "C:\foren\python-3.13.9.exe"

C:\foren\python-3.13.9.exe /quiet `
  InstallAllUsers=0 `
  InstallLauncherAllUsers=0 `
  PrependPath=1 `
  Include_test=0
```

## Chainsaw

### Description

Chainsaw is used to hunt Windows event logs using Sigma rules.

### Setup

* Download **Chainsaw** for all required platforms
* Download **Sigma rules**
* Ensure mappings are available

### Usage

```powershell
chainsaw.exe hunt "..\WS\kesha_luddy" `
  -r rules `
  -s sigma `
  -m mappings\sigma-event-logs-all.yml `
  --local `
  -o keyshaluddy_chainsaw.txt
```


## Hayabusa

### Description

Hayabusa is used to generate CSV timelines and HTML reports from Windows event logs.

### Usage

```powershell
hayabusa.exe csv-timeline `
  -d "..\WS\kesha_luddy" `
  -H luddy_hayabusa.html `
  -o luddy_hayabusa.csv
```


## DeepBlue

### Description

DeepBlueCLI analyzes Windows event logs for suspicious activity.

### Usage

```powershell
Get-ChildItem "..\WS\kesha_luddy" -Recurse -Filter "*.evtx" |
ForEach-Object {
    .\DeepBlue.ps1 -File $_.FullName
} >> luddy_deepblue.txt
```

