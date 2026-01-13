# Windows Event Log Extraction – Oracle & Shell Core

## 1. Persiapan Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
````
---

## 2. Ekstraksi Oracle Event Log (Application.evtx)

Oracle di Windows **tidak menulis data ke field `Message`**, melainkan ke
`EventData`. Oleh karena itu, data Oracle diambil dari `Properties[0].Value`.

```powershell
Get-WinEvent -Path '.\Application.evtx' |
Where-Object { $_.ProviderName -like "Oracle*" } |
Select-Object TimeCreated, Id, ProviderName,
    @{Name="OracleData";Expression={$_.Properties[0].Value}} |
Export-Csv oracle_events.csv -NoTypeInformation -Encoding UTF8
```

---

## 3. Ekstraksi Shell Core Operational Log

```powershell
Get-WinEvent -Path '.\Microsoft-Windows-Shell-Core%4Operational.evtx' |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Export-Csv -Path ".\shell.csv" -NoTypeInformation
```
---
```powershell
Get-WinEvent -Path '.\System.evtx' | Select-Object TimeCreated, Id, ProviderName,Message| Sort-Object TimeCreated |Export-Csv -Path ".\system.csv" -NoTypeInformation

Get-WinEvent -Path '.\Application.evtx' | Select-Object TimeCreated, Id, ProviderName,Message| Sort-Object TimeCreated |Export-Csv -Path ".\app.csv" -NoTypeInformation
```

## logon

```powershell
Get-WinEvent -FilterHashtable @{ Path='.\Security.evtx'; Id=4624 } |
Where-Object { $_.Properties[8].Value -in 2,3 } |
Select TimeCreated,
@{Name='LogonType';Expression={$_.Properties[8].Value}},
@{Name='Account';Expression={$_.Properties[5].Value}},
@{Name='SourceIP';Expression={$_.Properties[18].Value}}

```
