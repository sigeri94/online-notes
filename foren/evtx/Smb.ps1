'''powershell

$log = "$source\Microsoft-Windows-SMBServer%4Security.evtx"

$start = Get-Date "2025-01-01"
$end   = Get-Date "2026-01-01"

Get-WinEvent -Path $log -ErrorAction SilentlyContinue |
Where-Object {
    $_.Id -eq 5140 -and
    $_.TimeCreated -ge $start -and
    $_.TimeCreated -lt $end
} |
ForEach-Object {

    $xml = [xml]$_.ToXml()

    # Ambil Client IP dari XML
    $addr = ($xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "ClientAddress"}).'#text'

    # fallback jika kosong
    if(!$addr -and $_.Message -match 'Client Address:\s+([\d\.]+)'){
        $addr = $matches[1]
    }

    if(!$addr){ $addr = "UNKNOWN" }

    # Ambil share name
    $share = ($xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "ShareName"}).'#text'
    if(!$share){ $share = "UNKNOWN" }

    [PSCustomObject]@{
        Date      = $_.TimeCreated.ToString("yyyy-MM-dd")
        SourceIP  = $addr
        ShareName = $share
    }
} |
Group-Object Date, SourceIP, ShareName |
Select-Object `
    @{n='Date';e={$_.Name.Split(',')[0]}},
    @{n='SourceIP';e={$_.Name.Split(',')[1]}},
    @{n='ShareName';e={$_.Name.Split(',')[2]}},
    Count |
Sort-Object {[datetime]$_.Date}, SourceIP
'''
