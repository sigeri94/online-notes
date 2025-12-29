param (
    [Parameter(Mandatory=$true)]
    [string]$EvtxPath
)

if (!(Test-Path $EvtxPath)) {
    Write-Error "File EVTX tidak ditemukan"
    exit
}

$CsvPath = "RDP_Offline_Session_Report.csv"

Write-Host "[*] Parsing EVTX offline: $EvtxPath"

# --- READ ALL EVENTS FROM EVTX ---
$events = Get-WinEvent -Path $EvtxPath | Sort-Object TimeCreated

# --- IP EVENTS (1149) ---
$ipEvents = @()
foreach ($e in $events | Where-Object { $_.Id -eq 1149 }) {

    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    $ipEvents += [PSCustomObject]@{
        Time = $e.TimeCreated
        User = $data["Param1"]
        IP   = $data["Param3"]
    }
}

# --- SESSION TRACKING ---
$sessions = @{}
$output = @()

foreach ($event in $events | Where-Object { $_.Id -in 21,23,24 }) {

    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    $sessionId = $data["SessionID"]
    $user      = $data["User"]
    $time      = $event.TimeCreated

    switch ($event.Id) {

        21 { # LOGON
            $ip = ($ipEvents |
                  Where-Object { $_.User -eq $user -and $_.Time -le $time } |
                  Sort-Object Time -Descending |
                  Select-Object -First 1).IP

            $sessions[$sessionId] = @{
                User  = $user
                Start = $time
                IP    = $ip
            }
        }

        23 { # LOGOFF
            if ($sessions.ContainsKey($sessionId)) {
                $s = $sessions[$sessionId]
                $output += [PSCustomObject]@{
                    User         = $s.User
                    SessionID   = $sessionId
                    ClientIP    = $s.IP
                    StartTime   = $s.Start
                    EndTime     = $time
                    DurationMin = [math]::Round(($time - $s.Start).TotalMinutes,2)
                    EndReason   = "Logoff"
                }
                $sessions.Remove($sessionId)
            }
        }

        24 { # DISCONNECT
            if ($sessions.ContainsKey($sessionId)) {
                $s = $sessions[$sessionId]
                $output += [PSCustomObject]@{
                    User         = $s.User
                    SessionID   = $sessionId
                    ClientIP    = $s.IP
                    StartTime   = $s.Start
                    EndTime     = $time
                    DurationMin = [math]::Round(($time - $s.Start).TotalMinutes,2)
                    EndReason   = "Disconnect"
                }
                $sessions.Remove($sessionId)
            }
        }
    }
}

$output | Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] Report selesai → $CsvPath"
