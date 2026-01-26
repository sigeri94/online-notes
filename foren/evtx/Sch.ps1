$tasksPath = "C:\Windows\System32\Tasks"
$outputXlsx = "$PWD\ScheduledTasks_2025.xlsx"
$results = @()

Get-ChildItem -Path $tasksPath -Recurse -File | ForEach-Object {

    try {
        [xml]$xml = Get-Content $_.FullName -ErrorAction Stop

        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")

        # Created date
        $createdNode = $xml.SelectSingleNode("//t:RegistrationInfo/t:Date", $ns)
        if (-not $createdNode) { return }

        $createdDate = [datetime]$createdNode.InnerText
        if ($createdDate.Year -ne 2025) { return }

        # User
        $authorNode = $xml.SelectSingleNode("//t:RegistrationInfo/t:Author", $ns)
        if (-not $authorNode) {
            $authorNode = $xml.SelectSingleNode("//t:Principals/t:Principal/t:UserId", $ns)
        }

        # Action
        $execNode = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Command", $ns)
        $argsNode = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Arguments", $ns)

        # Last Run
        $lastRunNode = $xml.SelectSingleNode("//t:LastRunTime", $ns)
        $lastRunTime = if ($lastRunNode -and $lastRunNode.InnerText) {
            [datetime]$lastRunNode.InnerText
        } else {
            $null
        }

        $results += [PSCustomObject]@{
            TaskName     = $_.FullName.Replace($tasksPath + "\", "")
            CreatedDate = $createdDate
            LastRunTime = $lastRunTime
            User        = if ($authorNode) { $authorNode.InnerText } else { "Unknown" }
            Action      = if ($execNode) { $execNode.InnerText } else { "" }
            Arguments   = if ($argsNode) { $argsNode.InnerText } else { "" }
        }

    } catch {
        # Skip bad XML
    }
}

# ===== Export to Excel =====
$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$workbook = $excel.Workbooks.Add()
$sheet = $workbook.Worksheets.Item(1)
$sheet.Name = "ScheduledTasks_2025"

# Header
$headers = $results[0].PSObject.Properties.Name
for ($i = 0; $i -lt $headers.Count; $i++) {
    $sheet.Cells.Item(1, $i + 1) = $headers[$i]
    $sheet.Cells.Item(1, $i + 1).Font.Bold = $true
}

# Data
$row = 2
foreach ($r in $results) {
    $col = 1
    foreach ($h in $headers) {
        $sheet.Cells.Item($row, $col) = $r.$h
        $col++
    }
    $row++
}

# Auto-fit columns
$sheet.Columns.AutoFit()

# Save
$workbook.SaveAs($outputXlsx)
$workbook.Close($true)
$excel.Quit()

[System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null

Write-Host "Excel exported to: $outputXlsx"
