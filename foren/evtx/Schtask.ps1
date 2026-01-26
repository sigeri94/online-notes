$tasksPath = "C:\Windows\System32\Tasks"
$results = @()

Get-ChildItem -Path $tasksPath -Recurse -File | ForEach-Object {

    try {
        [xml]$xml = Get-Content $_.FullName -ErrorAction Stop

        # Namespace handling
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")

        # Creation date
        $created = $xml.SelectSingleNode("//t:RegistrationInfo/t:Date", $ns)
        if (-not $created) { return }

        $createdDate = [datetime]$created.InnerText
        if ($createdDate.Year -ne 2025) { return }

        # Author / User
        $author = $xml.SelectSingleNode("//t:RegistrationInfo/t:Author", $ns)
        if (-not $author) {
            $author = $xml.SelectSingleNode("//t:Principals/t:Principal/t:UserId", $ns)
        }

        # Action
        $exec = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Command", $ns)
        $args = $xml.SelectSingleNode("//t:Actions/t:Exec/t:Arguments", $ns)

        $results += [PSCustomObject]@{
            TaskName     = $_.FullName.Replace($tasksPath + "\", "")
            CreatedDate = $createdDate
            User        = $author.InnerText
            Action      = $exec.InnerText
            Arguments   = if ($args) { $args.InnerText } else { "" }
        }

    } catch {
        # Skip unreadable or malformed XML
    }
}

$results | Sort-Object CreatedDate | Format-Table -AutoSize
