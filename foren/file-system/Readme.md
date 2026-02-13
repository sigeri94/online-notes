```powershell
Get-ChildItem "F:\users" -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime, Length | Sort-Object CreationTime

Get-ChildItem "F:\Windows\system32\tasks" -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime, Length | Sort-Object CreationTime

Get-Date "12/04/2025"; $end = $start.AddDays(1) ; Get-ChildItem "F:\Users" -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -ge $start -and $_.CreationTime -lt $end }

$start = Get-Date "12/03/2025";
$end   = $start.AddDays(1);
Get-ChildItem "F:\" -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -ge $start -and $_.CreationTime -lt $end } | Select-Object FullName, CreationTime, LastWriteTime, Length | Sort-Object CreationTime | Export-Csv "C:\Users\batman\Desktop\analisa-all-03122025.csv" -NoTypeInformation -Encoding UTF8

```
