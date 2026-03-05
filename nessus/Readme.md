```powershell
# Source - https://stackoverflow.com/a/52578838
# Posted by Isma, modified by community. See post 'Timeline' for change history
# Retrieved 2026-03-05, License - CC BY-SA 4.0

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.7.0/python-3.7.0.exe" -OutFile "c:/temp/python-3.7.0.exe"

c:/temp/python-3.7.0.exe /quiet InstallAllUsers=0 InstallLauncherAllUsers=0 PrependPath=1 Include_test=0

```
