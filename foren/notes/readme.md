[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.13.9/python-3.13.9.exe" -OutFile "c:/foren/python-3.13.9.exe"
c:/foren/python-3.13.9.exe /quiet InstallAllUsers=0 InstallLauncherAllUsers=0 PrependPath=1 Include_test=0

-- chainsaw
donload chainsaw all platform and rules
chainsaw.exe hunt ..\WS\kesha_luddy -r rules -s sigma -m mappings\sigma-event-logs-all.yml --local -o keyshaluddy_chainsaw.txt

-- hayabusa
chainsaw.exe hunt ..\WS\kesha_luddy -r rules -s sigma -m mappings\sigma-event-logs-all.yml --local -o keyshaluddy_chainsaw.txt
