
#HOSTS
```bash
└─$ nxc smb 192.168.56.11 --generate-hosts hosts
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)

└─$ nxc smb 192.168.56.10 --generate-hosts hosts
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)

└─$ cat hosts
192.168.56.11     WINTERFELL.north.sevenkingdoms.local north.sevenkingdoms.local WINTERFELL
192.168.56.10     KINGSLANDING.sevenkingdoms.local sevenkingdoms.local KINGSLANDING
```
```bash
└─$ nxc smb 192.168.56.11 --generate-krb5 krb5.conf
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)

└─$ cat krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = NORTH.SEVENKINGDOMS.LOCAL

[realms]
    NORTH.SEVENKINGDOMS.LOCAL = {
        kdc = winterfell.north.sevenkingdoms.local
        admin_server = winterfell.north.sevenkingdoms.local
        default_domain = north.sevenkingdoms.local
    }

[domain_realm]
    .north.sevenkingdoms.local = NORTH.SEVENKINGDOMS.LOCAL
    north.sevenkingdoms.local = NORTH.SEVENKINGDOMS.LOCAL

└─$ nxc smb 192.168.56.10 --generate-krb5 krb5.conf
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)

└─$ cat krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = SEVENKINGDOMS.LOCAL

[realms]
    SEVENKINGDOMS.LOCAL = {
        kdc = kingslanding.sevenkingdoms.local
        admin_server = kingslanding.sevenkingdoms.local
        default_domain = sevenkingdoms.local
    }

[domain_realm]
    .sevenkingdoms.local = SEVENKINGDOMS.LOCAL
    sevenkingdoms.local = SEVENKINGDOMS.LOCAL
```

#RECON
```bash
sudo netdiscover -r 10.136.69.0/24 | awk '{print $1}'
nxc smb ./hosts.txt -u '' -p '' --shares
nxc smb ./hosts.txt -u 'guest' -p '' - shares
nxc smb ./hosts.txt -u 'anonymous' -p '' - shares

NASIP=10.136.69.10
nxc smb ${NASIP} -u 'guest' -p '' -M spider_plus -o DOWNLOAD_FLAG=True

nxc smb ./hosts.txt -u 'guest' -p '' --users
nxc smb ./hosts.txt -u '' -p '' --users

TARGET_USERNAME=#[fill in the username you discovered in the previous lesson]
TARGET_PASSWORD=#[fill in the password you discovered in the previous lesson]

nxc smb ./hosts.txt -u "${TARGET_USERNAME}" -p "${TARGET_PASSWORD}"

SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\hodor:hodor
SPOOLER     192.168.56.11   445    WINTERFELL       Spooler service enabled
```
