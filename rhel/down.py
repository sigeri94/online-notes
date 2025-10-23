import requests

cert = "/etc/pki/entitlement/5257088692100978896.pem"
key = "/etc/pki/entitlement/5257088692100978896-key.pem"
ca = "/etc/rhsm/ca/redhat-uep.pem"

url = "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os/Packages/c/container-selinux-2.232.1-1.el9.noarch.rpm"
output = "container-selinux-2.232.1-1.el9.noarch.rpm"

with requests.get(url, cert=(cert, key), verify=ca, stream=True) as r:
    r.raise_for_status()
    with open(output, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)

print(f"Downloaded: {output}")


