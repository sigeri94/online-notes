## baca hasil VA jika packages ada di Extended support maka url harus di ubah
url = "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os/Packages/c/container-selinux-2.232.1-1.el9.noarch.rpm"

## ubah dist menjadi eus dan release menjadi versi nya (9.4)
url = "https://cdn.redhat.com/content/eus/rhel9/9.4/x86_64/appstream/os/Packages/l/libxslt-1.1.34-14.el9_4.x86_64.rpm"

## gunakan curl untuk erifikasi jika hasil 404
curl --cert /tmp/3023925816861647773.pem --key /tmp/3023925816861647773-key.pem --cacert /tmp/redhat-uep.pem \
     https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os/Packages/l/
