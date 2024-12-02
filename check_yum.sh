#!/usr/bin/env bash

echo "Repository GPG and Enabled Status:"
echo "----------------------------------"

find /etc/yum.repos.d/ -type f -name "*.repo" | while read -r repo_file; do
    awk '
    /^\[.*\]/ { repo=$0 }
    /^\s*enabled\s*=\s*1/ { enabled=1 }
    /^\s*gpgcheck\s*=\s*1/ { gpgcheck=1 }
    { if (repo && enabled == 1) {
        if (gpgcheck == 1)
            print "Repository: " repo "\n  Enabled: Yes\n  GPG Check: Yes\n"
        else
            print "Repository: " repo "\n  Enabled: Yes\n  GPG Check: No\n"
        repo=""; enabled=0; gpgcheck=0;
    }}
    END { if (repo && enabled == 1) {
        print "Repository: " repo "\n  Enabled: Yes\n  GPG Check: Unknown\n"
    }}
    ' "$repo_file"
done
