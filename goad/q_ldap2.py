# q_ldap_simple.py

from ldap3 import Server, Connection, ALL, SUBTREE

# === LDAP CONFIG ===
LDAP_HOST = "10.10.11.91"                  # IP of DC
USER_DN = "ken.w@hercules.htb"             # UPN format
PASSWORD = "change*th1s_p@ssw()rd!!"       # Password
BASE_DN = "DC=hercules,DC=htb"

# === Connect to server ===
server = Server(LDAP_HOST, get_info=ALL)

# Simple Bind (username + password)
conn = Connection(
    server,
    user=USER_DN,
    password=PASSWORD,
    authentication="SIMPLE",
    auto_bind=True
)

print("[+] Bind successful!")

# === LDAP Query ===
conn.search(
    search_base=BASE_DN,
    search_filter="(objectClass=person)",
    search_scope=SUBTREE,
    attributes=[
        "cn",
        "sAMAccountName",
        "memberOf"
    ]
)

# === Print Results ===
for entry in conn.entries:
    print("────────────────────────")
    print(f"CN: {entry.cn}")
    print(f"sAMAccountName: {entry.sAMAccountName}")

    if hasattr(entry, "memberOf"):
        print("Groups:")
        for g in entry.memberOf:
            print(f"  - {g}")

conn.unbind()
