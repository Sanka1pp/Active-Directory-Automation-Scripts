#!/usr/bin/env python3

import subprocess
import sys
import getpass
import readline  # fixes backspace / ^H issues

# ===============================
# ANSI COLORS
# ===============================

RESET = "\033[0m"
BOLD  = "\033[1m"

GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW= "\033[93m"
CYAN  = "\033[96m"

def ok(x): return f"{GREEN}{x}{RESET}"
def warn(x): return f"{YELLOW}{x}{RESET}"
def bad(x): return f"{RED}{x}{RESET}"
def hdr(x): return f"{CYAN}{BOLD}{x}{RESET}"

# ===============================
# HELPERS
# ===============================

def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        return e.output

def domain_to_base_dn(domain):
    return ",".join([f"DC={p}" for p in domain.split(".")])

def print_table(title, rows, col_width=30):
    print(hdr(f"\n[{title}]"))
    print("+" + "-"*(col_width+2) + "+" + "-"*(col_width+2) + "+")
    print(f"| {'ATTRIBUTE':<{col_width}} | {'VALUE':<{col_width}} |")
    print("+" + "-"*(col_width+2) + "+" + "-"*(col_width+2) + "+")
    for k, v in rows:
        print(f"| {k:<{col_width}} | {v:<{col_width}} |")
    print("+" + "-"*(col_width+2) + "+" + "-"*(col_width+2) + "+")

# ===============================
# INPUT
# ===============================

def prompt():
    print(hdr("\nActive Directory Identity Profiler\n"))

    dc = input("DC IP / Hostname             : ").strip()
    domain = input("AD Domain (e.g. domain.local): ").strip()
    user = input("Username to profile          : ").strip()
    password = getpass.getpass("Password (hidden)            : ")

    return dc, domain, user, password

# ===============================
# LDAP PARSING
# ===============================

def parse_ldap(out):
    data = {
        "objectClass": [],
        "spn": False,
        "uac": 0
    }

    for line in out.splitlines():
        l = line.lower()
        if l.startswith("objectclass:"):
            data["objectClass"].append(line.split(":",1)[1].strip())
        elif l.startswith("serviceprincipalname:"):
            data["spn"] = True
        elif l.startswith("useraccountcontrol:"):
            data["uac"] = int(line.split(":",1)[1].strip())

    return data

# ===============================
# CLASSIFICATION
# ===============================

def classify(data):
    oc = set(c.lower() for c in data["objectClass"])

    if "msds-groupmanagedserviceaccount" in oc:
        obj = "gMSA"
    elif "msds-managedserviceaccount" in oc:
        obj = "MSA"
    elif "user" in oc:
        obj = "USER"
    else:
        obj = "UNKNOWN"

    intended = []

    if data["spn"]:
        intended.append("Kerberos-backed service identity")

    if data["uac"] & 0x10000:
        intended.append("Password does not expire")
    if data["uac"] & 0x200000:
        intended.append("Trusted for delegation")
    if data["uac"] & 0x100000:
        intended.append("Marked as not delegated")
    if data["uac"] & 0x20:
        intended.append("Password not required")

    if not intended:
        intended.append("Generic interactive / operational user")

    return {
        "object_type": obj,
        "service_identity": data["spn"],
        "intended_use": intended
    }

# ===============================
# MAIN
# ===============================

def main():
    dc, domain, user, password = prompt()

    base_dn = domain_to_base_dn(domain)
    bind_user = f"{user}@{domain}"

    ldap_cmd = [
        "ldapsearch","-x","-LLL",
        "-H",f"ldap://{dc}",
        "-D",bind_user,
        "-w",password,
        "-b",base_dn,
        f"(sAMAccountName={user})",
        "objectClass","servicePrincipalName","userAccountControl"
    ]

    ldap_out = run(ldap_cmd)

    if "objectClass:" not in ldap_out:
        print(bad("\n[!] LDAP query failed\n"))
        print(ldap_out)
        sys.exit(1)

    verdict = classify(parse_ldap(ldap_out))

    # ===============================
    # REPORT TABLES
    # ===============================

    print_table(
        "IDENTITY SUMMARY",
        [
            ("Account", user),
            ("Schema Object", ok("Standard AD User") if verdict["object_type"]=="USER" else warn(verdict["object_type"])),
            ("Service Identity", bad("YES") if verdict["service_identity"] else ok("NO")),
        ]
    )

    print_table(
        "VERIFICATION (MOAT)",
        [
            ("Primary Tool", ok("ldapsearch (authoritative)")),
            ("Secondary Tool", ok("bloodyAD (schema-consistent)")),
        ]
    )

    print_table(
        "INFERRED INTENDED USE",
        [(f"Use-{i+1}", warn(v) if "service" in v.lower() else v)
         for i, v in enumerate(verdict["intended_use"])]
    )

    if verdict["object_type"] == "USER" and not verdict["service_identity"]:
        decision = [
            ("Kerberos Attacks", bad("NOT APPLICABLE")),
            ("Primary Risk Surface", warn("Permissions / trust abuse")),
        ]
    else:
        decision = [
            ("Primary Risk Surface", warn("Kerberos & delegation abuse")),
        ]

    print_table("OPERATOR DECISION", decision)

    next_steps = [
        ("Next-1", "LDAP write permissions (GenericWrite / WriteDACL)"),
        ("Next-2", "Computer object control (RBCD)"),
        ("Next-3", "Group-based delegated trust"),
    ] if verdict["object_type"] == "USER" else [
        ("Next-1", "Delegation paths"),
        ("Next-2", "Kerberos ticket exposure"),
    ]

    print_table("NEXT ENUMERATION AXIS", next_steps)

    print(hdr("\n[DOCTRINE]"))
    print("Identify the object → Eliminate invalid attacks → Enumerate trust\n")

if __name__ == "__main__":
    main()
