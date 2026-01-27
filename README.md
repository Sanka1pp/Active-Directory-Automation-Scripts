# Active-Directory-Automation-Scripts
Schema-first Active Directory identity classification. Identify before you attack.

# SchemaFirst

**Identify the object before you touch the domain.**

SchemaFirst is a lightweight Active Directory identity profiler that answers **one critical question** before any attack, enumeration, or path analysis:

> **What does Active Directory say this identity *is* at the schema level?**

This tool exists to prevent incorrect assumptions, wasted time, and invalid attack paths during Active Directory security assessments.

---

## Why SchemaFirst Exists

Most Active Directory failures don’t happen because of missing tools —  
they happen because of **incorrect mental models**.

Common mistakes:
- Treating any `svc_*` user as a service account
- Attempting Kerberoasting where no service identity exists
- Jumping to BloodHound before understanding identity semantics
- Confusing naming conventions with schema truth

**SchemaFirst enforces discipline.**

---

## What SchemaFirst Does

SchemaFirst uses **authoritative LDAP queries** (with secondary schema consistency checks) to:

- Identify the **true object class** of an AD identity
- Determine whether it is a **service-backed identity**
- Infer the **intended operational use** of the account
- Eliminate entire attack classes early
- Point the operator toward the **correct next enumeration axis**

---

## What SchemaFirst Is NOT

- ❌ Not BloodHound  
- ❌ Not an attack-path visualizer  
- ❌ Not an exploitation framework  
- ❌ Not a Kerberoasting helper  

SchemaFirst is the **first step**, not the whole engagement.

---

## When to Use SchemaFirst

Use SchemaFirst immediately after obtaining:
- Any valid domain username + password
- Initial access credentials
- Credentials from backups, shares, configs, or memory

If you haven’t classified the identity, **you are not ready to attack it**.

---

## Installation

### Requirements
- Python 3.8+
- `ldapsearch`
- `bloodyAD` (optional, for secondary verification)
- Linux / Kali / Parrot recommended

### Clone
```bash
git clone https://github.com/Sanka1pp/Active-Directory-Automation-Scripts/blob/main/schemafirst.py
cd schemafirst
python3 schemafirst.py
```

You will be prompted for:
- Domain Controller IP / hostname
- AD domain name (e.g. domain.local)

---

## Expected Output
```
[IDENTITY SUMMARY]
+------------------------------+------------------------------+
| ATTRIBUTE                    | VALUE                        |
+------------------------------+------------------------------+
| Account                      | sqlsvc                       |
| Schema Object                | Standard AD User             |
| Service Identity             | NO                           |
+------------------------------+------------------------------+

[VERIFICATION (MOAT)]
Primary Tool   : ldapsearch (authoritative)
Secondary Tool : bloodyAD (schema-consistent)

[INFERRED INTENDED USE]
- Password does not expire (automation / service-like usage)

[OPERATOR DECISION]
Kerberos Attacks     : NOT APPLICABLE
Primary Risk Surface : Permissions / trust abuse

[NEXT ENUMERATION AXIS]
- LDAP write permissions
- Computer object control (RBCD)
- Group-based delegated trust

- Username
- Password (hidden input)
```
