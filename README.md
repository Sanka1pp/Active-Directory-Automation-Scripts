# SchemaFirst

**Schema-first Active Directory identity classification.  
Identify before you attack.**

---

## What Is SchemaFirst?

SchemaFirst is a lightweight Active Directory identity profiler that answers **one critical question** before any attack, enumeration, or path analysis:

> **What does Active Directory say this identity *is* at the schema level?**

It exists to prevent incorrect assumptions, wasted effort, and invalid attack paths during Active Directory security assessments.

SchemaFirst is intentionally narrow in scope — and deliberately opinionated.

---

## Why SchemaFirst Exists

Most Active Directory failures don’t happen because of missing tools.  
They happen because of **incorrect mental models**.

Common mistakes seen in labs, CTFs, and real-world assessments:

- Treating any `svc_*` or `sql*` user as a service account
- Attempting Kerberoasting where no service identity exists
- Jumping to BloodHound before understanding identity semantics
- Confusing naming conventions with schema truth

**Names lie. Groups mislead. Schema does not.**

SchemaFirst enforces this discipline.

---

## What SchemaFirst Does

SchemaFirst uses **authoritative LDAP queries** (with optional secondary validation) to:

- Identify the **true schema object class** of an AD identity
- Determine whether the identity is **service-backed**
- Infer the **intended operational use** of the account
- Eliminate entire attack classes early
- Point the operator toward the **correct next enumeration axis**

This ensures every downstream decision is grounded in evidence.

---

## What SchemaFirst Is NOT

SchemaFirst is intentionally **not**:

- ❌ BloodHound  
- ❌ An attack-path visualizer  
- ❌ An exploitation framework  
- ❌ A Kerberoasting helper  

SchemaFirst is the **first step**, not the entire engagement.

If you skip this step, you risk attacking the wrong surface.

---

## When to Use SchemaFirst

Use SchemaFirst immediately after obtaining:

- Any valid domain username + password
- Initial access credentials
- Credentials from backups, shares, configuration files, or memory

If you haven’t classified the identity, **you are not ready to attack it**.

---

## Installation

### Requirements

- Python 3.8+
- `ldapsearch`
- `bloodyAD` *(optional, used as a secondary consistency check)*
- Linux environment (Kali / Parrot / similar recommended)

---

### Clone the Repository

> **Important:** Clone the repository, not the individual script.

```bash
git clone https://github.com/Sanka1pp/Active-Directory-Automation-Scripts.git
cd Active-Directory-Automation-Scripts
python3 schemafirst.py
```

---

### Example Output

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
```
---


git clone https://github.com/Sanka1pp/Active-Directory-Automation-Scripts.git
cd Active-Directory-Automation-Scripts
