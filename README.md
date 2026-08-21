# ntds-organiser

> [!WARNING]
> Deprecated and kept only as a PoC for the article, see [`password-audit`](https://github.com/CSpanias/password-audit) for the actual tool.

A Python-based tool designed to make Active Directory password audits more efficient.

Developed as a Proof of Concept to accompany [Password Audits Part 2: Hash Organisation](https://mollysec.com/posts/password-audits-part-2/).

It automates the post-processing of `secretsdump.py` output and combines NTDS data with BloodHound and Hashcat artefacts and produces clean datasets that are easier to review, crack, and report on.

## Workflow

```markdown
NTDS
 ↓
Parse accounts
 ↓
Filter enabled users
 ↓
Extract NTLM and LM hashes
 ↓
(Optional) BloodHound enrichment
 ↓
(Optional) Password mapping
 ↓
LM analysis
 ↓
Generate reporting and spraying artefacts
```

## Installation

Recommended (uv):

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install ntds-organiser via UV
uv tool install git+https://github.com/CSpanias/ntds-organiser

# Verify installation
ntds-organiser -h

# Update
uv tool upgrade ntds-organiser
```

Clone locally:

> Note: Python 3 must be installed and available in your PATH.

```bash
# Clone the repository
git clone https://github.com/CSpanias/ntds-organiser /opt/ntds-organiser

# Make the script executable
chmod +x /opt/ntds-organiser/ntds_audit.py

# Create a symbolic link
sudo ln -s /opt/ntds-organiser/ntds_audit.py /usr/local/bin/ntds-organiser

# Verify installation
ntds-organiser -h
```

## Features

The tool follows the same workflow typically used during an Active Directory password audit.

### NTDS Processing

* Parse `secretsdump.py` NTDS output
* Separate enabled and disabled accounts
* Identify machine accounts
* Filter testing accounts
* Extract NTLM hashes
* Detect and extract LM hashes
  
### BloodHound Integration

* Parse BloodHound ZIP exports directly
* Automatically extract Domain Admins
* Automatically extract domain password policy
* Remove testing accounts from generated datasets

### Password Mapping

* Parse Hashcat potfiles
* Map recovered NTLM and LM passwords back to users
* Generate clean `username:password` datasets

### LM Hash Analysis

* Automatically identify Domain Admins with cracked LM passwords
* Generate capitalization candidates from recovered LM passwords

## Usage

```bash
# Organise NTDS
ntds-organiser -n mollysec.com.ntds

# Filter Testing Accounts
ntds-organiser -n mollysec.com.ntds -f testing-acc-1,testing-acc-2

# Include BloodHound Data
ntds-organiser -n mollysec.com.ntds -b bloodhound.zip

# Map Recovered Passwords
ntds-organiser -n mollysec.com.ntds -p hashcat.potfile

# LM Analysis Workflow
ntds-organiser -n mollysec.com.ntds -b bloodhound.zip -p lm.potfile

# Full Workflow
ntds-organiser -n mollysec.com.ntds -b bloodhound.zip -p hashcat.potfile -f testing-acc-1,testing-acc-2
```

## Example Output

```bash
$ ntds-organiser -n mollysec.com.ntds -b bloodhound.zip -p company.potfile -f testing-acc-1,testing-acc-2

[*] NTDS Organiser v1.0

[!] Filtered Accounts (2)
    - MOLLYSEC\testing-acc-1
    - MOLLYSEC\testing-acc-2

[+] Enabled Accounts     : 422
[+] Disabled Accounts    : 39
[+] User Accounts        : 314
[+] Machine Accounts     : 108
[+] NTLM Hashes          : 297
[+] LM Hashes            : 5
[+] Domain Admins        : 7
[+] Mapped Passwords     : 126
[+] Mapped LM Passwords  : 4
[+] LM Domain Admins     : 1
[+] LM DA Candidates     : 256
[+] Company Words        : 10

[+] Output Directory     : ntds-organiser
```

## Generated Files

### Core Outputs

* `enabled-users.txt` (Enabled user accounts after filtering)
* `domain-admins.txt` (Domain Admin accounts extracted from BloodHound)
* `domain-policy.txt` (Password policy extracted from the domain)
* `ntds-users-clean.txt` (Primary account dataset used for password mapping)
* `ntlm-hashes.txt` (Hashcat-ready NTLM hashes)
* `company-words.txt` (Domain related words)
* `mapped-passwords.txt` (Final dataset in `username:password` format)

### Conditional Outputs

> Generated only when LM hashes are present and recovered.

* `lm-users.txt` (Accounts containing LM hashes)
* `lm-hashes.txt` (Unique LM hashes suitable for Hashcat)
* `mapped-lm-passwords.txt` (Recovered LM passwords mapped back to users)
* `lm-das.txt` (Domain Admin accounts that have recovered LM passwords)
* `lm-da-candidates.txt` (Capitalization permutations generated from Domain Admin LM passwords)

### Audit Artefacts

> Generated to assist troubleshooting and validation.

* `.ntds-enabled.txt` (All enabled accounts)
* `.ntds-disabled.txt` (All disabled accounts)
* `.ntds-machines.txt` (Machine accounts removed from analysis)
* `.testing-accounts.txt` (Accounts excluded via the filtering option `-f`)

## Requirements

* Python 3 (Core)
* BloodHound ZIP exports (optional)
* Hashcat potfiles (optional)

## Roadmap
* Support additional privileged groups (Enterprise Admins, Account Operators, DNS Admins, etc.)
