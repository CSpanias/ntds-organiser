# ntds-organiser

A Python-based tool designed to make Active Directory password audits more efficient.

Developed as a Proof of Concept to accompany [Password Audits Part 2: Hash Organisation](https://mollysec.com/posts/password-audits-part-2/).

It automates the post-processing of `secretsdump.py` output and combines NTDS data with BloodHound and Hashcat artefacts and produces clean datasets that are easier to review, crack, and report on.

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
* Map recovered passwords back to users
* Generate clean `username:password` datasets

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

[+] Enabled Accounts  : 422
[+] Disabled Accounts : 39
[+] User Accounts     : 314
[+] Machine Accounts  : 108
[+] NTLM Hashes       : 297
[+] LM Hashes         : 2
[+] Domain Admins     : 7
[+] Mapped Passwords  : 126

[+] Output Directory  : ntds-organiser
```

## Generated Files

### Core Outputs

* `enabled-users.txt` (Enabled user accounts after filtering)
* `domain-admins.txt` (Domain Admin accounts extracted from BloodHound)
* `domain-policy.txt` (Password policy extracted from the domain)
* `ntds-users-clean.txt` (Primary account dataset used for password mapping)
* `ntlm-hashes.txt` (Hashcat-ready NTLM hashes)
* `mapped-passwords.txt` (Final dataset in `username:password` format)

### Conditional Outputs

> Generated only when applicable.

* `lm-users.txt` (Users that have an LM hash)
* `lm-hashes.txt` (Hashcat-ready LM hashes)

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
* ???
