# SAMR & LDAP Password Policy Checker

## Overview

This tool connects to a Windows domain controller over SMB and LDAP to retrieve and display password policy information using different authentication methods (Basic, NTLM hash, Kerberos, Anonymous). It leverages Impacket and ldap3 libraries to query SAMR named pipes and LDAP for domain policies.


---

## TODO

- [ ] **Implement SSL (LDAPS) support for secure LDAP communication**
- [ ] Add option to export results to JSON.

---

## Features

- Connect to Windows SMB service on port 445
- Authenticate using:
  - Basic username/password
  - NTLM hashes (Pass-the-Hash)
  - Kerberos tickets
  - Anonymous LDAP bind
- Query SAMR named pipe for user/group/security policy info
- Retrieve domain password policies via LDAP
- Display fine-grained password policies (FGPP) if configured
- Nicely formatted output of password policy attributes (e.g., min/max password age, lockout threshold, complexity)

---

## How SMB Retrieves SAMR Info

The **Security Account Manager Remote Protocol (SAMR)** is a Microsoft RPC interface exposed over SMB named pipes (specifically `\\PIPE\\samr`) on port 445.

Here is how the tool uses SMB to retrieve SAMR data:

1. **Establish SMB Connection:** The script opens a connection to the target Windows host on TCP port 445 using the SMB protocol.

2. **Authenticate:** Using the provided credentials (username/password, NTLM hashes, or Kerberos), it performs SMB authentication. This can include NTLM or Kerberos authentication mechanisms.

3. **Access SAMR Named Pipe:** Once authenticated, the script opens the `\\PIPE\\samr` named pipe, which exposes the SAMR RPC interface.

4. **RPC Communication:** Using Impacket's SAMR client classes, the script initiates remote procedure calls to query domain and user account information.

5. **Query Password Policy:** Through SAMR RPC calls, it requests domain password policy data, user/group details, and security policy information.

6. **Parse and Display:** The raw SAMR data returned is parsed and formatted to show password requirements such as minimum/maximum password age, lockout thresholds, complexity requirements, etc.

This method allows querying Windows password policy even if standard LDAP queries are restricted or limited.

---
![image](https://github.com/user-attachments/assets/33922009-b7da-4835-805f-96f9357fe006)


---

## Usage

```bash
# Basic authentication (username + password)
python script.py -t <target_ip> -d <domain> -u <username> -p <password>

# Pass-the-hash authentication
python script.py -t <target_ip> -d <domain> -u <username> --hashes <LMHASH>:<NTHASH>

# Kerberos authentication
python script.py -t <target_ip> -d <domain> -u <username> -p <password> --auth KERBEROS

# Anonymous LDAP bind
python script.py -t <target_ip> -d <domain> -u '' -p '' --auth ANONYMOUS
