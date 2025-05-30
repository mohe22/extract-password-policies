from ldap3 import Server, Connection, ALL, NTLM, SASL, GSSAPI
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr
from impacket.smbconnection import SMBConnection
from texttable import Texttable
import argparse
import sys
import datetime

def print_banner(title):
    print("\n" + "="*60)
    print(f" {title.center(58)} ")
    print("="*60)

def print_section(title):
    print(f"\n{'-'*30} {title} {'-'*30}\n")

def d2b(a):
    """Convert number to binary string representation"""
    return bin(a)[2:].zfill(8)

def format_time(seconds):
    """Convert seconds to human-readable time format (days, hours, minutes)"""
    if seconds == 0:
        return "0 minutes"
    
    try:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days} day{'s' if days>1 else ''}")
        if hours > 0:
            parts.append(f"{hours} hour{'s' if hours>1 else ''}")
        if minutes > 0 or not parts:
            parts.append(f"{minutes} minute{'s' if minutes>1 else ''}")
            
        return ' '.join(parts)
    except Exception:
        return "Invalid"

def convert(low, high, lockout=False):
    """Convert Windows time format to human readable"""
    if low == 0 and hex(high) == "-0x80000000":
        return "Not Set"
    if low == 0 and high == 0:
        return "None"

    if not lockout:
        # Handle negative values (time intervals)
        if low != 0:
            high = abs(high + 1)
        else:
            high = abs(high)
            low = abs(low)
        total_seconds = (low + (high) * (2**32)) * 1e-7
    else:
        total_seconds = abs(high) * 1e-7

    return format_time(total_seconds)


class LDAP:
    def __init__(self, server_uri, user_dn=None, password=None, auth_method="SIMPLE"):
        self.server = Server(server_uri, get_info=ALL)
        self.user_dn = user_dn
        self.base_dn = None
        self.password = password
        self.conn = None
        self.auth_method = auth_method.upper()
        

    def connect(self):
        try:
            if self.auth_method == "NTLM":
                self.conn = Connection(
                    self.server,
                    user=self.user_dn,
                    password=self.password,
                    authentication=NTLM,
                    auto_bind=True
                )
            elif self.auth_method == "KERBEROS":
                self.conn = Connection(
                    self.server,
                    authentication=SASL,
                    sasl_mechanism=GSSAPI,
                    auto_bind=True
                )
            elif self.auth_method == "ANONYMOUS":
                  self.conn = Connection(
                    self.server,
                    authentication='ANONYMOUS',
                    client_strategy="SYNC",
                    auto_referrals=True,
                    version=3,
                    auto_bind=True,
                    check_names=True,
                    read_only=False,
                    lazy=False,
                    raise_exceptions=False
                )
            else: 
                self.conn = Connection(
                    self.server,
                    user=self.user_dn,
                    password=self.password,
                    auto_bind=True
                )

            self.base_dn = self.conn.server.info.other.get('defaultNamingContext', [None])[0]
            if not self.base_dn:
                print("[-] Failed to retrieve defaultNamingContext")
         
            print("[+] LDAP bind successful")

            return self.conn

        except Exception as e:
            print(f"[-] LDAP bind failed: {e}")
            return None

    def print_domain_policy(self):
        try:
            print_banner("DOMAIN PASSWORD POLICY (LDAP)")
            
            # Get basic domain policy
            domain_policy = self.query(
                '(objectClass=domain)',
                attributes=['minPwdLength', 'maxPwdAge', 'minPwdAge',
                        'lockoutDuration', 'lockoutObservationWindow',
                        'lockoutThreshold', 'pwdProperties']
            )[0]
            
            if domain_policy is None:
                raise("[-] Empty domain policy")
            
            # Print basic policy
            print("\nBasic Password Policy:")
            print(f"  • Minimum password length: {domain_policy.minPwdLength.value}")
            
            # Handle maxPwdAge (special case for "Never")
            max_pwd_age = domain_policy.maxPwdAge.value
            if isinstance(max_pwd_age, datetime.timedelta):
                if max_pwd_age.days == -1 and max_pwd_age.seconds == 0:  # Special value for "Never"
                    print("  • Maximum password age: Never")
                else:
                    print(f"  • Maximum password age: {format_time(abs(max_pwd_age.total_seconds()))}")
            else:
                print(f"  • Maximum password age: Not Set")
            
            # Handle minPwdAge
            min_pwd_age = domain_policy.minPwdAge.value
            if isinstance(min_pwd_age, datetime.timedelta):
                print(f"  • Minimum password age: {format_time(abs(min_pwd_age.total_seconds()))}")
            else:
                print(f"  • Minimum password age: Not Set")
            
            # Handle lockoutDuration (special case for "None")
            lockout_duration = domain_policy.lockoutDuration.value
            if isinstance(lockout_duration, datetime.timedelta):
                if lockout_duration.total_seconds() == 0:
                    print("  • Lockout duration: None")
                else:
                    print(f"  • Lockout duration: {format_time(abs(lockout_duration.total_seconds()))}")
            else:
                print(f"  • Lockout duration: Not Set")
            
            # Handle lockoutObservationWindow
            lockout_obs = domain_policy.lockoutObservationWindow.value
            if isinstance(lockout_obs, datetime.timedelta):
                print(f"  • Lockout observation window: {format_time(abs(lockout_obs.total_seconds()))}")
            else:
                print(f"  • Lockout observation window: Not Set")
            
            # Handle lockoutThreshold
            lockout_threshold = domain_policy.lockoutThreshold.value
            if lockout_threshold is not None:
                if lockout_threshold == 0:
                    print("  • Lockout threshold: None")
                else:
                    print(f"  • Lockout threshold: {lockout_threshold}")
            else:
                print("  • Lockout threshold: Not Set")
            
            # Handle password properties
            pwd_props = domain_policy.pwdProperties.value
            if pwd_props is not None:
                complexity = "Enabled" if pwd_props & 0b1 else "Disabled"
                print(f"  • Password properties: {bin(pwd_props)} (Complexity {complexity})")
            else:
                print("  • Password properties: Not Set")
            
            # Get fine-grained policies if they exist
            try:
                fgpp = self.query(
                    '(objectClass=msDS-PasswordSettings)',
                    base_dn=f"CN=Password Settings Container,CN=System,{self.base_dn}",
                    attributes=['msDS-MinimumPasswordLength', 'msDS-PasswordSettingsPrecedence',
                            'msDS-PasswordComplexityEnabled', 'name']
                )
                
                if fgpp:
                    print("\nFine-Grained Password Policies:")
                    for policy in fgpp:
                        print(f"\nPolicy: {policy.name.value}")
                        print(f"  • Precedence: {policy.msDS_PasswordSettingsPrecedence.value}")
                        print(f"  • Minimum length: {policy.msDS_MinimumPasswordLength.value}")
                        complexity = "Enabled" if policy.msDS_PasswordComplexityEnabled.value else "Disabled"
                        print(f"  • Complexity: {complexity}")
                        
            except Exception as e:
                print(f"\n[!] Note: Could not retrieve fine-grained policies ({str(e)})")

        except Exception as e:
            print(f"[-] Failed to get domain policy: {str(e)}")
            
    def query(self, ldap_filter, base_dn=None, attributes=None):
        if not self.conn:
            print("[-] Not connected to LDAP")
            return []
        

        if base_dn is None:
            if self.base_dn is None:
                raise Exception("No base dn found")
            base_dn = self.base_dn
        
        try:
            self.conn.search(base_dn, ldap_filter, attributes=attributes)
            return self.conn.entries
        except Exception as e:
            print(f"[-] LDAP query failed: {e}")
            return []


class SMB:
    def __init__(self, remote_host, domain, username, password=None, 
                 lmhash='', nthash='', auth_method="NTLM", port=445):
        self.remote_host = remote_host
        self.port = port
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.auth_method = auth_method.upper()
        self.smb_connection = None
        self.pass_pol = {}

    def connect(self):
            try:
                self.smb_connection = SMBConnection(self.remote_host, self.remote_host, sess_port=self.port)
                
                if self.auth_method == "KERBEROS":
                    self.kerberos_auth()
                else:
                    self.ntlm_auth()
                
                return True
                
            except Exception as e:
                print(f"[-] SMB connection failed: {e}")
                return False

    def kerberos_auth(self):
            print("[*] Attempting Kerberos authentication")
            try:
                self.smb_connection.kerberosLogin(
                    self.username, self.password or '',
                    self.domain, self.lmhash, self.nthash,
                    kdcHost=self.remote_host, useCache=False
                )
            except Exception as e:
                print(f"[-] Kerberos failed: {e}")
                print("[*] Falling back to NTLM")
                self.ntlm_auth()

    def ntlm_auth(self):
            if self.lmhash or self.nthash:
                print("[*] Authenticating with NTLM hashes")
                self.smb_connection.login(
                    self.username, '', self.domain,
                    self.lmhash, self.nthash
                )
            else:
                if not self.password:
                    raise ValueError("No password or hashes provided")
                print("[*] Authenticating with password")
                self.smb_connection.login(
                    self.username, self.password, self.domain
                )

    def get_password_policy(self):
        try:
            # Create SMB transport connection to SAMR named pipe
            rpctransport = transport.SMBTransport(
                self.remote_host, self.port, r'\samr',
                self.username, self.password or '',
                self.domain, self.lmhash, self.nthash,
                doKerberos=(self.auth_method == "KERBEROS")
            )
            
            # Create DCE/RPC client and establish connection
            dce = DCERPC_v5(rpctransport)
            dce.connect()  # Establish connection to remote pipe
            dce.bind(samr.MSRPC_UUID_SAMR)  # Bind to SAMR interface UUID

            # Connect to SAMR server and get server handle
            resp = samr.hSamrConnect2(dce)
            if resp["ErrorCode"] != 0:
                raise Exception("SAMR connect failed")

            # Enumerate domains available on the server
            resp2 = samr.hSamrEnumerateDomainsInSamServer(
                dce,
                serverHandle=resp["ServerHandle"],  # Use obtained server handle
                enumerationContext=0,              # Start enumeration from beginning
                preferedMaximumLength=500          # Max entries to return
            )
            if resp2["ErrorCode"] != 0:
                raise Exception("Domain enumeration failed")

            # Extract domain name (handle bytes-to-string conversion)
            domain_name = resp2["Buffer"]["Buffer"][0]["Name"]
          
            # Lookup domain SID (Security Identifier)
            resp3 = samr.hSamrLookupDomainInSamServer(
                dce,
                serverHandle=resp["ServerHandle"],
                name=domain_name,  # Use the decoded domain name,
            )
            if resp3["ErrorCode"] != 0:
                raise Exception("Domain lookup failed")

            # Open domain handle with maximum permissions
            resp4 = samr.hSamrOpenDomain(
                dce,
                serverHandle=resp["ServerHandle"],
                desiredAccess=samr.MAXIMUM_ALLOWED,  # Request full access
                domainId=resp3["DomainId"],          # Use obtained domain SID
            )
            if resp4["ErrorCode"] != 0:
                raise Exception("Failed to open domain")

            domainHandle = resp4["DomainHandle"]  # Store handle for subsequent operations

            # Query password policy information
            re = samr.hSamrQueryInformationDomain2(
                dce,
                domainHandle=domainHandle,
                domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
            )
            # Store password policy attributes
            self.pass_pol["min_pass_len"] = re["Buffer"]["Password"]["MinPasswordLength"] or "None"
            self.pass_pol["pass_hist_len"] = re["Buffer"]["Password"]["PasswordHistoryLength"] or "None"
            self.pass_pol["max_pass_age"] = convert(  # Convert Windows time format to readable
                int(re["Buffer"]["Password"]["MaxPasswordAge"]["LowPart"]),
                int(re["Buffer"]["Password"]["MaxPasswordAge"]["HighPart"]),
            )
            self.pass_pol["min_pass_age"] = convert(
                int(re["Buffer"]["Password"]["MinPasswordAge"]["LowPart"]),
                int(re["Buffer"]["Password"]["MinPasswordAge"]["HighPart"]),
            )
            self.pass_pol["pass_prop"] = d2b(re["Buffer"]["Password"]["PasswordProperties"])  # Convert to binary flags

            # Query account lockout policy
            re = samr.hSamrQueryInformationDomain2(
                dce,
                domainHandle=domainHandle,
                domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
            )
            self.pass_pol["rst_accnt_lock_counter"] = convert(0, re["Buffer"]["Lockout"]["LockoutObservationWindow"], lockout=True)
            self.pass_pol["lock_accnt_dur"] = convert(0, re["Buffer"]["Lockout"]["LockoutDuration"], lockout=True)
            self.pass_pol["accnt_lock_thres"] = re["Buffer"]["Lockout"]["LockoutThreshold"] or "None"

            # Query forced logoff information
            re = samr.hSamrQueryInformationDomain2(
                dce,
                domainHandle=domainHandle,
                domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation,
            )
            self.pass_pol["force_logoff_time"] = convert(
                re["Buffer"]["Logoff"]["ForceLogoff"]["LowPart"],
                re["Buffer"]["Logoff"]["ForceLogoff"]["HighPart"],
            )

            # Clean up connection
            dce.disconnect()
            return self.pass_pol

        except Exception as e:
            print(f"[-] Failed to get password policy: {str(e)}") 
            return None

    def print_password_policy(self):
        if not self.pass_pol:
            print("[-] No password policy available")
            return

        print_banner("PASSWORD POLICY (SMB/SAMR)")
        
        table = Texttable()
        table.set_cols_align(["l", "l"])
        table.add_rows([
            ["Minimum password length", self.pass_pol.get('min_pass_len', 'N/A')],
            ["Password history length", self.pass_pol.get('pass_hist_len', 'N/A')],
            ["Maximum password age", self.pass_pol.get('max_pass_age', 'N/A')],
            ["Minimum password age", self.pass_pol.get('min_pass_age', 'N/A')],
            ["Lockout threshold", self.pass_pol.get('accnt_lock_thres', 'N/A')],
            ["Lockout duration", self.pass_pol.get('lock_accnt_dur', 'N/A')],
            ["Reset account lockout counter", self.pass_pol.get('rst_accnt_lock_counter', 'N/A')],
            ["Force logoff time", self.pass_pol.get('force_logoff_time', 'N/A')]
        ])
        print(table.draw())
        
        if 'pass_prop' in self.pass_pol:
            print_section("PASSWORD COMPLEXITY FLAGS")
            flags = {
                0: "Password must meet complexity requirements",
                1: "Store passwords with reversible encryption",
                2: "Allow Administrator account lockout",
                3: "Require smartcard for interactive logon",
                4: "Password never expires",
                5: "User cannot change password"
            }
            
            for i, bit in enumerate(reversed(self.pass_pol['pass_prop'])):
                if i in flags:
                    print(f"[{'*' if bit == '1' else ' '}] {flags[i]}")
                else:
                    print(f"[{'*' if bit == '1' else ' '}] Bit {i} (Unknown)")


def parse_args():
    parser = argparse.ArgumentParser(description="Retrieve domain password policy via LDAP and SMB/SAMR")
    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP address")
    parser.add_argument("-d", "--domain", required=True, help="Domain name")
    parser.add_argument("-u", "--user", required=True, help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("--ldap-port", type=int, default=389, help="LDAP port (default: 389)")
    parser.add_argument("--smb-port", type=int, default=445, help="SMB port (default: 445)")
    parser.add_argument("--auth", choices=["NTLM", "KERBEROS", "ANONYMOUS", "SIMPLE"], 
                        default="NTLM", help="Authentication method (default: NTLM)")
    parser.add_argument("--hashes", help="LM:NT hashes for pass-the-hash authentication")
    return parser.parse_args()

def main():
    args = parse_args()

    # Process hashes if provided
    lmhash = nthash = ''
    if args.hashes:
        try:
            lmhash, nthash = args.hashes.split(':')
        except ValueError:
            sys.exit("[!] Invalid hash format. Use LMHASH:NTHASH")

    # LDAP Connection
    try:
        print_banner("LDAP CONNECTION")
        ldap_uri = f"ldap://{args.target}:{args.ldap_port}"
        user_dn = f"{args.domain}\\{args.user}" if args.auth != "ANONYMOUS" else None
        
        ldap = LDAP(
            server_uri=ldap_uri,
            user_dn=user_dn,
            password=args.password,
            auth_method=args.auth
        )
        
        if ldap.connect():
            ldap.print_domain_policy()
    except Exception as e:
        print(f"[-] LDAP operation failed: {str(e)}")

    # SMB Connection
    try:
        print_banner("SMB CONNECTION")
        smb = SMB(
            remote_host=args.target,
            port=args.smb_port,
            domain=args.domain,
            username=args.user,
            password=args.password,
            lmhash=lmhash,
            nthash=nthash,
            auth_method=args.auth
        )
        
        if smb.connect():
            smb.get_password_policy()
            smb.print_password_policy()
    except Exception as e:
        print(f"[-] SMB operation failed: {str(e)}")

if __name__ == "__main__":
    main()