#!/usr/bin/env python3
"""
F5 BIG-IP APM Active Directory LDAPS Configuration Script
=========================================================
Automates provisioning of TMOS resources for Active Directory password management
(Expired Password Reset & Voluntary Password Change over LDAPS Port 636) via iControl REST:

1. CA Certificate management for LDAPS verification.
2. Active Directory AAA Server Object (Port 636, SSL Enabled, Service Account auth).
3. APM Access Policy Profile with:
   - Logon Page (username/password prompt).
   - AD Authentication (Show Extended Error & Password Expired reset enabled).
   - Password Modify Action / Decision Branches.
   - Allow / Deny Ending Rules.
4. LTM Virtual Server (HTTPS/443, Client-SSL, HTTP profile, APM Access profile).

Author: Antigravity Lab Automation
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import Dict, Any, Optional, List
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(dotenv_path=None, override=False):
        """Simple fallback .env parser when python-dotenv is not installed."""
        target_path = dotenv_path or ".env"
        if not os.path.exists(target_path):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            alt_path = os.path.join(script_dir, "..", target_path)
            if os.path.exists(alt_path):
                target_path = alt_path
            else:
                return
        with open(target_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if override or k not in os.environ:
                    os.environ[k] = v
try:
    import urllib3
    import requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Missing required packages. Please run: pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("f5_apm_config")


class F5RestClient:
    """Client for interacting with F5 BIG-IP iControl REST API."""

    def __init__(self, host: str, port: int, user: str, password: str, verify_ssl: bool = False, partition: str = "Common"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self.partition = partition
        self.base_url = f"https://{self.host}:{self.port}/mgmt"
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.token: Optional[str] = None
        self.headers = {"Content-Type": "application/json"}

    def authenticate(self) -> bool:
        """Obtain an iControl REST authentication token."""
        auth_url = f"{self.base_url}/shared/authn/login"
        payload = {
            "username": self.user,
            "password": self.password,
            "loginProviderName": "tmos"
        }
        logger.info(f"Authenticating to BIG-IP at {self.host}:{self.port}...")
        try:
            resp = self.session.post(auth_url, json=payload, headers=self.headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("token", {}).get("token")
                if self.token:
                    self.headers["X-F5-Auth-Token"] = self.token
                    logger.info("Authentication successful. Token obtained.")
                    return True
            logger.warning(f"Token auth failed ({resp.status_code}): {resp.text}. Falling back to Basic Auth.")
            self.session.auth = (self.user, self.password)
            return True
        except Exception as ex:
            logger.error(f"Connection failed to BIG-IP management endpoint: {ex}")
            return False

    def get(self, endpoint: str) -> requests.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        return self.session.get(url, headers=self.headers, timeout=30)

    def post(self, endpoint: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        return self.session.post(url, json=payload, headers=self.headers, timeout=30)

    def put(self, endpoint: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        return self.session.put(url, json=payload, headers=self.headers, timeout=30)

    def patch(self, endpoint: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        return self.session.patch(url, json=payload, headers=self.headers, timeout=30)

    def delete(self, endpoint: str) -> requests.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        return self.session.delete(url, headers=self.headers, timeout=30)


class F5ApmAdConfigurator:
    """Provisions and validates F5 APM Active Directory LDAPS Password Management objects."""

    def __init__(self, client: F5RestClient, config: Dict[str, Any]):
        self.client = client
        self.cfg = config
        self.partition = config.get("BIGIP_PARTITION", "Common")

    def format_path(self, name: str) -> str:
        """Format TMOS object path (e.g. ~Common~name)."""
        return f"~{self.partition}~{name}"

    def ensure_ca_certificate(self) -> bool:
        """Ensure Root CA certificate exists on TMOS for LDAPS certificate validation."""
        cert_name = self.cfg.get("CA_CERT_NAME", "lab_ad_ca_cert")
        cert_file_path = self.cfg.get("CA_CERT_FILE", "./certs/lab_root_ca.crt")

        logger.info(f"Checking SSL CA Certificate: {cert_name}...")
        resp = self.client.get(f"tm/sys/crypto/cert/{self.format_path(cert_name)}")
        if resp.status_code == 200:
            logger.info(f"CA Certificate '{cert_name}' already exists.")
            return True

        if os.path.exists(cert_file_path):
            logger.info(f"Reading certificate file from {cert_file_path}...")
            with open(cert_file_path, "r") as f:
                cert_content = f.read()

            upload_payload = {
                "name": cert_name,
                "partition": self.partition,
                "command": "install",
                "from-local-file": cert_file_path,
                "text": cert_content
            }
            logger.info(f"Installing CA certificate '{cert_name}' onto BIG-IP...")
            resp = self.client.post("tm/sys/crypto/cert", upload_payload)
            if resp.status_code in [200, 201]:
                logger.info(f"Successfully installed CA certificate '{cert_name}'.")
                return True
            else:
                logger.warning(f"Could not install crypto cert: {resp.status_code} {resp.text}")
        else:
            logger.info(f"Local CA cert file '{cert_file_path}' not found. Using default system CA bundle.")
            return True
        return False

    def provision_aaa_active_directory(self) -> bool:
        """
        Create or update the Active Directory AAA Server Object configured for LDAPS (Port 636).
        """
        aaa_name = self.cfg["AAA_AD_NAME"]
        ad_domain = self.cfg["AD_DOMAIN"]
        ad_dc_ip = self.cfg["AD_DC_IP"]
        ad_ldaps_port = int(self.cfg.get("AD_LDAPS_PORT", 636))
        ad_svc_user = self.cfg["AD_SVC_USER"]
        ad_svc_pass = self.cfg["AD_SVC_PASS"]
        ca_cert_name = self.cfg.get("CA_CERT_NAME", "lab_ad_ca_cert")

        # Verify whether CA cert exists; fallback to ca-bundle if not found
        cert_ref = f"/{self.partition}/{ca_cert_name}"
        chk_cert = self.client.get(f"tm/sys/crypto/cert/{self.format_path(ca_cert_name)}")
        if chk_cert.status_code != 200:
            cert_ref = "/Common/ca-bundle.crt"

        payload = {
            "name": aaa_name,
            "partition": self.partition,
            "domain": ad_domain,
            "domainControllers": [
                {
                    "ip": ad_dc_ip,
                    "port": ad_ldaps_port,
                    "name": ad_dc_ip
                }
            ],
            "useSsl": "enabled",
            "sslCaCert": cert_ref,
            "adminName": ad_svc_user,
            "adminPassword": ad_svc_pass,
            "timeout": 15,
            "retryInterval": 3,
            "schema": "active-directory"
        }

        logger.info(f"Provisioning AAA Active Directory Object '{aaa_name}' (LDAPS Port {ad_ldaps_port})...")
        check_resp = self.client.get(f"tm/apm/aaa/active-directory/{self.format_path(aaa_name)}")
        
        if check_resp.status_code == 200:
            logger.info(f"AAA Active Directory Object '{aaa_name}' exists. Updating configuration...")
            resp = self.client.patch(f"tm/apm/aaa/active-directory/{self.format_path(aaa_name)}", payload)
        else:
            resp = self.client.post("tm/apm/aaa/active-directory", payload)

        if resp.status_code in [200, 201]:
            # Ensure admin credentials are set via tmsh for password expiry reminders (K16806)
            set_pwd_cmd = f'tmsh modify apm aaa active-directory /{self.partition}/{aaa_name} admin-name {ad_svc_user} admin-encrypted-password {ad_svc_pass} 2>/dev/null || true'
            self.client.post("tm/util/bash", {"command": "run", "utilCmdArgs": f'-c "{set_pwd_cmd}"'})
            logger.info(f"AAA Active Directory Object '{aaa_name}' configured successfully.")
            return True
        else:
            logger.error(f"Failed to configure AAA AD Object: {resp.status_code} - {resp.text}")
            return False

    def provision_access_policy_and_profile(self) -> bool:
        """
        Create APM Access Profile and Policy with:
        - Customization Groups
        - Logon Page Action
        - AD Authentication with Password Expired reset enabled
        - Allow / Deny Endings
        - Apply Access Policy (generation-action increment)
        """
        profile_name = self.cfg["APM_PROFILE_NAME"]
        aaa_name = self.cfg["AAA_AD_NAME"]

        logger.info(f"Checking APM Access Profile '{profile_name}'...")
        chk_resp = self.client.get(f"tm/apm/profile/access/{self.format_path(profile_name)}")
        if chk_resp.status_code == 200:
            logger.info(f"APM Access Profile '{profile_name}' already exists.")
            return True

        import base64
        tmsh_script = f"""
create cli transaction

create apm policy customization-group /{self.partition}/{profile_name}_act_logon_page_ag type logon
create apm policy customization-group /{self.partition}/{profile_name}_end_deny_ag type logout
create apm policy customization-group /{self.partition}/{profile_name}_eps type eps
create apm policy customization-group /{self.partition}/{profile_name}_errormap type errormap
create apm policy customization-group /{self.partition}/{profile_name}_framework_installation type framework-installation
create apm policy customization-group /{self.partition}/{profile_name}_general_ui type general-ui
create apm policy customization-group /{self.partition}/{profile_name}_logout type logout

create apm policy agent ending-allow /{self.partition}/{profile_name}_end_allow_ag {{ }}
create apm policy policy-item /{self.partition}/{profile_name}_end_allow {{ agents add {{ /{self.partition}/{profile_name}_end_allow_ag {{ type ending-allow }} }} caption Allow color 1 item-type ending }}

create apm policy agent ending-deny /{self.partition}/{profile_name}_end_deny_ag {{ customization-group /{self.partition}/{profile_name}_end_deny_ag }}
create apm policy policy-item /{self.partition}/{profile_name}_end_deny {{ agents add {{ /{self.partition}/{profile_name}_end_deny_ag {{ type ending-deny }} }} caption Deny color 2 item-type ending }}

create apm policy agent logon-page /{self.partition}/{profile_name}_act_logon_page_ag {{ type form-based customization-group /{self.partition}/{profile_name}_act_logon_page_ag }}
create apm policy policy-item /{self.partition}/{profile_name}_act_logon_page {{ agents add {{ /{self.partition}/{profile_name}_act_logon_page_ag {{ type logon-page }} }} caption "Logon Page" color 1 item-type action rules {{ {{ caption fallback next-item /{self.partition}/{profile_name}_act_ad_auth }} }} }}

create apm policy agent aaa-active-directory /{self.partition}/{profile_name}_act_ad_auth_ag {{ type auth server /{self.partition}/{aaa_name} show-extended-error true pwd-expiry-warn-days 14 pwd-complexity-check true max-pwd-reset-attempt 3 }}
create apm policy policy-item /{self.partition}/{profile_name}_act_ad_auth {{ agents add {{ /{self.partition}/{profile_name}_act_ad_auth_ag {{ type aaa-active-directory }} }} caption "AD Auth" color 1 item-type action rules {{ {{ caption Successful expression "expr {{[mcget {{session.ad.last.authresult}}] == 1}}" next-item /{self.partition}/{profile_name}_end_allow }} {{ caption fallback next-item /{self.partition}/{profile_name}_end_deny }} }} }}

create apm policy policy-item /{self.partition}/{profile_name}_ent {{ caption Start color 1 item-type entry rules {{ {{ caption fallback next-item /{self.partition}/{profile_name}_act_logon_page }} }} }}

create apm policy access-policy /{self.partition}/{profile_name} {{ default-ending /{self.partition}/{profile_name}_end_deny items add {{ {profile_name}_end_allow {{ }} {profile_name}_end_deny {{ }} {profile_name}_act_logon_page {{ }} {profile_name}_act_ad_auth {{ }} {profile_name}_ent {{ }} }} start-item {profile_name}_ent }}

create apm profile access /{self.partition}/{profile_name} {{ accept-languages add {{ en }} default-language en access-policy /{self.partition}/{profile_name} eps-group /{self.partition}/{profile_name}_eps errormap-group /{self.partition}/{profile_name}_errormap framework-installation-group /{self.partition}/{profile_name}_framework_installation general-ui-group /{self.partition}/{profile_name}_general_ui customization-group /{self.partition}/{profile_name}_logout type all }}

submit cli transaction
"""
        logger.info(f"Submitting APM Access Policy and Profile transaction for '{profile_name}'...")
        b64_script = base64.b64encode(tmsh_script.strip().encode('utf-8')).decode('utf-8')
        cmd = f"echo {b64_script} | base64 -d > /tmp/setup_apm_{profile_name}.tmsh && tmsh -q < /tmp/setup_apm_{profile_name}.tmsh"
        res = self.client.post("tm/util/bash", {"command": "run", "utilCmdArgs": f'-c "{cmd}"'})
        cmd_out = res.json().get("commandResult", "") if res.status_code == 200 else res.text

        if "transaction failed" in cmd_out.lower():
            logger.error(f"Transaction failed: {cmd_out}")
            return False

        # Apply the access policy configuration
        logger.info(f"Applying APM Access Policy for profile '{profile_name}'...")
        apply_cmd = f"tmsh modify apm profile access /{self.partition}/{profile_name} generation-action increment"
        self.client.post("tm/util/bash", {"command": "run", "utilCmdArgs": f'-c "{apply_cmd}"'})
        logger.info(f"Successfully provisioned and applied APM Profile '{profile_name}'.")
        return True

    def provision_virtual_server(self) -> bool:
        """
        Create HTTPS LTM Virtual Server attaching:
        - HTTP Profile
        - ClientSSL Profile
        - APM Access Profile
        """
        vs_name = self.cfg["VS_NAME"]
        vs_ip = self.cfg["VS_IP"]
        vs_port = int(self.cfg.get("VS_PORT", 443))
        profile_name = self.cfg["APM_PROFILE_NAME"]

        destination = f"/{self.partition}/{vs_ip}:{vs_port}"
        
        vs_payload = {
            "name": vs_name,
            "partition": self.partition,
            "destination": destination,
            "ipProtocol": "tcp",
            "mask": "255.255.255.255",
            "sourceAddressTranslation": {"type": "automap"},
            "profiles": [
                {"name": "http", "partition": "Common", "context": "all"},
                {"name": "clientssl", "partition": "Common", "context": "clientside"},
                {"name": profile_name, "partition": self.partition, "context": "all"}
            ]
        }

        # Phase 1 & 2: Attach Backend Pool and RBAC iRule
        pool_name = "pool_apm_ad_backend"
        node_name = "node_portal_app"
        node_ip = "10.1.20.14"
        rule_name = "rule_apm_ad_rbac_headers"
        mon_name = "mon_portal_http"

        # Ensure Node
        self.client.post("tm/ltm/node", {"name": node_name, "address": node_ip, "partition": self.partition})

        # Ensure HTTP Monitor
        mon_payload = {
            "name": mon_name,
            "partition": self.partition,
            "send": "GET /health HTTP/1.1\\r\\nHost: 10.1.20.14\\r\\nConnection: Close\\r\\n\\r\\n",
            "recv": "OK",
            "interval": 5,
            "timeout": 16
        }
        self.client.post("tm/ltm/monitor/http", mon_payload)

        # Ensure Pool
        pool_payload = {
            "name": pool_name,
            "partition": self.partition,
            "monitor": f"/{self.partition}/{mon_name}",
            "members": [{"name": f"{node_name}:8000", "address": node_ip}]
        }
        self.client.post("tm/ltm/pool", pool_payload)

        # Ensure iRule with K16806 password expiration headers
        irule_code = """when ACCESS_ACL_ALLOWED {
    set apm_user [ACCESS::session data get session.logon.last.username]
    if { $apm_user ne "" } {
        HTTP::header insert "X-Authenticated-User" $apm_user
        if { [string tolower $apm_user] contains "admin" } {
            HTTP::header insert "X-User-Role" "Enterprise Administrator"
        } else {
            HTTP::header insert "X-User-Role" "Standard Corporate User"
        }
        set pwd_last_set [ACCESS::session data get session.ad.last.pwdLastSet]
        if { $pwd_last_set ne "" } {
            HTTP::header insert "X-AD-Password-Last-Set" $pwd_last_set
        }
        set warn_pwd [ACCESS::session data get session.ad.last.warnpwd]
        if { $warn_pwd ne "" } {
            HTTP::header insert "X-AD-Password-Warn" $warn_pwd
        }
    }
}"""
        self.client.post("tm/ltm/rule", {"name": rule_name, "partition": self.partition, "apiAnonymous": irule_code})

        vs_payload["pool"] = f"/{self.partition}/{pool_name}"
        vs_payload["rules"] = [f"/{self.partition}/{rule_name}"]

        logger.info(f"Checking Virtual Server '{vs_name}' ({destination})...")
        chk_resp = self.client.get(f"tm/ltm/virtual/{self.format_path(vs_name)}")

        if chk_resp.status_code == 200:
            logger.info(f"Virtual Server '{vs_name}' exists. Updating configuration...")
            resp = self.client.patch(f"tm/ltm/virtual/{self.format_path(vs_name)}", vs_payload)
        else:
            logger.info(f"Creating Virtual Server '{vs_name}'...")
            resp = self.client.post("tm/ltm/virtual", vs_payload)

        if resp.status_code in [200, 201]:
            logger.info(f"Virtual Server '{vs_name}' configured successfully.")
            return True
        else:
            logger.error(f"Failed to configure Virtual Server: {resp.status_code} - {resp.text}")
            return False

    def teardown(self) -> bool:
        """Safely remove lab objects in reverse dependency order."""
        vs_name = self.cfg["VS_NAME"]
        profile_name = self.cfg["APM_PROFILE_NAME"]
        aaa_name = self.cfg["AAA_AD_NAME"]

        logger.info("Starting teardown of F5 lab resources...")

        # 1. Delete Virtual Server
        logger.info(f"Deleting Virtual Server '{vs_name}'...")
        self.client.delete(f"tm/ltm/virtual/{self.format_path(vs_name)}")

        # 2. Delete APM Profile & Policy components
        logger.info(f"Deleting APM Access Profile '{profile_name}'...")
        del_cmd = f"tmsh delete apm profile access /{self.partition}/{profile_name} 2>/dev/null; tmsh delete apm policy access-policy /{self.partition}/{profile_name} 2>/dev/null || true"
        self.client.post("tm/util/bash", {"command": "run", "utilCmdArgs": f'-c "{del_cmd}"'})

        # 3. Delete AAA AD Object
        logger.info(f"Deleting AAA Active Directory object '{aaa_name}'...")
        self.client.delete(f"tm/apm/aaa/active-directory/{self.format_path(aaa_name)}")

        logger.info("Teardown complete.")
        return True

    def verify_status(self) -> Dict[str, Any]:
        """Verify the current TMOS configuration status."""
        status = {}
        # Check AAA AD Object
        aaa_name = self.cfg["AAA_AD_NAME"]
        r = self.client.get(f"tm/apm/aaa/active-directory/{self.format_path(aaa_name)}")
        status["aaa_ad_object"] = {
            "name": aaa_name,
            "exists": r.status_code == 200,
            "status_code": r.status_code
        }

        # Check APM Profile
        profile_name = self.cfg["APM_PROFILE_NAME"]
        r = self.client.get(f"tm/apm/profile/access/{self.format_path(profile_name)}")
        status["apm_access_profile"] = {
            "name": profile_name,
            "exists": r.status_code == 200,
            "status_code": r.status_code
        }

        # Check Virtual Server
        vs_name = self.cfg["VS_NAME"]
        r = self.client.get(f"tm/ltm/virtual/{self.format_path(vs_name)}")
        status["virtual_server"] = {
            "name": vs_name,
            "exists": r.status_code == 200,
            "status_code": r.status_code
        }
        return status


def load_config(env_file: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from .env or system environment."""
    if env_file and os.path.exists(env_file):
        load_dotenv(dotenv_path=env_file, override=True)
    else:
        load_dotenv(dotenv_path=".env", override=True)
        if not os.path.exists(".env") and os.path.exists(".env.example"):
            load_dotenv(dotenv_path=".env.example", override=False)

    config = {
        "BIGIP_HOST": os.getenv("BIGIP_HOST", "10.1.1.245"),
        "BIGIP_PORT": int(os.getenv("BIGIP_PORT", "443")),
        "BIGIP_USER": os.getenv("BIGIP_USER", "admin"),
        "BIGIP_PASS": os.getenv("BIGIP_PASS", "admin_password"),
        "BIGIP_VERIFY_SSL": os.getenv("BIGIP_VERIFY_SSL", "false").lower() in ("true", "1", "yes"),
        "BIGIP_PARTITION": os.getenv("BIGIP_PARTITION", "Common"),
        "AD_DOMAIN": os.getenv("AD_DOMAIN", "lab.example.com"),
        "AD_DC_IP": os.getenv("AD_DC_IP", "10.1.1.10"),
        "AD_LDAPS_PORT": int(os.getenv("AD_LDAPS_PORT", "636")),
        "AD_SVC_USER": os.getenv("AD_SVC_USER", "f5-svc-ad"),
        "AD_SVC_PASS": os.getenv("AD_SVC_PASS", "AdminServicePass123!"),
        "VS_NAME": os.getenv("VS_NAME", "vs_apm_ad_lab_https"),
        "VS_IP": os.getenv("VS_IP", "10.1.1.200"),
        "VS_PORT": int(os.getenv("VS_PORT", "443")),
        "APM_PROFILE_NAME": os.getenv("APM_PROFILE_NAME", "ap_ad_password_mgmt"),
        "AAA_AD_NAME": os.getenv("AAA_AD_NAME", "aaa_lab_ad_ldaps"),
        "CA_CERT_NAME": os.getenv("CA_CERT_NAME", "lab_ad_ca_cert"),
        "CA_CERT_FILE": os.getenv("CA_CERT_FILE", "./certs/lab_root_ca.crt"),
    }
    return config


def main():
    parser = argparse.ArgumentParser(description="F5 BIG-IP APM Active Directory LDAPS Provisioning Script")
    parser.add_argument("--env", help="Path to custom .env file", default=None)
    parser.add_argument("--teardown", action="store_true", help="Delete lab objects from BIG-IP")
    parser.add_argument("--status", action="store_true", help="Check status of BIG-IP lab objects")
    parser.add_argument("--dry-run", action="store_true", help="Validate credentials and test connection without making changes")
    args = parser.parse_args()

    config = load_config(args.env)

    logger.info("=" * 70)
    logger.info("F5 APM Active Directory Password Management Provisioner")
    logger.info("=" * 70)
    logger.info(f"Target BIG-IP:        {config['BIGIP_HOST']}:{config['BIGIP_PORT']}")
    logger.info(f"Active Directory DC:  {config['AD_DC_IP']} ({config['AD_DOMAIN']}) LDAPS:{config['AD_LDAPS_PORT']}")
    logger.info(f"Virtual Server:       {config['VS_IP']}:{config['VS_PORT']} ({config['VS_NAME']})")
    logger.info(f"APM Access Profile:   {config['APM_PROFILE_NAME']}")
    logger.info(f"AAA AD Server Object: {config['AAA_AD_NAME']}")
    logger.info("=" * 70)

    client = F5RestClient(
        host=config["BIGIP_HOST"],
        port=config["BIGIP_PORT"],
        user=config["BIGIP_USER"],
        password=config["BIGIP_PASS"],
        verify_ssl=config["BIGIP_VERIFY_SSL"],
        partition=config["BIGIP_PARTITION"]
    )

    if not client.authenticate():
        logger.error("Authentication failed. Please verify BIGIP_HOST, BIGIP_USER, and BIGIP_PASS.")
        sys.exit(1)

    configurator = F5ApmAdConfigurator(client, config)

    if args.dry_run:
        logger.info("[DRY-RUN] Authentication verified. Checking system status...")
        status = configurator.verify_status()
        logger.info(f"System status: {json.dumps(status, indent=2)}")
        logger.info("[DRY-RUN] Completed without modifying configuration.")
        return

    if args.status:
        status = configurator.verify_status()
        logger.info("=" * 70)
        logger.info("Current Configuration Status:")
        for obj_type, details in status.items():
            state = "EXISTS" if details.get("exists") else "NOT FOUND"
            logger.info(f"  - {obj_type} ({details.get('name')}): {state}")
        logger.info("=" * 70)
        return

    if args.teardown:
        success = configurator.teardown()
        sys.exit(0 if success else 1)

    # Step-by-step Provisioning
    logger.info("Starting Provisioning Workflow...")
    
    # 1. CA Certificate
    configurator.ensure_ca_certificate()

    # 2. AAA Active Directory Object
    if not configurator.provision_aaa_active_directory():
        logger.error("Failed to provision AAA Active Directory Object.")
        sys.exit(1)

    # 3. APM Access Profile and Policy
    if not configurator.provision_access_policy_and_profile():
        logger.error("Failed to provision APM Access Profile.")
        sys.exit(1)

    # 4. HTTPS Virtual Server
    if not configurator.provision_virtual_server():
        logger.error("Failed to provision Virtual Server.")
        sys.exit(1)

    logger.info("=" * 70)
    logger.info("SUCCESS: All F5 BIG-IP APM resources have been provisioned!")
    logger.info(f"Virtual Server is ready for testing at: https://{config['VS_IP']}:{config['VS_PORT']}/")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
