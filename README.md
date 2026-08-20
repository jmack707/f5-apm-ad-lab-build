# F5 BIG-IP APM Active Directory Password & Account Management Lab

A complete, production-grade automation lab for implementing and validating **Active Directory Password Management** (Expired Password Reset per F5 K16806 and Voluntary Password Change) and **Account Expiration Lifecycle** on **F5 BIG-IP Access Policy Manager (APM)** over secure **LDAPS (Port 636)** using the **iControl REST API**.

---

## Table of Contents

1. [Architecture & Workflow Overview](#architecture--workflow-overview)
2. [Active Directory Delegation & Least Privilege](#active-directory-delegation--least-privilege)
3. [F5 TMOS & APM Configuration Architecture](#f5-tmos--apm-configuration-architecture)
4. [F5 K16806 Password Expiration & Account Expiration Mechanics](#f5-k16806-password-expiration--account-expiration-mechanics)
5. [Intranet Portal & Live Lifecycle Controls](#intranet-portal--live-lifecycle-controls)
6. [Test Cases Specification (TC-01 to TC-05)](#test-cases-specification-tc-01-to-tc-05)
7. [Directory Structure](#directory-structure)
8. [Prerequisites & Environment Setup](#prerequisites--environment-setup)
9. [Step-by-Step Deployment Guide](#step-by-step-deployment-guide)
10. [Automated Verification & Test Execution](#automated-verification--test-execution)
11. [REST API Reference & Troubleshooting](#rest-api-reference--troubleshooting)

---

## Architecture & Workflow Overview

Active Directory requires a secure, encrypted transport layer (LDAPS on TCP port 636 or LDAP with StartTLS on TCP port 389) to perform administrative or delegated password modifications (`unicodePwd` attribute). Active Directory rejects any password reset or change requests over unencrypted LDAP (port 389) with `LDAP_UNWILLING_TO_PERFORM` (Error code 53).

```
 +------------------+             +--------------------+             +--------------------+
 |   Client User    |             |    F5 BIG-IP APM   |             |  Active Directory  |
 |  (Browser/Agent) |             |  (Virtual Server)  |             |  Domain Controller |
 +--------+---------+             +---------+----------+             +---------+----------+
          |                                 |                                  |
          | 1. HTTPS GET /                  |                                  |
          |-------------------------------->|                                  |
          | 2. 302 Redirect /my.policy      |                                  |
          |<--------------------------------|                                  |
          |                                 |                                  |
          | 3. Submit Credentials           |                                  |
          |-------------------------------->| 4. Kerberos / LDAPS Auth (636)   |
          |                                 |--------------------------------->|
          |                                 |                                  |
          |                                 | 5. Return Pwd Expired (532/773)  |
          |                                 |<---------------------------------|
          | 6. Render K16806 Reset Form     |                                  |
          |    (_F5_challenge fields)       |                                  |
          |<--------------------------------|                                  |
          |                                 |                                  |
          | 7. Submit New Password          |                                  |
          |-------------------------------->| 8. LDAPS Admin Reset (unicodePwd)|
          |                                 |    Using 'f5-svc-ad' delegation  |
          |                                 |--------------------------------->|
          |                                 | 9. Password Update Success       |
          |                                 |<---------------------------------|
          | 10. Session Allowed / Redirect  |                                  |
          |<--------------------------------|                                  |
```

### Password & Account Management Workflows

1. **Expired Password Reset (K16806 Logon Enforcement)**
   - User authenticates with expired password (`pwdLastSet = 0` and `userAccountControl = 512` with `DONT_EXPIRE_PASSWORD` flag cleared).
   - AD Domain Controller returns `STATUS_PASSWORD_MUST_CHANGE` (Win32 error `0xC0000224` / extended error 532 / 773).
   - F5 APM catches the extended error, branches into the **Password Modify** action, and displays the password reset prompt (`_F5_challenge` and `_F5_verify_password`).
   - User enters new compliant password.
   - F5 APM uses the delegated service account over LDAPS (636) to modify the `unicodePwd` and `pwdLastSet` attributes.
   - Session is successfully established and granted.

2. **Expired Account Catching (`accountExpires = 1`)**
   - Active Directory user account has `accountExpires` set to a past timestamp (e.g., `1`).
   - During logon, Active Directory returns `STATUS_ACCOUNT_EXPIRED` (Win32 error `0xC0000193` / extended error 701).
   - F5 APM catches the extended error, denies authentication, and displays:
     `"The username or password is not correct. Please try again. (error: Client's credentials have been revoked ... User account is locked/expired)"`.

3. **Voluntary Password Change (Self-Service)**
   - Authenticated user initiates voluntary password change via APM Webtop, self-service link, or `/change_password`.
   - User provides current password and new password.
   - Updates `unicodePwd` in Active Directory over LDAPS 636 and clears expiration.

---

## Active Directory Delegation & Least Privilege

Rather than granting Domain Admin privileges to the F5 BIG-IP service account, this lab establishes strict **least-privilege delegation** scoped only to the target Organizational Unit (OU):

### Required Delegated Rights on Target OU

| Right / Attribute | AD Schema Object / GUID | Description |
| :--- | :--- | :--- |
| **Reset Password** | `User-Force-Change-Password`<br>`{00299570-246d-11d0-a7c2-00a0c911505a}` | Allows resetting user passwords without knowing existing password. |
| **Read/Write `pwdLastSet`** | `{bf967a0a-0de6-11d0-a285-00aa003049e2}` | Clears the "Must change password at next logon" flag upon successful reset. |
| **Read/Write `accountExpires`** | `{bf96791f-0de6-11d0-a285-00aa003049e2}` | Manages user account expiration timestamps. |
| **Read/Write `lockoutTime`** | `{28636aa8-d4d6-11d1-99c7-006097924342}` | Allows unlocking locked accounts during password recovery workflows. |
| **Read/Write `userAccountControl`** | `{bf967a68-0de6-11d0-a285-00aa003049e2}` | Reads account status flags (e.g., normal 512, DONT_EXPIRE_PASSWORD 65536). |

These permissions are automated via [scripts/setup_ad_delegation.ps1](file:///home/ubuntu/f5-apm-ad-lab/scripts/setup_ad_delegation.ps1).

---

## F5 TMOS & APM Configuration Architecture

The F5 BIG-IP configuration is deployed idempotently using the iControl REST API:

1. **System SSL Crypto Certificate (`/mgmt/tm/sys/crypto/cert`)**:
   - Imports Domain Root/Enterprise CA certificate to validate LDAPS TLS certificates presented by Active Directory Domain Controllers.
2. **AAA Active Directory Server (`/mgmt/tm/apm/aaa/active-directory`)**:
   - `domain`: `f5lab.local`
   - `domainControllers`: `[{"ip": "10.1.20.7", "port": 636}]`
   - `useSsl`: `enabled`
   - `sslCaCert`: `/Common/lab_ad_ca_cert`
   - `adminName`: `admin`
   - `adminPassword`: `admin`
3. **APM Access Profile & Policy (`/mgmt/tm/apm/profile/access`)**:
   - **Logon Page Item**: Prompts for username and password.
   - **AD Auth Item**:
     - `showExtendedError`: `enabled`
     - `changePasswordOnPasswordExpired`: `enabled`
     - `maxPasswordPromptAttempts`: 3
   - **Password Modify Item**: Handles expired password and voluntary password updates over LDAPS 636.
   - **Ending Rules**: Allow on success, Deny on failure.
4. **HTTPS Virtual Server (`/mgmt/tm/ltm/virtual`)**:
   - Port 443 with `http`, `clientssl`, and APM Access Profile attached.

---

## F5 K16806 Password Expiration & Account Expiration Mechanics

Per **F5 Knowledge Base Article [K16806](https://my.f5.com/manage/s/article/K16806)** (*Overview of BIG-IP APM password resets for AD users*), BIG-IP APM provides native mechanisms for handling expired passwords and user password notifications:

### Key Active Directory Attributes & UAC Interaction

1. **`userAccountControl` (UAC) & `DONT_EXPIRE_PASSWORD`**:
   - When a user has the `DONT_EXPIRE_PASSWORD` flag set in Active Directory (`0x10000` = 65536, e.g., UAC = 66048), **Active Directory overrides and ignores `pwdLastSet = 0`**.
   - **Resolution:** The Demo page and testing tools explicitly set `userAccountControl = 512` (`NORMAL_ACCOUNT`), removing `0x10000`. This allows AD to return `data 773` (`STATUS_PASSWORD_MUST_CHANGE`), which APM catches and presents the password reset form.
2. **`accountExpires` & Account Expiration (`data 701`)**:
   - Setting `accountExpires = 1` sets the account expiry date in the past (Jan 1, 1601).
   - Active Directory returns `STATUS_ACCOUNT_EXPIRED` (extended error 701 / `0xC0000193`).
   - APM catches the revoked credentials condition, prevents session establishment, and displays the credential revocation error.
3. **Password Complexity & LDAPS Updates**:
   - Enforces password complexity rules prior to submitting updates to Active Directory (Minimum length 8, uppercase, lowercase, numbers, symbols).
   - Modifies `unicodePwd` attribute using UTF-16LE encoded quotes over LDAPS (TCP port 636).
   - Sets `pwdLastSet = -1` upon password update to restore active state.

---

## Intranet Portal & Container Deployment

The backend Intranet Portal is containerized using Docker and Docker Compose, running on port 8000:

- **Container Management**:
  ```bash
  # View container status and healthcheck
  docker compose ps

  # View live application logs (LDAPS events, password resets, auto-restore timers)
  docker compose logs -f portal-app

  # Restart container
  docker compose restart portal-app

  # Stop container
  docker compose down
  ```

- **Live Password & Account Status Dashboard**:
  - **Password Status**: Displays status badge (`ACTIVE`, `EXPIRING SOON`, `EXPIRED`, `UAC NEVER EXPIRES`), last changed timestamp, and days remaining.
  - **Account Status**: Displays `accountExpires` timestamp and Active Directory policy status.
  - **Auto-Restore Timer**: Displays real-time countdown pill and status (`Active (Re-enables in 04:59)`) when an auto-reenable timer is active.
  - **Dynamic Alert Banners**: Color-coded banners for account expiration (Red), password expiration (Red/Yellow), and active state (Green).
- **Interactive Action Modals**:
  - **Change Password Modal**: Direct LDAPS 636 self-service password update with K16806 validation.
  - **Expire Password Modal (K16806 Test)**:
    - User selection chips (`user1`, `user_expired`, `user_normal`, `user_voluntary`, `admin`).
    - Optional temporary password field (sets known password in AD over LDAPS).
    - Automatically clears `DONT_EXPIRE_PASSWORD` (UAC=512), sets `pwdLastSet = 0`, and ensures `accountExpires = 0`.
    - Configurable auto-restore timer (Default: **5 Minutes / 300s**).
  - **Expire Account Modal (AD Test)**:
    - Sets `accountExpires = 1` over LDAPS 636 to test APM error 701 handling.
    - Configurable auto-restore timer (Default: **5 Minutes / 300s**), automatically restoring `accountExpires = 0` via background worker thread.
  - **Restore Active State**:
    - Instantly resets `pwdLastSet = -1`, `accountExpires = 0`, `userAccountControl = 512`, clears lockout, and cancels any pending timers.
- **REST API Endpoints**:
  - `GET /api/password_status?user=<username>` (Returns active timer metadata and expiration state)
  - `POST /expire_password` (`username`, `temp_password`, `timer_seconds=300`)
  - `POST /expire_account` (`username`, `timer_seconds=300`)
  - `POST /unexpire_password` (`username`, `temp_password`)
  - `POST /unexpire_account` (`username`)
  - `POST /change_password` (`username`, `_sys_password_old`, `_sys_password_new`, `_sys_password_confirm`)

---

## Ansible Automation Deployment

The entire stack (Backend Container, BIG-IP LTM Objects, AD AAA LDAPS Server, and APM Access Policy Profile) can be fully provisioned, updated, and validated using **Ansible**:

```bash
# Navigate to ansible directory
cd ansible

# Run the master deployment playbook
ansible-playbook -i inventory.ini playbooks/deploy_f5_apm_lab.yml
```

### Ansible Roles Architecture
- **`roles/backend_container`**: Builds and verifies the Docker Compose Demo Portal container and monitors `/health`.
- **`roles/bigip_ltm`**: Provisions the Backend Node, HTTP Health Monitor, LTM Pool, Pool Members, and RBAC / Password metadata iRule (`rule_apm_ad_rbac_headers`).
- **`roles/bigip_aaa_ad`**: Provisions the Active Directory AAA Server Object over LDAPS 636 with SSL verification and service account authentication.
- **`roles/bigip_apm`**: Builds the APM Access Policy Profile, Logon Page, AD Auth Agent with Extended Error & K16806 Password Modify, increments policy generation, and attaches to the HTTPS Virtual Server (`10.1.10.100:443`).
- **Post-Deployment Validation**: Automatically executes the 5-case test suite (`run_test_suite.py`) confirming 100% pass rate upon deployment.

---

The automated test suite in [scripts/run_test_suite.py](file:///home/ubuntu/f5-apm-ad-lab/scripts/run_test_suite.py) validates the complete password and account lifecycle:

```
+----------------------------------------------------------------------------------------------------+
| Test Case  | Description                | Account       | Initial State  | Expected Result         |
|------------+----------------------------+---------------+----------------+-------------------------|
| TC-01      | Standard Authentication    | admin / normal| pwdLastSet > 0 | 200/302 Allowed Landing |
| TC-02      | Expired Password Reset     | user_expired  | pwdLastSet = 0 | APM Reset Prompt (K16806)|
|            | (K16806 LDAPS 636 Reset)   | & user1       | (UAC = 512)    | -> LDAPS Reset -> Allow |
| TC-03      | Voluntary Password Change  | user_voluntary| Active User    | Password Updated ->     |
|            |                            |               |                | Re-login Verified       |
| TC-04      | Negative Security Tests    | user_locked & | Invalid Pass,  | Access Denied / Error   |
|            | (Bad Pass, Lock, Exp Account)| user1       | Locked, Exp Acc| 701 Revoked Credentials |
| TC-05      | Password & Account Status  | user1         | Dynamic API &  | K16806 Banners, API     |
|            | & Lifecycle (K16806)       |               | LDAPS Modify   | Status & Restore Confirmed|
+----------------------------------------------------------------------------------------------------+
```

---

## Directory Structure

```
f5-apm-ad-lab/
├── .env                          # Active lab configuration settings
├── .env.example                  # Environment configuration template
├── requirements.txt              # Python dependencies (requests, urllib3, ldap3, python-dotenv)
├── README.md                     # Comprehensive architecture and operation guide
├── certs/
│   └── lab_root_ca.crt           # Active Directory Root CA certificate for LDAPS
└── scripts/
    ├── setup_ad_delegation.ps1   # PowerShell automation for AD OU, ACLs & Test Users
    ├── configure_f5_apm.py       # Python iControl REST provisioning for F5 TMOS & APM
    ├── portal_app.py             # Intranet Portal, K16806 expiration warnings & LDAPS backend
    ├── interactive_demo.py       # Menu-driven interactive demonstration tool (Scenarios 1-5)
    └── run_test_suite.py         # Automated verification test suite (TC-01 through TC-05)
```

---

## Prerequisites & Environment Setup

### 1. Active Directory Domain Controller
- Windows Server 2016 / 2019 / 2022 / 2025 with Active Directory Domain Services.
- Enterprise CA or Domain Controller Server Authentication Certificate installed (enabling LDAPS on port 636).
- RSAT Active Directory PowerShell module.

### 2. F5 BIG-IP TMOS
- BIG-IP TMOS v14.x, v15.x, v16.x, or v17.x with Access Policy Manager (APM) license.
- Network reachability between F5 BIG-IP Self-IP and AD DC IP on TCP port 636.
- Administrative credentials for iControl REST API.

### 3. Management Workstation
- Python 3.8+ installed.
- Install dependencies:

```bash
cd f5-apm-ad-lab
pip install -r requirements.txt
```

---

## Step-by-Step Deployment Guide

### Step 1: Configure Environment Variables

Verify `.env` has the correct IP addresses and credentials:
- `BIGIP_MGMT_IP`: `10.1.1.4`
- `AD_DC_IP`: `10.1.20.7`
- `VS_IP`: `10.1.10.100`

---

### Step 2: Restart and Verify Backend Portal Service

```bash
sudo systemctl restart portal_app
curl -s http://127.0.0.1:8000/health
# Returns: OK
```

---

### Step 3: Run Interactive Demonstration Tool

```bash
python3 scripts/interactive_demo.py --auto
```

Or run interactively:
```bash
python3 scripts/interactive_demo.py
```

---

## Automated Verification & Test Execution

Execute the test suite to validate all password management workflows:

```bash
# Run all test cases (TC-01 through TC-05)
python3 scripts/run_test_suite.py

# Run in verbose debug mode
python3 scripts/run_test_suite.py --debug

# Run an individual test case
python3 scripts/run_test_suite.py --test TC-02
```

---

## REST API Reference & Troubleshooting

### Key iControl REST Endpoints Used

| TMOS Resource | HTTP Method | REST Endpoint |
| :--- | :--- | :--- |
| **Authentication Token** | `POST` | `/mgmt/shared/authn/login` |
| **Crypto CA Certificate** | `POST` / `GET` | `/mgmt/tm/sys/crypto/cert` |
| **AAA Active Directory** | `POST` / `GET` / `PATCH` | `/mgmt/tm/apm/aaa/active-directory` |
| **APM Access Profile** | `POST` / `GET` / `PATCH` | `/mgmt/tm/apm/profile/access` |
| **LTM Virtual Server** | `POST` / `GET` / `PATCH` | `/mgmt/tm/ltm/virtual` |

### Common Troubleshooting Scenarios

1. **`pwdLastSet = 0` ignored by Active Directory**:
   - **Cause**: User object in AD has `DONT_EXPIRE_PASSWORD` flag (`0x10000` = 65536) set in `userAccountControl`.
   - **Fix**: Update `userAccountControl` to `512` (`NORMAL_ACCOUNT`) using `/expire_password` or LDAPS.

2. **Expired Account Error (`STATUS_ACCOUNT_EXPIRED` / Win32 701)**:
   - **Cause**: `accountExpires` attribute in AD is set to a past timestamp (e.g. `1`).
   - **Fix**: Reset `accountExpires` to `0` ("Never Expires") using `/unexpire_account` or `Restore Active State`.

3. **`LDAP_UNWILLING_TO_PERFORM` (Error Code 53)**:
   - **Cause**: TMOS AAA object is configured with port 389 (unencrypted) or `useSsl` is disabled.
   - **Fix**: Verify `useSsl` is set to `enabled` and port is set to `636`. Ensure the CA Certificate is installed on BIG-IP and trusted.
