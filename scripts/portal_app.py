#!/usr/bin/env python3
"""
F5 APM Corporate Intranet Portal & Self-Service Password Management Backend
==========================================================================
Provides the backend web application for the F5 APM lab virtual server:
1. Displays authenticated user info and RBAC role headers passed from F5 APM.
2. Informs users of expired or expiring passwords in accordance with F5 K16806.
3. Informs users of account expiration states (accountExpires) caught by APM.
4. Auto-restores / re-enables expired accounts & passwords via background timer (Default: 5 minutes / 300s).
5. Serves health checks on /health for BIG-IP LTM monitors.
6. Provides working in-portal LDAPS password expiration & change functionality
   on /expire_password, /expire_account, /unexpire_password, /change_password,
   and /api/password_status over LDAPS (Port 636).
"""

import os
import sys
import json
import ssl
import time
import datetime
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Load environment configuration
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env", override=True)
except Exception:
    def load_dotenv(dotenv_path=None, override=False):
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
    load_dotenv()

PORT = int(os.getenv("PORT", 8000))
HOST = "0.0.0.0"

AD_DC_IP = os.getenv("AD_DC_IP", "10.1.20.7")
AD_LDAPS_PORT = int(os.getenv("AD_LDAPS_PORT", 636))
AD_DOMAIN = os.getenv("AD_DOMAIN", "f5lab.local")
AD_SVC_USER = os.getenv("AD_SVC_USER", "admin")
AD_SVC_PASS = os.getenv("AD_SVC_PASS", "admin")
AD_BASE_DN = os.getenv("AD_BASE_DN", "DC=f5lab,DC=local")
MAX_PWD_AGE_DAYS = 90
EXPIRY_WARN_DAYS = 14
DEFAULT_AUTO_RESTORE_DELAY = 300  # 5 minutes in seconds

# Windows FileTime epoch offset (Jan 1, 1601 UTC in 100ns intervals)
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# In-memory dictionary for active auto-restore timers
# Key: sam_account (lowercase) -> dict(timer, username, type, start_time, duration_seconds, expires_at)
AUTO_RESTORE_TIMERS = {}
TIMERS_LOCK = threading.Lock()


def get_clean_sam_account(username: str) -> str:
    """Extracts raw sAMAccountName from domain\\user or user@domain formats."""
    if not username:
        return "admin"
    clean = str(username).strip()
    if "\\" in clean:
        clean = clean.split("\\")[-1]
    if "@" in clean:
        clean = clean.split("@")[0]
    return clean.strip()


def get_ldap_connection():
    """Establishes an authenticated LDAPS connection to Active Directory."""
    from ldap3 import Server, Connection, NONE, Tls
    
    server = Server(
        AD_DC_IP,
        port=AD_LDAPS_PORT,
        use_ssl=True,
        tls=Tls(validate=ssl.CERT_NONE),
        get_info=NONE,
        connect_timeout=5
    )
    
    bind_user = AD_SVC_USER
    if "@" not in bind_user and "\\" not in bind_user:
        bind_user = f"{AD_SVC_USER}@{AD_DOMAIN}"

    conn = Connection(
        server,
        user=bind_user,
        password=AD_SVC_PASS,
        auto_bind=True
    )
    return conn


def parse_filetime(val) -> tuple:
    """
    Parses Windows FileTime (100ns intervals since 1601-01-01).
    Returns (datetime_obj_or_None, is_never, is_expired).
    """
    if val is None:
        return None, True, False
    try:
        raw_int = int(val)
    except (ValueError, TypeError):
        return None, True, False

    # 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) means Never Expires
    if raw_int == 0 or raw_int == 9223372036854775807 or raw_int <= 0:
        return None, True, False

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    try:
        dt = FILETIME_EPOCH + datetime.timedelta(microseconds=raw_int / 10)
        is_exp = (dt <= now_utc)
        return dt, False, is_exp
    except OverflowError:
        return None, True, False


def cancel_user_timer(username: str) -> bool:
    """Cancels any active auto-restore timer for the specified user."""
    sam_account = get_clean_sam_account(username).lower()
    with TIMERS_LOCK:
        timer_info = AUTO_RESTORE_TIMERS.pop(sam_account, None)
        if timer_info and "timer" in timer_info:
            try:
                timer_info["timer"].cancel()
                print(f"[TIMER] Cancelled active auto-restore timer for '{sam_account}'.")
                return True
            except Exception as e:
                print(f"[TIMER] Error cancelling timer for '{sam_account}': {e}")
    return False


def get_active_timer_info(username: str) -> dict:
    """Returns active timer metadata for the user, if running."""
    sam_account = get_clean_sam_account(username).lower()
    with TIMERS_LOCK:
        timer_info = AUTO_RESTORE_TIMERS.get(sam_account)
        if not timer_info:
            return None
        now = time.time()
        expires_at = timer_info.get("expires_at", 0)
        remaining = max(0, int(expires_at - now))
        if remaining <= 0:
            return None
        mins = remaining // 60
        secs = remaining % 60
        return {
            "active": True,
            "username": timer_info.get("username", sam_account),
            "type": timer_info.get("type", "account"),
            "duration_seconds": timer_info.get("duration_seconds", 300),
            "seconds_remaining": remaining,
            "display": f"{mins:02d}:{secs:02d}",
            "expires_at": expires_at
        }


def schedule_auto_restore(username: str, restore_type: str, delay_seconds: int = 300, reset_pwd: str = None) -> dict:
    """Schedules a background Timer to re-enable/restore the account/password after delay_seconds."""
    sam_account = get_clean_sam_account(username)
    key = sam_account.lower()
    
    # Cancel any previous timer for this user
    cancel_user_timer(sam_account)
    
    if delay_seconds <= 0:
        return {"scheduled": False, "delay": 0}

    def _auto_restore_callback():
        print(f"[AUTO-RESTORE] ⏰ Timer ({delay_seconds}s) triggered for '{sam_account}'. Restoring active state in AD...")
        try:
            if restore_type == "account":
                unexpire_ad_account(sam_account)
            else:
                unexpire_ad_user_password(sam_account, reset_pwd)
            print(f"[AUTO-RESTORE] ✅ Successfully auto-restored '{sam_account}' in Active Directory via LDAPS 636.")
        except Exception as ex:
            print(f"[AUTO-RESTORE] ❌ Error executing auto-restore for '{sam_account}': {ex}")
        finally:
            with TIMERS_LOCK:
                AUTO_RESTORE_TIMERS.pop(key, None)

    t = threading.Timer(delay_seconds, _auto_restore_callback)
    t.daemon = True
    start_time = time.time()
    expires_at = start_time + delay_seconds

    with TIMERS_LOCK:
        AUTO_RESTORE_TIMERS[key] = {
            "timer": t,
            "username": sam_account,
            "type": restore_type,
            "start_time": start_time,
            "duration_seconds": delay_seconds,
            "expires_at": expires_at
        }

    t.start()
    mins = delay_seconds // 60
    secs = delay_seconds % 60
    time_str = f"{mins}m {secs}s" if secs else f"{mins}m"
    print(f"[TIMER] ⏳ Scheduled auto-restore timer for '{sam_account}' ({restore_type}) in {time_str} ({delay_seconds}s).")
    return {
        "scheduled": True,
        "delay": delay_seconds,
        "display": f"{mins:02d}:{secs:02d}",
        "expires_at": expires_at
    }


def get_ad_user_password_info(username: str) -> dict:
    """
    Queries Active Directory via LDAPS (636) to determine password lifecycle status,
    expiration state, last set timestamp, UAC flags, accountExpires, and active timers per K16806.
    """
    sam_account = get_clean_sam_account(username)
    timer_data = get_active_timer_info(sam_account)

    try:
        from ldap3 import SUBTREE
        conn = get_ldap_connection()
        conn.search(
            AD_BASE_DN,
            f"(sAMAccountName={sam_account})",
            search_scope=SUBTREE,
            attributes=[
                "distinguishedName",
                "pwdLastSet",
                "userAccountControl",
                "accountExpires",
                "lockoutTime",
                "whenChanged",
                "sAMAccountName",
                "displayName",
                "userPrincipalName"
            ]
        )

        if not conn.entries:
            conn.unbind()
            return {
                "status": "NOT_FOUND",
                "is_expired": False,
                "is_account_expired": False,
                "is_locked": False,
                "is_warning": False,
                "never_expires": False,
                "badge_class": "badge-danger",
                "status_display": "NOT FOUND",
                "account_status_display": "NOT FOUND",
                "uac_flags_display": "N/A",
                "uac_val": 0,
                "message": f"User '{sam_account}' not found in Active Directory base '{AD_BASE_DN}'.",
                "days_remaining": 0,
                "last_set_str": "Unknown",
                "account_expires_str": "Unknown",
                "username": sam_account,
                "auto_restore": timer_data
            }

        entry = conn.entries[0]
        
        # Raw attributes
        raw_pwd_last_set = entry.pwdLastSet.raw_values[0] if (hasattr(entry, "pwdLastSet") and entry.pwdLastSet.raw_values) else None
        raw_uac = entry.userAccountControl.raw_values[0] if (hasattr(entry, "userAccountControl") and entry.userAccountControl.raw_values) else None
        raw_acc_expires = entry.accountExpires.raw_values[0] if (hasattr(entry, "accountExpires") and entry.accountExpires.raw_values) else None
        raw_lockout = entry.lockoutTime.raw_values[0] if (hasattr(entry, "lockoutTime") and entry.lockoutTime.raw_values) else None
        
        conn.unbind()

        # Parse userAccountControl
        uac_val = int(raw_uac) if raw_uac else 512
        dont_expire_pwd = bool(uac_val & 0x10000)  # 65536 = DONT_EXPIRE_PASSWORD
        account_disabled = bool(uac_val & 0x00002) # 2 = ACCOUNTDISABLE
        is_locked_uac = bool(uac_val & 0x00010)    # 16 = LOCKOUT

        # Parse lockoutTime
        lockout_int = int(raw_lockout) if raw_lockout else 0
        is_locked = is_locked_uac or (lockout_int > 0)

        # Parse accountExpires
        acc_dt, acc_never, is_account_expired = parse_filetime(raw_acc_expires)
        if acc_never:
            account_expires_str = "Never Expires"
            account_status_display = "Active (Never Expires)"
        elif is_account_expired:
            account_expires_str = acc_dt.strftime("%Y-%m-%d %H:%M:%S UTC") if acc_dt else "Expired"
            account_status_display = "EXPIRED (Account Expired)"
        else:
            account_expires_str = acc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            account_status_display = f"Active (Expires {acc_dt.strftime('%Y-%m-%d')})"

        # Format UAC Display
        uac_flag_names = []
        if uac_val & 512:
            uac_flag_names.append("NORMAL_ACCOUNT")
        if dont_expire_pwd:
            uac_flag_names.append("DONT_EXPIRE_PASSWORD (Never Expires)")
        if account_disabled:
            uac_flag_names.append("ACCOUNT_DISABLED")
        if is_locked_uac:
            uac_flag_names.append("LOCKED_OUT")
        uac_flags_str = f"{uac_val} ({', '.join(uac_flag_names) if uac_flag_names else 'Default'})"

        # Parse pwdLastSet
        pwd_val = int(raw_pwd_last_set) if raw_pwd_last_set else 0

        # Case 1: Account Expired takes precedence for access
        if is_account_expired:
            timer_suffix = f" ⏳ Auto-reenable in {timer_data['display']}." if timer_data else ""
            return {
                "status": "ACCOUNT_EXPIRED",
                "is_expired": False,
                "is_account_expired": True,
                "is_locked": is_locked,
                "is_warning": False,
                "never_expires": dont_expire_pwd,
                "badge_class": "badge-danger",
                "status_display": "ACCOUNT EXPIRED (accountExpires)",
                "account_status_display": account_status_display,
                "uac_flags_display": uac_flags_str,
                "uac_val": uac_val,
                "message": f"Active Directory account has EXPIRED (accountExpires: {account_expires_str}). F5 APM will catch this state and deny authentication with Win32 error 701 (STATUS_ACCOUNT_EXPIRED / Revoked Credentials).{timer_suffix}",
                "days_remaining": 0,
                "last_set_str": "Active",
                "account_expires_str": account_expires_str,
                "username": sam_account,
                "auto_restore": timer_data
            }

        # Case 2: Account Locked Out
        if is_locked or account_disabled:
            return {
                "status": "LOCKED",
                "is_expired": False,
                "is_account_expired": False,
                "is_locked": True,
                "is_warning": False,
                "never_expires": dont_expire_pwd,
                "badge_class": "badge-danger",
                "status_display": "LOCKED / DISABLED",
                "account_status_display": "Locked Out" if is_locked else "Disabled",
                "uac_flags_display": uac_flags_str,
                "uac_val": uac_val,
                "message": f"User account is locked out or disabled in Active Directory. Access will be denied by F5 APM.",
                "days_remaining": 0,
                "last_set_str": "N/A",
                "account_expires_str": account_expires_str,
                "username": sam_account,
                "auto_restore": timer_data
            }

        # Case 3: Password Must Change flag (pwdLastSet = 0)
        if pwd_val == 0:
            timer_suffix = f" ⏳ Auto-restore in {timer_data['display']}." if timer_data else ""
            if dont_expire_pwd:
                return {
                    "status": "UAC_NEVER_OVERRIDE",
                    "is_expired": False,
                    "is_account_expired": False,
                    "is_locked": False,
                    "is_warning": True,
                    "never_expires": True,
                    "badge_class": "badge-warning",
                    "status_display": "UAC NEVER EXPIRES (Override Active)",
                    "account_status_display": account_status_display,
                    "uac_flags_display": uac_flags_str,
                    "uac_val": uac_val,
                    "message": f"User has pwdLastSet = 0, but userAccountControl has 'DONT_EXPIRE_PASSWORD' (0x10000 = 65536) set. Active Directory will bypass expiration until UAC is set to 512. Click 'Expire Password' to clear this flag for APM K16806 testing.{timer_suffix}",
                    "days_remaining": 999,
                    "last_set_str": "Never (Must Change Pending UAC Fix)",
                    "account_expires_str": account_expires_str,
                    "username": sam_account,
                    "auto_restore": timer_data
                }
            else:
                return {
                    "status": "EXPIRED",
                    "is_expired": True,
                    "is_account_expired": False,
                    "is_locked": False,
                    "is_warning": False,
                    "never_expires": False,
                    "badge_class": "badge-danger",
                    "status_display": "EXPIRED (Must change at next logon)",
                    "account_status_display": account_status_display,
                    "uac_flags_display": uac_flags_str,
                    "uac_val": uac_val,
                    "message": f"Your Active Directory password has expired (pwdLastSet = 0, DONT_EXPIRE_PASSWORD cleared). F5 APM will catch this and enforce a password change upon next logon per K16806 policy.{timer_suffix}",
                    "last_set_str": "Never (Must Change at Next Logon)",
                    "account_expires_str": account_expires_str,
                    "days_remaining": 0,
                    "age_days": 0,
                    "username": sam_account,
                    "auto_restore": timer_data
                }

        # Case 4: Password Timestamp Calculation
        dt = FILETIME_EPOCH + datetime.timedelta(microseconds=pwd_val / 10)
        now = datetime.datetime.now(datetime.timezone.utc)
        age_days = (now - dt).days

        # Case 4a: Password Never Expires Flag
        if dont_expire_pwd:
            return {
                "status": "NEVER_EXPIRES",
                "is_expired": False,
                "is_account_expired": False,
                "is_locked": False,
                "is_warning": False,
                "never_expires": True,
                "badge_class": "badge-success",
                "status_display": "ACTIVE (Never Expires)",
                "account_status_display": account_status_display,
                "uac_flags_display": uac_flags_str,
                "uac_val": uac_val,
                "message": "Password is active and flagged to never expire (userAccountControl = 66048 / DONT_EXPIRE_PASSWORD).",
                "last_set_str": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "account_expires_str": account_expires_str,
                "days_remaining": 999,
                "age_days": age_days,
                "username": sam_account,
                "auto_restore": timer_data
            }

        # Case 4b: Domain Age Expiration check (MAX_PWD_AGE_DAYS = 90)
        days_rem = max(0, MAX_PWD_AGE_DAYS - age_days)
        is_exp = (days_rem == 0)
        is_warn = (days_rem <= EXPIRY_WARN_DAYS and not is_exp)

        if is_exp:
            status = "EXPIRED"
            status_display = "EXPIRED (Maximum Age Exceeded)"
            badge_class = "badge-danger"
            msg = f"Your password expired {age_days - MAX_PWD_AGE_DAYS} days ago (Domain Max Age: {MAX_PWD_AGE_DAYS} days). F5 APM will require a password reset per K16806."
        elif is_warn:
            status = "EXPIRING_SOON"
            status_display = f"EXPIRING SOON ({days_rem} days left)"
            badge_class = "badge-warning"
            msg = f"⚠️ Password Expiration Notice (K16806): Your Active Directory password will expire in {days_rem} days. Please update it using the self-service button."
        else:
            status = "ACTIVE"
            status_display = f"ACTIVE ({days_rem} days remaining)"
            badge_class = "badge-success"
            msg = f"Password is active and healthy ({days_rem} days until scheduled expiration)."

        return {
            "status": status,
            "is_expired": is_exp,
            "is_account_expired": False,
            "is_locked": False,
            "is_warning": is_warn,
            "never_expires": False,
            "badge_class": badge_class,
            "status_display": status_display,
            "account_status_display": account_status_display,
            "uac_flags_display": uac_flags_str,
            "uac_val": uac_val,
            "message": msg,
            "last_set_str": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "account_expires_str": account_expires_str,
            "days_remaining": days_rem,
            "age_days": age_days,
            "username": sam_account,
            "auto_restore": timer_data
        }
    except Exception as ex:
        return {
            "status": "ERROR",
            "is_expired": False,
            "is_account_expired": False,
            "is_locked": False,
            "is_warning": False,
            "never_expires": False,
            "badge_class": "badge-danger",
            "status_display": "ERROR",
            "account_status_display": "ERROR",
            "uac_flags_display": "ERROR",
            "uac_val": 0,
            "message": f"Active Directory LDAPS lookup error: {ex}",
            "days_remaining": 0,
            "last_set_str": "Error",
            "account_expires_str": "Error",
            "username": sam_account,
            "auto_restore": timer_data
        }


def change_ad_user_password(username: str, old_pwd: str, new_pwd: str) -> tuple:
    """Modifies user password in Active Directory via LDAPS (636)."""
    sam_account = get_clean_sam_account(username)
    cancel_user_timer(sam_account)
    try:
        from ldap3 import MODIFY_REPLACE, SUBTREE
        conn = get_ldap_connection()

        # Locate user DN by sAMAccountName
        conn.search(AD_BASE_DN, f"(sAMAccountName={sam_account})", search_scope=SUBTREE, attributes=["distinguishedName", "userAccountControl"])
        if conn.entries:
            user_dn = str(conn.entries[0].distinguishedName.value)
        else:
            conn.unbind()
            return False, f"Active Directory user '{sam_account}' was not found in directory base '{AD_BASE_DN}'."

        unicode_pwd = f'"{new_pwd}"'.encode("utf-16-le")
        mod_ok = conn.modify(user_dn, {
            "unicodePwd": [(MODIFY_REPLACE, [unicode_pwd])],
            "pwdLastSet": [(MODIFY_REPLACE, [-1])],
            "userAccountControl": [(MODIFY_REPLACE, [512])],
            "accountExpires": [(MODIFY_REPLACE, [0])],
            "lockoutTime": [(MODIFY_REPLACE, [0])]
        })
        if not mod_ok:
            err = conn.result.get("description") or conn.result.get("message") or str(conn.result)
            conn.unbind()
            return False, f"Active Directory LDAPS error: {err}"

        conn.unbind()
        return True, f"Active Directory password for '{sam_account}' successfully updated over LDAPS (Port {AD_LDAPS_PORT})."
    except Exception as ex:
        return False, f"Active Directory LDAPS error: {ex}"


def expire_ad_user_password(username: str, temp_password: str = None, auto_restore_delay: int = DEFAULT_AUTO_RESTORE_DELAY) -> tuple:
    """
    Sets pwdLastSet = 0, CLEARS DONT_EXPIRE_PASSWORD from userAccountControl (setting UAC=512),
    ensures accountExpires = 0 (Active Account), clears lockoutTime, optionally sets a known
    temporary password in Active Directory via LDAPS (636), and schedules a 5-minute auto-restore timer.
    """
    sam_account = get_clean_sam_account(username)
    try:
        from ldap3 import MODIFY_REPLACE, SUBTREE
        conn = get_ldap_connection()

        conn.search(AD_BASE_DN, f"(sAMAccountName={sam_account})", search_scope=SUBTREE, attributes=["distinguishedName", "userAccountControl", "pwdLastSet"])
        if conn.entries:
            user_dn = str(conn.entries[0].distinguishedName.value)
        else:
            conn.unbind()
            return False, f"Active Directory user '{sam_account}' was not found in directory base '{AD_BASE_DN}'."

        # If a temp/known password is provided, set unicodePwd first
        if temp_password:
            unicode_pwd = f'"{temp_password}"'.encode("utf-16-le")
            pwd_ok = conn.modify(user_dn, {"unicodePwd": [(MODIFY_REPLACE, [unicode_pwd])]})
            if not pwd_ok:
                err = conn.result.get("description") or conn.result.get("message") or str(conn.result)
                conn.unbind()
                return False, f"Failed to set temporary password in Active Directory: {err}"

        # Clear DONT_EXPIRE_PASSWORD (0x10000) by setting UAC=512, set pwdLastSet = 0, set accountExpires = 0
        mod_ok = conn.modify(user_dn, {
            "userAccountControl": [(MODIFY_REPLACE, [512])],
            "pwdLastSet": [(MODIFY_REPLACE, [0])],
            "accountExpires": [(MODIFY_REPLACE, [0])],
            "lockoutTime": [(MODIFY_REPLACE, [0])]
        })
        if not mod_ok:
            err = conn.result.get("description") or conn.result.get("message") or str(conn.result)
            conn.unbind()
            return False, f"Active Directory LDAPS error: {err}"

        conn.unbind()

        # Schedule auto-restore timer (5 minutes by default)
        timer_info = None
        if auto_restore_delay > 0:
            timer_info = schedule_auto_restore(sam_account, restore_type="password", delay_seconds=auto_restore_delay, reset_pwd=temp_password or "bigip123")

        time_note = f" (Auto-re-enabling in {auto_restore_delay//60}m {auto_restore_delay%60}s)" if auto_restore_delay > 0 else ""
        if temp_password:
            return True, f"Password for '{sam_account}' set to '{temp_password}' and marked EXPIRED in Active Directory (pwdLastSet = 0, UAC = 512, account active). Next logon via F5 APM will enforce the K16806 password change prompt.{time_note}"
        else:
            return True, f"Password for '{sam_account}' has been expired in Active Directory (pwdLastSet = 0, UAC = 512 DONT_EXPIRE_PASSWORD cleared, account active). Next logon via F5 APM will enforce the K16806 password change prompt.{time_note}"
    except Exception as ex:
        return False, f"Active Directory LDAPS error: {ex}"


def expire_ad_account(username: str, auto_restore_delay: int = DEFAULT_AUTO_RESTORE_DELAY) -> tuple:
    """
    Sets accountExpires = 1 in Active Directory via LDAPS (636) to simulate an expired AD user account.
    F5 APM will catch this state during authentication and deny access with STATUS_ACCOUNT_EXPIRED (Win32 701).
    Automatically schedules a 5-minute background timer to re-enable the account after expiration.
    """
    sam_account = get_clean_sam_account(username)
    try:
        from ldap3 import MODIFY_REPLACE, SUBTREE
        conn = get_ldap_connection()

        conn.search(AD_BASE_DN, f"(sAMAccountName={sam_account})", search_scope=SUBTREE, attributes=["distinguishedName"])
        if conn.entries:
            user_dn = str(conn.entries[0].distinguishedName.value)
        else:
            conn.unbind()
            return False, f"Active Directory user '{sam_account}' was not found in directory base '{AD_BASE_DN}'."

        # Set accountExpires = 1 (Jan 1, 1601 - expired in the past)
        mod_ok = conn.modify(user_dn, {
            "accountExpires": [(MODIFY_REPLACE, [1])],
            "lockoutTime": [(MODIFY_REPLACE, [0])]
        })
        if not mod_ok:
            err = conn.result.get("description") or conn.result.get("message") or str(conn.result)
            conn.unbind()
            return False, f"Active Directory LDAPS error: {err}"

        conn.unbind()

        # Schedule auto-restore timer (5 minutes by default)
        timer_info = None
        if auto_restore_delay > 0:
            timer_info = schedule_auto_restore(sam_account, restore_type="account", delay_seconds=auto_restore_delay)

        time_note = f" (Auto-re-enabling account in {auto_restore_delay//60}m {auto_restore_delay%60}s)" if auto_restore_delay > 0 else ""
        return True, f"Account '{sam_account}' is now marked EXPIRED in Active Directory (accountExpires = 1). Next logon via F5 APM will be caught and denied with STATUS_ACCOUNT_EXPIRED (Win32 error 701 / Credentials Revoked).{time_note}"
    except Exception as ex:
        return False, f"Active Directory LDAPS error: {ex}"


def unexpire_ad_account(username: str) -> tuple:
    """Sets accountExpires = 0 in Active Directory via LDAPS (636) to restore active account state."""
    sam_account = get_clean_sam_account(username)
    cancel_user_timer(sam_account)
    try:
        from ldap3 import MODIFY_REPLACE, SUBTREE
        conn = get_ldap_connection()

        conn.search(AD_BASE_DN, f"(sAMAccountName={sam_account})", search_scope=SUBTREE, attributes=["distinguishedName"])
        if conn.entries:
            user_dn = str(conn.entries[0].distinguishedName.value)
        else:
            conn.unbind()
            return False, f"Active Directory user '{sam_account}' was not found in directory base '{AD_BASE_DN}'."

        mod_ok = conn.modify(user_dn, {
            "accountExpires": [(MODIFY_REPLACE, [0])],
            "lockoutTime": [(MODIFY_REPLACE, [0])]
        })
        if not mod_ok:
            err = conn.result.get("description") or conn.result.get("message") or str(conn.result)
            conn.unbind()
            return False, f"Active Directory LDAPS error: {err}"

        conn.unbind()
        return True, f"Account '{sam_account}' is now ACTIVE in Active Directory (accountExpires = Never Expires)."
    except Exception as ex:
        return False, f"Active Directory LDAPS error: {ex}"


def unexpire_ad_user_password(username: str, reset_password: str = None) -> tuple:
    """Sets pwdLastSet = -1, accountExpires = 0, UAC = 512 in Active Directory via LDAPS (636) to restore fully active password and account state."""
    sam_account = get_clean_sam_account(username)
    cancel_user_timer(sam_account)
    try:
        from ldap3 import MODIFY_REPLACE, SUBTREE
        conn = get_ldap_connection()

        conn.search(AD_BASE_DN, f"(sAMAccountName={sam_account})", search_scope=SUBTREE, attributes=["distinguishedName", "pwdLastSet"])
        if conn.entries:
            user_dn = str(conn.entries[0].distinguishedName.value)
        else:
            conn.unbind()
            return False, f"Active Directory user '{sam_account}' was not found in directory base '{AD_BASE_DN}'."

        if reset_password:
            unicode_pwd = f'"{reset_password}"'.encode("utf-16-le")
            pwd_ok = conn.modify(user_dn, {"unicodePwd": [(MODIFY_REPLACE, [unicode_pwd])]})
            if not pwd_ok:
                err = conn.result.get("description") or conn.result.get("message") or str(conn.result)
                conn.unbind()
                return False, f"Failed to set reset password in Active Directory: {err}"

        mod_ok = conn.modify(user_dn, {
            "pwdLastSet": [(MODIFY_REPLACE, [-1])],
            "userAccountControl": [(MODIFY_REPLACE, [512])],
            "accountExpires": [(MODIFY_REPLACE, [0])],
            "lockoutTime": [(MODIFY_REPLACE, [0])]
        })
        if not mod_ok:
            err = conn.result.get("description") or conn.result.get("message") or str(conn.result)
            conn.unbind()
            return False, f"Active Directory LDAPS error: {err}"

        conn.unbind()
        return True, f"User '{sam_account}' is now fully ACTIVE in Active Directory (pwdLastSet = -1, accountExpires = Never, UAC = 512, lockout cleared)."
    except Exception as ex:
        return False, f"Active Directory LDAPS error: {ex}"


HTML_PORTAL = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>F5 APM Corporate Intranet Portal - AD Password & Account Management</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; margin: 0; }
    .card { background: #1e293b; border-radius: 12px; padding: 32px; max-width: 900px; margin: 25px auto; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
    h1 { color: #38bdf8; margin: 0 0 6px 0; font-size: 24px; }
    .subtitle { color: #94a3b8; margin: 0 0 18px 0; font-size: 13px; }
    .badge { padding: 5px 12px; border-radius: 6px; font-weight: 700; font-size: 12px; letter-spacing: 0.5px; display: inline-block; }
    .badge-success { background: #10b981; color: white; }
    .badge-warning { background: #f59e0b; color: #1e293b; font-weight: 800; }
    .badge-danger { background: #ef4444; color: white; }
    .badge-info { background: #0284c7; color: white; }
    .badge-purple { background: #8b5cf6; color: white; }
    .badge-timer { background: #3b82f6; color: white; animation: pulse 2s infinite; }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.75; } 100% { opacity: 1; } }
    .row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #334155; font-size: 14px; }
    .label { color: #94a3b8; }
    .val { font-weight: 600; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: #f1f5f9; }
    .btn-group { margin-top: 24px; display: flex; gap: 10px; flex-wrap: wrap; }
    .btn { display: inline-flex; align-items: center; justify-content: center; padding: 10px 18px; background: #0284c7; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 13px; border: none; cursor: pointer; transition: background 0.2s; }
    .btn:hover { background: #0369a1; }
    .btn-danger { background: #ef4444; }
    .btn-danger:hover { background: #dc2626; }
    .btn-warning { background: #d97706; }
    .btn-warning:hover { background: #b45309; }
    .btn-purple { background: #7c3aed; }
    .btn-purple:hover { background: #6d28d9; }
    .btn-success { background: #059669; }
    .btn-success:hover { background: #047857; }
    .btn-secondary { background: #475569; }
    .btn-secondary:hover { background: #334155; }
    .btn-sm { padding: 5px 10px; font-size: 11px; border-radius: 4px; }
    
    /* Section Box */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 18px 0; }
    @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
    .section-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 16px; position: relative; }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid #1e293b; padding-bottom: 6px; }
    .section-title { font-weight: 700; color: #38bdf8; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
    
    /* Quick User Chips */
    .chip-group { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
    .chip { background: #334155; color: #e2e8f0; padding: 5px 10px; border-radius: 16px; font-size: 11px; font-family: monospace; cursor: pointer; border: 1px solid #475569; transition: all 0.2s; }
    .chip:hover, .chip.active { background: #0284c7; color: white; border-color: #38bdf8; }
    
    /* Timer Display Pill */
    .timer-pill { display: inline-flex; align-items: center; gap: 6px; background: #1e3a8a; border: 1px solid #3b82f6; color: #93c5fd; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 700; font-family: monospace; }
    
    /* Modal Styles */
    .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(4px); z-index: 1000; justify-content: center; align-items: center; }
    .modal-card { background: #1e293b; border-radius: 12px; padding: 26px; width: 100%; max-width: 520px; border: 1px solid #475569; box-shadow: 0 20px 35px rgba(0,0,0,0.5); }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .modal-title { color: #38bdf8; font-size: 18px; font-weight: 700; margin: 0; }
    .form-group { margin-bottom: 14px; }
    .form-group label { display: block; margin-bottom: 5px; font-size: 13px; color: #94a3b8; }
    .form-control { width: 100%; padding: 9px 12px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; font-size: 13px; box-sizing: border-box; }
    .form-control:focus { outline: none; border-color: #38bdf8; }
    .alert { padding: 12px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; line-height: 1.5; }
    .alert-success { background: #064e3b; color: #6ee7b7; border: 1px solid #059669; }
    .alert-error { background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
    .alert-warning { background: #78350f; color: #fde68a; border: 1px solid #d97706; }
    .alert-info { background: #0c4a6e; color: #7dd3fc; border: 1px solid #0284c7; }
  </style>
</head>
<body>
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 12px;">
      <div>
        <h1>F5 APM Corporate Intranet Portal</h1>
        <p class="subtitle">Active Directory Password & Account Management (LDAPS Port 636 & F5 K16806)</p>
      </div>
      <div style="display:flex; gap:6px; align-items:center;">
        <div id="liveTimerPill" class="timer-pill" style="display:none;">⏳ <span id="liveTimerText">05:00</span></div>
        <span class="badge badge-success">LDAPS 636</span>
        <span class="badge badge-info">F5 K16806 READY</span>
      </div>
    </div>

    <!-- Dynamic Alert Banners (Password Expiration & Account Expiration) -->
    <div id="expirationBanner" class="alert __BANNER_CLASS__" style="display:__BANNER_DISPLAY__;">
      __BANNER_CONTENT__
    </div>

    <div id="portalAlert" class="alert" style="display:none;"></div>
    
    <!-- User and Session Info -->
    <div class="row"><span class="label">Active Directory User</span><span class="val" id="disp_user">__USER__</span></div>
    <div class="row"><span class="label">Assigned Role</span><span class="val">__ROLE__</span></div>
    <div class="row"><span class="label">Domain (FQDN)</span><span class="val">__DOMAIN__</span></div>
    <div class="row"><span class="label">Client IP Address</span><span class="val">__CLIENT_IP__</span></div>
    <div class="row"><span class="label">Virtual Server Target</span><span class="val">10.1.10.100:443 (vs_apm_ad_lab_https)</span></div>
    <div class="row"><span class="label">APM Access Profile</span><span class="val">ap_ad_password_mgmt</span></div>
    
    <!-- Status Grid: Password Lifecycle vs Account Status -->
    <div class="grid-2">
      <!-- Box 1: Password Lifecycle (K16806) -->
      <div class="section-box">
        <div class="section-header">
          <span class="section-title">Password Lifecycle (K16806)</span>
          <button class="btn btn-secondary btn-sm" onclick="refreshPasswordStatus()">↻ Refresh</button>
        </div>
        <div class="row" style="border-bottom:none; padding: 4px 0;">
          <span class="label">Password Status</span>
          <span id="stat_badge" class="badge __BADGE_CLASS__">__STATUS_DISPLAY__</span>
        </div>
        <div class="row" style="border-bottom:none; padding: 4px 0;">
          <span class="label">Last Password Set</span>
          <span id="stat_last_set" class="val">__LAST_SET_STR__</span>
        </div>
        <div class="row" style="border-bottom:none; padding: 4px 0;">
          <span class="label">Days Remaining</span>
          <span id="stat_days" class="val">__DAYS_REMAINING__ days</span>
        </div>
        <div class="row" style="border-bottom:none; padding: 4px 0;">
          <span class="label">UAC Flags</span>
          <span id="stat_uac" class="val" style="font-size:11px; color:#38bdf8;">__UAC_FLAGS__</span>
        </div>
      </div>

      <!-- Box 2: AD Account Status -->
      <div class="section-box">
        <div class="section-header">
          <span class="section-title">AD Account Status</span>
          <span id="stat_acc_badge" class="badge badge-info">__ACCOUNT_STATUS_DISPLAY__</span>
        </div>
        <div class="row" style="border-bottom:none; padding: 4px 0;">
          <span class="label">Account Expiration</span>
          <span id="stat_acc_expires" class="val">__ACCOUNT_EXPIRES_STR__</span>
        </div>
        <div class="row" style="border-bottom:none; padding: 4px 0;">
          <span class="label">Auto-Restore Timer</span>
          <span id="stat_timer_display" class="val" style="color:#60a5fa; font-size:12px;">__TIMER_STATUS__</span>
        </div>
        <div class="row" style="border-bottom:none; padding: 4px 0;">
          <span class="label">APM Extended Error</span>
          <span class="val" style="font-size:12px; color:#10b981;">Enabled (532 / 701 / 773)</span>
        </div>
      </div>
    </div>

    <!-- Action Buttons -->
    <div class="btn-group">
      <button type="button" class="btn" onclick="openPasswordModal()">Change Password (LDAPS 636)</button>
      <button type="button" class="btn btn-warning" onclick="openExpireModal()">Expire Password (K16806 Test)</button>
      <button type="button" class="btn btn-purple" onclick="openExpireAccountModal()">Expire Account (AD Test)</button>
      <button type="button" class="btn btn-success" onclick="quickUnexpire(document.getElementById('disp_user')?.innerText || currentUser)">Restore Active State</button>
      <a href="/vdesk/hangup.php3" class="btn btn-danger">Sign Out (Test APM)</a>
    </div>
  </div>

  <!-- Password Change Modal -->
  <div id="pwdModal" class="modal-overlay">
    <div class="modal-card">
      <div class="modal-header">
        <h2 class="modal-title">Change Active Directory Password</h2>
        <span style="cursor:pointer; font-size:24px; color:#94a3b8;" onclick="closePasswordModal()">&times;</span>
      </div>

      <div id="modalAlert" class="alert" style="display:none;"></div>

      <form id="pwdForm" onsubmit="handlePasswordSubmit(event)">
        <input type="hidden" name="username" value="__USER__">
        
        <div class="form-group">
          <label for="old_pass">Current Password</label>
          <input type="password" id="old_pass" name="_sys_password_old" class="form-control" required autocomplete="current-password">
        </div>

        <div class="form-group">
          <label for="new_pass">New Password (Min 8 chars, Uppercase, Lowercase, Number, Symbol)</label>
          <input type="password" id="new_pass" name="_sys_password_new" class="form-control" required autocomplete="new-password">
        </div>

        <div class="form-group">
          <label for="confirm_pass">Confirm New Password</label>
          <input type="password" id="confirm_pass" name="_sys_password_confirm" class="form-control" required autocomplete="new-password">
        </div>

        <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:18px;">
          <button type="button" class="btn btn-secondary" onclick="closePasswordModal()">Cancel</button>
          <button type="submit" id="btnSubmitPwd" class="btn">Update Password (LDAPS)</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Expire Password Modal (K16806 Test Utility) -->
  <div id="expireModal" class="modal-overlay">
    <div class="modal-card">
      <div class="modal-header">
        <h2 class="modal-title" style="color:#fbbf24;">Expire Active Directory Password (K16806)</h2>
        <span style="cursor:pointer; font-size:24px; color:#94a3b8;" onclick="closeExpireModal()">&times;</span>
      </div>

      <div id="expireModalAlert" class="alert" style="display:none;"></div>

      <p style="color:#94a3b8; font-size:13px; line-height:1.5; margin-bottom:12px;">
        1. Clears <code>DONT_EXPIRE_PASSWORD</code> (0x10000) from <code>userAccountControl</code> (sets UAC=512).<br>
        2. Sets <code>pwdLastSet = 0</code> and <code>accountExpires = 0</code> in Active Directory via LDAPS (636).<br>
        3. F5 BIG-IP APM catches extended error 532/773 and displays the <strong>Password Expired Prompt</strong> per <strong>K16806</strong>.
      </p>

      <form id="expireForm" onsubmit="handleExpireSubmit(event)">
        <div class="form-group">
          <label for="expire_user">Target Active Directory User</label>
          <input type="text" id="expire_user" name="username" value="__USER__" class="form-control" required placeholder="sAMAccountName">
          <div class="chip-group">
            <span class="chip" onclick="selectExpireUser('user1', 'user1')">user1</span>
            <span class="chip" onclick="selectExpireUser('user_expired', 'MustChange123!')">user_expired</span>
            <span class="chip" onclick="selectExpireUser('user_normal', 'InitialPass123!')">user_normal</span>
            <span class="chip" onclick="selectExpireUser('user_voluntary', 'VoluntaryPass123!')">user_voluntary</span>
            <span class="chip" onclick="selectExpireUser('admin', 'admin')">admin</span>
          </div>
        </div>

        <div class="form-group">
          <label for="expire_temp_pass">Temporary / Known Password to Set in AD (Optional)</label>
          <input type="text" id="expire_temp_pass" name="temp_password" placeholder="e.g. user1 or MustChange123! (sets known password in AD)" class="form-control">
          <small style="color:#64748b; font-size:11px;">If specified, updates <code>unicodePwd</code> in AD over LDAPS so you can easily log in on the APM logon page.</small>
        </div>

        <div class="form-group">
          <label for="expire_pwd_timer">⏰ Auto-Restore Active State Timer</label>
          <select id="expire_pwd_timer" name="timer_seconds" class="form-control">
            <option value="300" selected>5 Minutes (300 seconds) - Recommended</option>
            <option value="60">1 Minute (60 seconds) - Quick Test</option>
            <option value="120">2 Minutes (120 seconds)</option>
            <option value="600">10 Minutes (600 seconds)</option>
            <option value="0">No Auto-Restore (Manual Restore Only)</option>
          </select>
          <small style="color:#64748b; font-size:11px;">A background timer will automatically re-enable the user after the chosen duration.</small>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:18px;">
          <button type="button" class="btn btn-secondary" onclick="closeExpireModal()">Cancel</button>
          <div style="display:flex; gap:8px;">
            <button type="button" class="btn btn-success btn-sm" onclick="quickUnexpire(document.getElementById('expire_user').value)">Restore Active</button>
            <button type="submit" id="btnSubmitExpire" class="btn btn-warning">Expire Password Now</button>
          </div>
        </div>
      </form>
    </div>
  </div>

  <!-- Expire Account Modal (Account Expiration Test Utility) -->
  <div id="expireAccountModal" class="modal-overlay">
    <div class="modal-card">
      <div class="modal-header">
        <h2 class="modal-title" style="color:#c084fc;">Expire Active Directory Account (accountExpires)</h2>
        <span style="cursor:pointer; font-size:24px; color:#94a3b8;" onclick="closeExpireAccountModal()">&times;</span>
      </div>

      <div id="expireAccountModalAlert" class="alert" style="display:none;"></div>

      <p style="color:#94a3b8; font-size:13px; line-height:1.5; margin-bottom:12px;">
        Sets <code>accountExpires = 1</code> in Active Directory via LDAPS (636). When the user authenticates through F5 APM, APM catches Win32 error 701 (<code>STATUS_ACCOUNT_EXPIRED</code>) and denies access with <em>"Client's credentials have been revoked"</em>.
      </p>

      <form id="expireAccountForm" onsubmit="handleExpireAccountSubmit(event)">
        <div class="form-group">
          <label for="expire_acc_user">Target Active Directory User</label>
          <input type="text" id="expire_acc_user" name="username" value="__USER__" class="form-control" required placeholder="sAMAccountName">
          <div class="chip-group">
            <span class="chip" onclick="selectExpireAccUser('user1')">user1</span>
            <span class="chip" onclick="selectExpireAccUser('user_locked')">user_locked</span>
            <span class="chip" onclick="selectExpireAccUser('user_normal')">user_normal</span>
            <span class="chip" onclick="selectExpireAccUser('user_expired')">user_expired</span>
            <span class="chip" onclick="selectExpireAccUser('admin')">admin</span>
          </div>
        </div>

        <div class="form-group">
          <label for="expire_acc_timer">⏰ Auto-Reenable Account Timer</label>
          <select id="expire_acc_timer" name="timer_seconds" class="form-control">
            <option value="300" selected>5 Minutes (300 seconds) - Recommended</option>
            <option value="60">1 Minute (60 seconds) - Quick Test</option>
            <option value="120">2 Minutes (120 seconds)</option>
            <option value="600">10 Minutes (600 seconds)</option>
            <option value="0">No Auto-Restore (Manual Restore Only)</option>
          </select>
          <small style="color:#64748b; font-size:11px;">Automatically restores <code>accountExpires = 0</code> after 5 minutes so test accounts stay clean.</small>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:18px;">
          <button type="button" class="btn btn-secondary" onclick="closeExpireAccountModal()">Cancel</button>
          <div style="display:flex; gap:8px;">
            <button type="button" class="btn btn-success btn-sm" onclick="quickUnexpire(document.getElementById('expire_acc_user').value)">Restore Active</button>
            <button type="submit" id="btnSubmitExpireAcc" class="btn btn-purple">Expire Account Now</button>
          </div>
        </div>
      </form>
    </div>
  </div>

  <script>
    const currentUser = '__USER__';
    let countdownSeconds = 0;
    let countdownInterval = null;

    function startLiveCountdown(seconds) {
      if (countdownInterval) clearInterval(countdownInterval);
      countdownSeconds = seconds;
      const pill = document.getElementById('liveTimerPill');
      const text = document.getElementById('liveTimerText');
      if (seconds <= 0) {
        if (pill) pill.style.display = 'none';
        return;
      }
      if (pill) pill.style.display = 'inline-flex';
      
      function updateDisplay() {
        if (countdownSeconds <= 0) {
          if (pill) pill.style.display = 'none';
          clearInterval(countdownInterval);
          refreshPasswordStatus();
          return;
        }
        const m = Math.floor(countdownSeconds / 60);
        const s = countdownSeconds % 60;
        const str = (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
        if (text) text.innerText = str;
        const statTimer = document.getElementById('stat_timer_display');
        if (statTimer) statTimer.innerText = 'Active (Re-enables in ' + str + ')';
        countdownSeconds--;
      }
      updateDisplay();
      countdownInterval = setInterval(updateDisplay, 1000);
    }

    function openPasswordModal() {
      document.getElementById('pwdModal').style.display = 'flex';
      document.getElementById('modalAlert').style.display = 'none';
      document.getElementById('old_pass').value = '';
      document.getElementById('new_pass').value = '';
      document.getElementById('confirm_pass').value = '';
      document.getElementById('old_pass').focus();
    }

    function closePasswordModal() {
      document.getElementById('pwdModal').style.display = 'none';
    }

    function openExpireModal() {
      document.getElementById('expireModal').style.display = 'flex';
      document.getElementById('expireModalAlert').style.display = 'none';
      document.getElementById('expire_user').value = currentUser;
      document.getElementById('expire_temp_pass').value = '';
      document.querySelectorAll('#expireModal .chip').forEach(c => c.classList.remove('active'));
      document.getElementById('expire_user').focus();
    }

    function closeExpireModal() {
      document.getElementById('expireModal').style.display = 'none';
    }

    function openExpireAccountModal() {
      document.getElementById('expireAccountModal').style.display = 'flex';
      document.getElementById('expireAccountModalAlert').style.display = 'none';
      document.getElementById('expire_acc_user').value = currentUser;
      document.querySelectorAll('#expireAccountModal .chip').forEach(c => c.classList.remove('active'));
      document.getElementById('expire_acc_user').focus();
    }

    function closeExpireAccountModal() {
      document.getElementById('expireAccountModal').style.display = 'none';
    }

    function selectExpireUser(u, defaultPwd) {
      document.getElementById('expire_user').value = u;
      if (defaultPwd) {
        document.getElementById('expire_temp_pass').value = defaultPwd;
      }
      document.querySelectorAll('#expireModal .chip').forEach(c => {
        if (c.innerText.trim() === u) {
          c.classList.add('active');
        } else {
          c.classList.remove('active');
        }
      });
    }

    function selectExpireAccUser(u) {
      document.getElementById('expire_acc_user').value = u;
      document.querySelectorAll('#expireAccountModal .chip').forEach(c => {
        if (c.innerText.trim() === u) {
          c.classList.add('active');
        } else {
          c.classList.remove('active');
        }
      });
    }

    async function refreshPasswordStatus(targetUser) {
      const userToQuery = targetUser || (document.getElementById('disp_user')?.innerText) || currentUser;
      try {
        const resp = await fetch('/api/password_status?user=' + encodeURIComponent(userToQuery));
        if (resp.ok) {
          const data = await resp.json();
          document.getElementById('stat_badge').className = 'badge ' + (data.badge_class || 'badge-info');
          document.getElementById('stat_badge').innerText = data.status_display || data.status;
          document.getElementById('stat_last_set').innerText = data.last_set_str || 'Unknown';
          document.getElementById('stat_days').innerText = data.days_remaining + ' days';
          if (document.getElementById('stat_uac')) {
            document.getElementById('stat_uac').innerText = data.uac_flags_display || 'Default';
          }
          if (document.getElementById('stat_acc_badge')) {
            document.getElementById('stat_acc_badge').className = 'badge ' + (data.is_account_expired ? 'badge-danger' : 'badge-info');
            document.getElementById('stat_acc_badge').innerText = data.account_status_display || 'Active';
          }
          if (document.getElementById('stat_acc_expires')) {
            document.getElementById('stat_acc_expires').innerText = data.account_expires_str || 'Never Expires';
          }
          if (document.getElementById('disp_user')) {
            document.getElementById('disp_user').innerText = userToQuery;
          }
          if (document.getElementById('stat_timer_display')) {
            if (data.auto_restore && data.auto_restore.seconds_remaining > 0) {
              document.getElementById('stat_timer_display').innerText = 'Active (Re-enables in ' + data.auto_restore.display + ')';
              startLiveCountdown(data.auto_restore.seconds_remaining);
            } else {
              document.getElementById('stat_timer_display').innerText = 'None (Inactive)';
              startLiveCountdown(0);
            }
          }
          
          const banner = document.getElementById('expirationBanner');
          if (data.is_account_expired) {
            banner.className = 'alert alert-error';
            const timerHtml = data.auto_restore ? `<div style="margin-top:4px; font-weight:700; color:#93c5fd;">⏳ Auto-reenabling account in ${data.auto_restore.display} (5-minute timer).</div>` : '';
            banner.innerHTML = `<strong>⚠️ ACCOUNT EXPIRED (Active Directory):</strong> ${data.message} ${timerHtml} <br><button class="btn btn-success btn-sm" style="margin-top:6px;" onclick="quickUnexpire('${userToQuery}')">Restore Account Now</button>`;
            banner.style.display = 'block';
          } else if (data.is_expired) {
            banner.className = 'alert alert-error';
            const timerHtml = data.auto_restore ? `<div style="margin-top:4px; font-weight:700; color:#93c5fd;">⏳ Auto-restoring password state in ${data.auto_restore.display}.</div>` : '';
            banner.innerHTML = `<strong>⚠️ PASSWORD EXPIRED (K16806):</strong> ${data.message} ${timerHtml} <br><a href="/vdesk/hangup.php3" style="color:#38bdf8; font-weight:700; text-decoration:underline;">Sign out now to test APM password reset prompt</a>.`;
            banner.style.display = 'block';
          } else if (data.is_warning) {
            banner.className = 'alert alert-warning';
            banner.innerHTML = `<strong>⚠️ NOTICE (K16806):</strong> ${data.message} <button class="btn btn-warning btn-sm" style="margin-left:10px;" onclick="openPasswordModal()">Change Password</button>`;
            banner.style.display = 'block';
          } else {
            banner.className = 'alert alert-success';
            banner.innerHTML = `<strong>✅ Active:</strong> ${data.message}`;
            banner.style.display = 'block';
          }
        }
      } catch (e) {
        console.error('Error fetching password status:', e);
      }
    }

    async function handleExpireSubmit(e) {
      e.preventDefault();
      const targetUser = document.getElementById('expire_user').value.trim();
      const tempPass = document.getElementById('expire_temp_pass').value.trim();
      const timerSec = document.getElementById('expire_pwd_timer').value;
      const alertBox = document.getElementById('expireModalAlert');
      const submitBtn = document.getElementById('btnSubmitExpire');

      if (!targetUser) return;

      submitBtn.disabled = true;
      submitBtn.innerText = 'Expiring in AD...';
      alertBox.style.display = 'none';

      try {
        const formData = new URLSearchParams();
        formData.append('username', targetUser);
        formData.append('timer_seconds', timerSec);
        if (tempPass) {
          formData.append('temp_password', tempPass);
        }

        const resp = await fetch('/expire_password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString()
        });

        const data = await resp.json();
        if (resp.ok && data.status === 'success') {
          alertBox.className = 'alert alert-warning';
          alertBox.innerHTML = `<strong>Success!</strong> ${data.message}`;
          alertBox.style.display = 'block';
          submitBtn.innerText = 'Expired!';
          
          const mainAlert = document.getElementById('portalAlert');
          if (mainAlert) {
            mainAlert.className = 'alert alert-error';
            mainAlert.innerHTML = `<strong>Password Expired for '${targetUser}' (K16806):</strong> ${data.message} <br><a href="/vdesk/hangup.php3" style="color:#38bdf8; text-decoration:underline; font-weight:700;">Sign out now to test F5 APM expired password logon prompt</a>.`;
            mainAlert.style.display = 'block';
          }

          if (parseInt(timerSec) > 0) {
            startLiveCountdown(parseInt(timerSec));
          }
          refreshPasswordStatus(targetUser);
          setTimeout(() => { closeExpireModal(); submitBtn.disabled = false; submitBtn.innerText = 'Expire Password Now'; }, 2000);
        } else {
          alertBox.className = 'alert alert-error';
          alertBox.innerText = data.message || 'Failed to expire password in Active Directory.';
          alertBox.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.innerText = 'Expire Password Now';
        }
      } catch (err) {
        alertBox.className = 'alert alert-error';
        alertBox.innerText = 'Communication error: ' + err.message;
        alertBox.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.innerText = 'Expire Password Now';
      }
    }

    async function handleExpireAccountSubmit(e) {
      e.preventDefault();
      const targetUser = document.getElementById('expire_acc_user').value.trim();
      const timerSec = document.getElementById('expire_acc_timer').value;
      const alertBox = document.getElementById('expireAccountModalAlert');
      const submitBtn = document.getElementById('btnSubmitExpireAcc');

      if (!targetUser) return;

      submitBtn.disabled = true;
      submitBtn.innerText = 'Expiring Account in AD...';
      alertBox.style.display = 'none';

      try {
        const formData = new URLSearchParams();
        formData.append('username', targetUser);
        formData.append('timer_seconds', timerSec);

        const resp = await fetch('/expire_account', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString()
        });

        const data = await resp.json();
        if (resp.ok && data.status === 'success') {
          alertBox.className = 'alert alert-warning';
          alertBox.innerHTML = `<strong>Success!</strong> ${data.message}`;
          alertBox.style.display = 'block';
          submitBtn.innerText = 'Account Expired!';
          
          const mainAlert = document.getElementById('portalAlert');
          if (mainAlert) {
            mainAlert.className = 'alert alert-error';
            mainAlert.innerHTML = `<strong>Account Expired for '${targetUser}':</strong> ${data.message} <br><a href="/vdesk/hangup.php3" style="color:#38bdf8; text-decoration:underline; font-weight:700;">Sign out now to test F5 APM expired account denial</a>.`;
            mainAlert.style.display = 'block';
          }

          if (parseInt(timerSec) > 0) {
            startLiveCountdown(parseInt(timerSec));
          }
          refreshPasswordStatus(targetUser);
          setTimeout(() => { closeExpireAccountModal(); submitBtn.disabled = false; submitBtn.innerText = 'Expire Account Now'; }, 2000);
        } else {
          alertBox.className = 'alert alert-error';
          alertBox.innerText = data.message || 'Failed to expire account in Active Directory.';
          alertBox.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.innerText = 'Expire Account Now';
        }
      } catch (err) {
        alertBox.className = 'alert alert-error';
        alertBox.innerText = 'Communication error: ' + err.message;
        alertBox.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.innerText = 'Expire Account Now';
      }
    }

    async function quickUnexpire(targetUser) {
      if (!targetUser) targetUser = document.getElementById('expire_user')?.value || currentUser;
      const mainAlert = document.getElementById('portalAlert');
      const expireAlert = document.getElementById('expireModalAlert');
      startLiveCountdown(0);
      try {
        const formData = new URLSearchParams();
        formData.append('username', targetUser);
        const resp = await fetch('/unexpire_password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString()
        });
        const data = await resp.json();
        if (resp.ok && data.status === 'success') {
          if (mainAlert) {
            mainAlert.className = 'alert alert-success';
            mainAlert.innerText = data.message || `User '${targetUser}' restored to active state.`;
            mainAlert.style.display = 'block';
          }
          if (expireAlert) {
            expireAlert.className = 'alert alert-success';
            expireAlert.innerText = data.message || `User '${targetUser}' restored to active state.`;
            expireAlert.style.display = 'block';
          }
          closeExpireModal();
          closeExpireAccountModal();
          refreshPasswordStatus(targetUser);
        } else {
          if (expireAlert) {
            expireAlert.className = 'alert alert-error';
            expireAlert.innerText = data.message || 'Failed to restore state.';
            expireAlert.style.display = 'block';
          }
        }
      } catch (err) {
        alert('Error restoring state: ' + err.message);
      }
    }

    async function handlePasswordSubmit(e) {
      e.preventDefault();
      const oldPass = document.getElementById('old_pass').value;
      const newPass = document.getElementById('new_pass').value;
      const confirmPass = document.getElementById('confirm_pass').value;
      const alertBox = document.getElementById('modalAlert');
      const submitBtn = document.getElementById('btnSubmitPwd');

      if (newPass !== confirmPass) {
        alertBox.className = 'alert alert-error';
        alertBox.innerText = 'New passwords do not match. Please verify.';
        alertBox.style.display = 'block';
        return;
      }

      if (newPass.length < 8) {
        alertBox.className = 'alert alert-error';
        alertBox.innerText = 'Password does not meet K16806 complexity requirements (minimum 8 characters).';
        alertBox.style.display = 'block';
        return;
      }

      submitBtn.disabled = true;
      submitBtn.innerText = 'Updating via LDAPS...';
      alertBox.style.display = 'none';

      try {
        const formData = new URLSearchParams();
        formData.append('username', currentUser);
        formData.append('_sys_password_old', oldPass);
        formData.append('_sys_password_new', newPass);
        formData.append('_sys_password_confirm', confirmPass);

        const resp = await fetch('/change_password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString()
        });

        const data = await resp.json();
        if (resp.ok && data.status === 'success') {
          alertBox.className = 'alert alert-success';
          alertBox.innerText = data.message || 'Password successfully updated in Active Directory over LDAPS 636!';
          alertBox.style.display = 'block';
          submitBtn.innerText = 'Updated!';
          refreshPasswordStatus();
          setTimeout(() => { closePasswordModal(); submitBtn.disabled = false; submitBtn.innerText = 'Update Password (LDAPS)'; }, 2200);
        } else {
          alertBox.className = 'alert alert-error';
          alertBox.innerText = data.message || 'Failed to update password in Active Directory.';
          alertBox.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.innerText = 'Update Password (LDAPS)';
        }
      } catch (err) {
        alertBox.className = 'alert alert-error';
        alertBox.innerText = 'Communication error: ' + err.message;
        alertBox.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.innerText = 'Update Password (LDAPS)';
      }
    }
  </script>
</body>
</html>"""

HTML_STANDALONE_FORM = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Active Directory Password Change (LDAPS 636) - K16806</title>
  <style>
    body { font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; }
    .card { background: #1e293b; border-radius: 12px; padding: 30px; max-width: 500px; margin: 50px auto; border: 1px solid #334155; }
    h2 { color: #38bdf8; margin-top: 0; }
    .form-group { margin-bottom: 16px; }
    label { display: block; margin-bottom: 6px; color: #94a3b8; font-size: 14px; }
    input[type="text"], input[type="password"] { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #fff; box-sizing: border-box; }
    .btn { width: 100%; padding: 12px; background: #0284c7; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; margin-top: 10px; }
    .info { background: #0c4a6e; color: #7dd3fc; border: 1px solid #0284c7; padding: 12px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; line-height: 1.4; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Change Password (LDAPS 636)</h2>
    <div class="info">
      <strong>Active Directory Password Policy (K16806):</strong><br>
      Must be at least 8 characters and include uppercase, lowercase, numbers, and symbols.
    </div>
    <form action="/my.policy" method="POST">
      <input type="hidden" name="username" value="__USER__">
      <div class="form-group">
        <label>Current Password</label>
        <input type="password" name="_sys_password_old" id="old_password" required>
      </div>
      <div class="form-group">
        <label>New Password</label>
        <input type="password" name="_sys_password_new" id="new_password" required>
      </div>
      <div class="form-group">
        <label>Confirm New Password</label>
        <input type="password" name="_sys_password_confirm" id="verify_password" required>
      </div>
      <button type="submit" class="btn">Submit Password Change</button>
    </form>
  </div>
</body>
</html>"""


class PortalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def get_user_info(self):
        username = self.headers.get("X-Authenticated-User") or self.headers.get("X-User") or "admin"
        username = get_clean_sam_account(username)
        role = self.headers.get("X-User-Role")
        if not role:
            role = "Enterprise Administrator" if "admin" in username.lower() else "Standard Corporate User"
        client_ip = self.headers.get("X-Forwarded-For") or self.client_address[0]
        return username, role, client_ip

    def do_GET(self):
        parsed = urlparse(self.path)
        
        # Health check endpoint for BIG-IP LTM monitor
        if parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b'OK')
            return

        username, role, client_ip = self.get_user_info()

        # Password status API endpoint
        if parsed.path == "/api/password_status":
            query_params = parse_qs(parsed.query)
            target_user = query_params.get("user", query_params.get("username", [username]))[0]
            info = get_ad_user_password_info(target_user)
            resp_bytes = json.dumps(info).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Expire password API endpoint (GET support)
        if parsed.path in ["/api/expire_password", "/expire_password"]:
            query_params = parse_qs(parsed.query)
            target_user = query_params.get("user", query_params.get("username", [username]))[0]
            temp_pwd = query_params.get("temp_password", query_params.get("password", [None]))[0]
            timer_delay = int(query_params.get("timer_seconds", query_params.get("delay", [DEFAULT_AUTO_RESTORE_DELAY]))[0])
            success, msg = expire_ad_user_password(target_user, temp_pwd, auto_restore_delay=timer_delay)
            response_payload = {
                "status": "success" if success else "error",
                "message": msg,
                "user": target_user,
                "temp_password_set": bool(temp_pwd),
                "auto_restore_delay": timer_delay
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Expire account API endpoint (GET support)
        if parsed.path in ["/api/expire_account", "/expire_account"]:
            query_params = parse_qs(parsed.query)
            target_user = query_params.get("user", query_params.get("username", [username]))[0]
            timer_delay = int(query_params.get("timer_seconds", query_params.get("delay", [DEFAULT_AUTO_RESTORE_DELAY]))[0])
            success, msg = expire_ad_account(target_user, auto_restore_delay=timer_delay)
            response_payload = {
                "status": "success" if success else "error",
                "message": msg,
                "user": target_user,
                "auto_restore_delay": timer_delay
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Cancel active timer endpoint
        if parsed.path in ["/api/cancel_timer", "/cancel_timer"]:
            query_params = parse_qs(parsed.query)
            target_user = query_params.get("user", query_params.get("username", [username]))[0]
            cancelled = cancel_user_timer(target_user)
            response_payload = {
                "status": "success",
                "message": f"Timer cancelled for '{target_user}'." if cancelled else f"No active timer found for '{target_user}'.",
                "cancelled": cancelled
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Direct password change form endpoint
        if "_sys_change_password" in self.path or parsed.path == "/change_password":
            content = HTML_STANDALONE_FORM.replace("__USER__", username)
            resp = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp)
            return

        # Fetch password & account expiration info for banner rendering
        pwd_info = get_ad_user_password_info(username)
        timer_info = pwd_info.get("auto_restore")
        timer_status_str = f"Active ({timer_info['display']} remaining)" if timer_info else "None (Inactive)"

        if pwd_info.get("is_account_expired"):
            banner_class = "alert-error"
            banner_display = "block"
            timer_note = f"<div style='margin-top:4px; color:#93c5fd; font-weight:700;'>⏳ 5-Minute Auto-Reenable Timer Active: Account will automatically restore in {timer_info['display']}.</div>" if timer_info else ""
            banner_content = f"<strong>⚠️ ACTIVE DIRECTORY ACCOUNT EXPIRED:</strong> {pwd_info['message']} {timer_note} <br><button class=\"btn btn-success btn-sm\" style=\"margin-top:6px;\" onclick=\"quickUnexpire('{username}')\">Restore Active State Now</button>"
        elif pwd_info.get("is_expired"):
            banner_class = "alert-error"
            banner_display = "block"
            timer_note = f"<div style='margin-top:4px; color:#93c5fd; font-weight:700;'>⏳ 5-Minute Auto-Restore Timer Active: Password state will restore in {timer_info['display']}.</div>" if timer_info else ""
            banner_content = f"<strong>⚠️ PASSWORD EXPIRED (K16806):</strong> {pwd_info['message']} {timer_note} <br><a href=\"/vdesk/hangup.php3\" style=\"color:#38bdf8; font-weight:700; text-decoration:underline;\">Sign out now to test F5 APM expired password logon prompt</a>."
        elif pwd_info.get("is_warning"):
            banner_class = "alert-warning"
            banner_display = "block"
            banner_content = f"<strong>⚠️ NOTICE (K16806):</strong> {pwd_info['message']} <button class=\"btn btn-warning btn-sm\" style=\"margin-left:10px;\" onclick=\"openPasswordModal()\">Change Password</button>"
        else:
            banner_class = "alert-success"
            banner_display = "block"
            banner_content = f"<strong>✅ Active & Healthy:</strong> {pwd_info['message']}"

        # Render Main Intranet Portal dashboard
        content = (
            HTML_PORTAL
            .replace("__USER__", username)
            .replace("__ROLE__", role)
            .replace("__CLIENT_IP__", client_ip)
            .replace("__DOMAIN__", AD_DOMAIN)
            .replace("__BANNER_CLASS__", banner_class)
            .replace("__BANNER_DISPLAY__", banner_display)
            .replace("__BANNER_CONTENT__", banner_content)
            .replace("__BADGE_CLASS__", pwd_info.get("badge_class", "badge-info"))
            .replace("__STATUS_DISPLAY__", pwd_info.get("status_display", "ACTIVE"))
            .replace("__ACCOUNT_STATUS_DISPLAY__", pwd_info.get("account_status_display", "Active"))
            .replace("__LAST_SET_STR__", pwd_info.get("last_set_str", "Unknown"))
            .replace("__ACCOUNT_EXPIRES_STR__", pwd_info.get("account_expires_str", "Never Expires"))
            .replace("__UAC_FLAGS__", pwd_info.get("uac_flags_display", "512 (NORMAL_ACCOUNT)"))
            .replace("__TIMER_STATUS__", timer_status_str)
            .replace("__DAYS_REMAINING__", str(pwd_info.get("days_remaining", 0)))
        )
        resp = content.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
        self.end_headers()
        self.wfile.write(resp)

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        # Parse parameters
        params = {}
        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                params = json.loads(post_body)
            except Exception:
                pass
        else:
            raw_params = parse_qs(post_body)
            for k, v in raw_params.items():
                params[k] = v[0] if v else ""

        username, _, _ = self.get_user_info()
        target_user = params.get("username") or params.get("user") or params.get("target_user") or params.get("samaccountname") or username
        temp_pwd = params.get("temp_password") or params.get("password") or params.get("temp_pwd") or None
        
        try:
            timer_delay = int(params.get("timer_seconds", params.get("delay", DEFAULT_AUTO_RESTORE_DELAY)))
        except (ValueError, TypeError):
            timer_delay = DEFAULT_AUTO_RESTORE_DELAY

        # Endpoint: Expire Password (sets pwdLastSet = 0, UAC = 512, accountExpires = 0 via LDAPS 636 + 5min timer)
        if parsed.path in ["/expire_password", "/api/expire_password"]:
            success, msg = expire_ad_user_password(target_user, temp_pwd, auto_restore_delay=timer_delay)
            response_payload = {
                "status": "success" if success else "error",
                "message": msg,
                "user": target_user,
                "temp_password_set": bool(temp_pwd),
                "auto_restore_delay": timer_delay
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Endpoint: Expire Account (sets accountExpires = 1 via LDAPS 636 + 5min timer)
        if parsed.path in ["/expire_account", "/api/expire_account"]:
            success, msg = expire_ad_account(target_user, auto_restore_delay=timer_delay)
            response_payload = {
                "status": "success" if success else "error",
                "message": msg,
                "user": target_user,
                "auto_restore_delay": timer_delay
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Endpoint: Un-expire / Restore Account (sets accountExpires = 0 via LDAPS 636)
        if parsed.path in ["/unexpire_account", "/api/unexpire_account"]:
            success, msg = unexpire_ad_account(target_user)
            response_payload = {
                "status": "success" if success else "error",
                "message": msg,
                "user": target_user
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Endpoint: Un-expire / Restore Password and Account (sets pwdLastSet = -1, UAC = 512, accountExpires = 0 via LDAPS 636)
        if parsed.path in ["/unexpire_password", "/api/unexpire_password"]:
            reset_pwd = params.get("temp_password") or params.get("password") or params.get("reset_password") or None
            success, msg = unexpire_ad_user_password(target_user, reset_pwd)
            response_payload = {
                "status": "success" if success else "error",
                "message": msg,
                "user": target_user
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        # Endpoint: Change Password
        old_pwd = params.get("_sys_password_old") or params.get("old_password") or ""
        new_pwd = params.get("_sys_password_new") or params.get("new_password") or ""
        confirm_pwd = params.get("_sys_password_confirm") or params.get("verify_password") or new_pwd

        if not new_pwd:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": "New password is required."}).encode("utf-8"))
            return

        if new_pwd != confirm_pwd:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": "Password confirmation does not match."}).encode("utf-8"))
            return

        # Execute LDAPS password change
        success, msg = change_ad_user_password(target_user, old_pwd, new_pwd)
        
        is_html_post = "text/html" in self.headers.get("Accept", "") and parsed.path == "/my.policy"
        if is_html_post:
            resp_html = f"""<!DOCTYPE html><html><body style="background:#0f172a;color:#f8fafc;font-family:sans-serif;padding:30px;">
            <div style="background:#1e293b;padding:24px;border-radius:8px;max-width:500px;margin:auto;border:1px solid #334155;">
            <h2 style="color:#10b981;">Password Updated Successfully (K16806)</h2>
            <p>{msg}</p>
            <a href="/" style="display:inline-block;padding:10px 18px;background:#0284c7;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">Return to Corporate Portal</a>
            </div></body></html>"""
            resp_bytes = resp_html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
        else:
            response_payload = {
                "status": "success" if success else "error",
                "message": msg,
                "user": target_user
            }
            resp_bytes = json.dumps(response_payload).encode("utf-8")
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-App-Backend", "F5-APM-Lab-Portal")
            self.end_headers()
            self.wfile.write(resp_bytes)


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


def run():
    server = ReusableHTTPServer((HOST, PORT), PortalHandler)
    print(f"Portal App listening on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    run()
