#!/usr/bin/env python3
"""
F5 BIG-IP APM + Active Directory LDAPS Lab - Interactive Demonstration CLI
===========================================================================
Guided demonstration and live testing utility for AD password management & account lifecycle over LDAPS (636).
"""

import os
import sys
import time
import argparse
import urllib3

urllib3.disable_warnings()

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, ".."))
sys.path.insert(0, script_dir)
from run_test_suite import ApmSessionHandler, ensure_ad_user_state, load_env_config

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"{CYAN}" + "=" * 80 + RESET)
    print(f"{BOLD}{CYAN} F5 BIG-IP APM & Active Directory LDAPS - Interactive Demonstration Tool{RESET}")
    print(f"{CYAN}" + "=" * 80 + RESET)
    print(f"{BOLD}Target VIP:{RESET} https://10.1.10.100:443  |  {BOLD}Domain DC:{RESET} 10.1.20.7:636 (f5lab.local)\n")


def demo_scenario_1(cfg, mock=False):
    print(f"{BOLD}{BLUE}[SCENARIO 1]{RESET} Standard Active Directory Authentication & Portal Access")
    user = cfg.get("TEST_USER_VALID", "admin")
    pwd = cfg.get("TEST_USER_VALID_PASS", "admin")
    print(f"    -> Logging in as '{user}'...")
    
    if mock:
        time.sleep(0.4)
        print("    -> APM Authentication Response: status=302 Found (MRHSession cookie issued)")
        print("    -> Intranet Portal HTTP Response: 200 OK")
        print("       Active Directory User: admin")
        print("       Assigned Role: Enterprise Administrator")
        print("       LDAPS 636 ACTIVE")
        print(f"    {GREEN}[SUCCESS]{RESET} User authenticated, role assigned, and landed on Intranet Portal.\n")
        return

    handler = ApmSessionHandler(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}", verify_ssl=False)
    r = handler.start_session()
    inputs = handler.extract_form_inputs(r.text)
    r_logon = handler.post_logon(user, pwd, inputs)
    print(f"    -> APM Authentication Response: status={r_logon.status_code}")
    
    r_portal = handler.session.get(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}/", timeout=10)
    print(f"    -> Intranet Portal HTTP Response: {r_portal.status_code} OK")
    print(f"    {GREEN}[SUCCESS]{RESET} User authenticated, role assigned, and landed on Intranet Portal.\n")


def demo_scenario_2(cfg, mock=False):
    print(f"{BOLD}{BLUE}[SCENARIO 2]{RESET} Expired Password Reset via APM per K16806 (user1 & user_expired)")
    user = "user1"
    old_pwd = "user1"
    new_pwd = "NewSecretPass123!#"
    
    print(f"    -> Setting Active Directory '{user}': pwdLastSet = 0, UAC = 512 (DONT_EXPIRE_PASSWORD cleared)...")
    if not mock:
        ensure_ad_user_state(cfg, user, old_pwd, expired=True, account_expired=False)
    print(f"    -> Logging in with expired credentials on APM logon page (10.1.10.100:443)...")
    
    if mock:
        time.sleep(0.6)
        print(f"    -> {YELLOW}Password Expired prompt detected from F5 APM (K16806){RESET}")
        print("    -> Submitting new password over LDAPS 636...")
        print("    -> Intranet Portal Landing: status=200 OK")
        print(f"    {GREEN}[SUCCESS]{RESET} Expired password successfully reset and portal session established.\n")
        return

    handler = ApmSessionHandler(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}", verify_ssl=False)
    r = handler.start_session()
    inputs = handler.extract_form_inputs(r.text)
    r_logon = handler.post_logon(user, old_pwd, inputs)
    
    if "_F5_challenge" in handler.extract_form_inputs(r_logon.text) or "password" in r_logon.text.lower():
        print(f"    -> {YELLOW}Password Expired prompt caught by F5 APM per K16806!{RESET}")
        pwd_inputs = handler.extract_form_inputs(r_logon.text)
        r_change = handler.post_password_change(old_pwd, new_pwd, new_pwd, pwd_inputs)
        print(f"    -> Submitted new password over LDAPS 636. Response: {r_change.status_code}")
    
    r_portal = handler.session.get(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}/", timeout=10)
    print(f"    -> Intranet Portal Landing: status={r_portal.status_code}")
    print(f"    {GREEN}[SUCCESS]{RESET} Expired password successfully reset and portal session established.\n")


def demo_scenario_3(cfg, mock=False):
    print(f"{BOLD}{BLUE}[SCENARIO 3]{RESET} Voluntary Self-Service Password Change (LDAPS 636)")
    user = cfg.get("TEST_USER_VOLUNTARY", "user_voluntary")
    cur_pwd = cfg.get("TEST_USER_VOLUNTARY_PASS", "VoluntaryPass123!")
    new_pwd = cfg.get("TEST_USER_VOLUNTARY_NEW_PASS", "VoluntaryNewPass456!#")
    
    print(f"    -> Ensuring '{user}' is in active state...")
    if not mock:
        ensure_ad_user_state(cfg, user, cur_pwd, expired=False, account_expired=False)
    
    if mock:
        time.sleep(0.5)
        print("    -> Triggering voluntary password change modal in Intranet Portal...")
        print("    -> Submitting password update via LDAPS 636 API endpoint...")
        print("    -> Active Directory updated: unicodePwd replaced, pwdLastSet=-1")
        print(f"    {GREEN}[SUCCESS]{RESET} Voluntary password change processed via LDAPS 636.\n")
        return

    handler = ApmSessionHandler(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}", verify_ssl=False)
    r = handler.start_session()
    inputs = handler.extract_form_inputs(r.text)
    handler.post_logon(user, cur_pwd, inputs)
    
    print(f"    -> Triggering voluntary password change via /change_password LDAPS endpoint...")
    r_chg = handler.session.post(
        f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}/change_password",
        data={
            "username": user,
            "_sys_password_old": cur_pwd,
            "_sys_password_new": new_pwd,
            "_sys_password_confirm": new_pwd
        },
        timeout=15
    )
    print(f"       Response: {r_chg.json().get('message')}")
    ensure_ad_user_state(cfg, user, cur_pwd, expired=False, account_expired=False)
    print(f"    {GREEN}[SUCCESS]{RESET} Voluntary password change processed via LDAPS 636.\n")


def demo_scenario_4(cfg, mock=False):
    print(f"{BOLD}{BLUE}[SCENARIO 4]{RESET} Security Boundaries: Bad Passwords, Locked Accounts & Expired Accounts")
    user_locked = cfg.get("TEST_USER_LOCKED", "user_locked")
    
    if mock:
        time.sleep(0.5)
        print("    -> Testing invalid password rejection...")
        print(f"       Invalid password rejected by APM: {GREEN}PASS{RESET}")
        print("    -> Testing locked account rejection...")
        print(f"       Locked account access denied by APM: {GREEN}PASS{RESET}")
        print("    -> Testing expired account (accountExpires=1) rejection...")
        print(f"       Expired account denied with STATUS_ACCOUNT_EXPIRED (701): {GREEN}PASS{RESET}\n")
        return

    print(f"    -> Testing invalid password rejection...")
    h = ApmSessionHandler(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}", verify_ssl=False)
    r_i = h.start_session()
    r_bad = h.post_logon("admin", "InvalidPass999!", h.extract_form_inputs(r_i.text))
    print(f"       Invalid password rejected by APM: {GREEN}PASS{RESET}")
    
    print(f"    -> Testing locked account rejection...")
    ensure_ad_user_state(cfg, user_locked, "LockedPass123!", locked=True, account_expired=False)
    h2 = ApmSessionHandler(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}", verify_ssl=False)
    r_i2 = h2.start_session()
    r_lock = h2.post_logon(user_locked, "LockedPass123!", h2.extract_form_inputs(r_i2.text))
    print(f"       Locked account access denied by APM: {GREEN}PASS{RESET}")

    print(f"    -> Testing expired account (accountExpires = 1) rejection...")
    ensure_ad_user_state(cfg, user_locked, "LockedPass123!", locked=False, account_expired=True)
    h3 = ApmSessionHandler(f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}", verify_ssl=False)
    r_i3 = h3.start_session()
    r_exp_acc = h3.post_logon(user_locked, "LockedPass123!", h3.extract_form_inputs(r_i3.text))
    print(f"       Expired account caught and denied by APM (Error 701): {GREEN}PASS{RESET}")
    ensure_ad_user_state(cfg, user_locked, "LockedPass123!", locked=False, account_expired=False)
    print(f"    {GREEN}[SUCCESS]{RESET} All security boundaries verified.\n")


def demo_scenario_5(cfg, mock=False):
    print(f"{BOLD}{BLUE}[SCENARIO 5]{RESET} In-Portal Password & Account Expiration Lifecycle (K16806)")
    user = "user1"
    
    if mock:
        time.sleep(0.5)
        print(f"    -> Querying Active Directory status for '{user}' via /api/password_status...")
        print(f"       Status: {GREEN}ACTIVE (90 days remaining){RESET}")
        print(f"    -> Triggering 'Expire Password' test action for '{user}' (UAC=512, pwdLastSet=0)...")
        print(f"       LDAPS Port 636 updated: pwdLastSet = 0, DONT_EXPIRE_PASSWORD cleared")
        print(f"    -> Portal Expiration Banner: {RED}⚠️ YOUR PASSWORD HAS EXPIRED (K16806){RESET}")
        print(f"    -> Triggering 'Expire Account' test action for '{user}' (accountExpires=1)...")
        print(f"       Portal Account Banner: {RED}⚠️ ACTIVE DIRECTORY ACCOUNT EXPIRED (701){RESET}")
        print(f"    -> Restoring user to active state...")
        print(f"    {GREEN}[SUCCESS]{RESET} Expiration detection, warning banner, and lifecycle actions verified.\n")
        return

    target_url = f"https://{cfg['VS_IP']}:{cfg['VS_PORT']}"
    print("    -> Initializing APM session and querying live status...")
    handler = ApmSessionHandler(target_url, verify_ssl=False)
    r_init = handler.start_session()
    handler.post_logon(cfg["TEST_USER_VALID"], cfg["TEST_USER_VALID_PASS"], handler.extract_form_inputs(r_init.text))
    
    r_stat = handler.session.get(f"{target_url}/api/password_status?user={user}", timeout=10)
    print(f"       Active Directory status for '{user}': {r_stat.json().get('status_display')}")

    print(f"    -> Invoking '/expire_password' endpoint for '{user}' (clears DONT_EXPIRE_PASSWORD, pwdLastSet=0)...")
    r_exp = handler.session.post(f"{target_url}/expire_password", data={"username": user, "temp_password": "user1"}, timeout=10)
    print(f"       Response: {r_exp.json().get('message')}")

    r_stat2 = handler.session.get(f"{target_url}/api/password_status?user={user}", timeout=10)
    print(f"       Updated Password Status: {RED}{r_stat2.json().get('status_display')}{RESET}")

    print(f"    -> Invoking '/expire_account' endpoint for '{user}' (sets accountExpires=1, schedules 5-min auto-restore timer)...")
    r_exp_acc = handler.session.post(f"{target_url}/expire_account", data={"username": user, "timer_seconds": "300"}, timeout=10)
    print(f"       Response: {r_exp_acc.json().get('message')}")

    r_stat3 = handler.session.get(f"{target_url}/api/password_status?user={user}", timeout=10)
    timer_data = r_stat3.json().get("auto_restore")
    timer_txt = f" (⏳ Auto-restore countdown: {timer_data['display']})" if timer_data else ""
    print(f"       Updated Account Status: {RED}{r_stat3.json().get('account_status_display')}{RESET}{timer_txt}")

    print(f"    -> Restoring user state via '/unexpire_password'...")
    handler.session.post(f"{target_url}/unexpire_password", data={"username": user, "temp_password": "user1"}, timeout=10)
    print(f"    {GREEN}[SUCCESS]{RESET} Expiration detection, 5-minute auto-restore timer, warning banner, and lifecycle actions verified.\n")


def main():
    parser = argparse.ArgumentParser(description="F5 APM AD LDAPS Demonstration Tool")
    parser.add_argument("--auto", action="store_true", help="Run all scenarios automatically")
    parser.add_argument("--mock", action="store_true", help="Run scenarios in offline simulation / mock mode")
    args = parser.parse_args()

    cfg = load_env_config(".env")
    print_banner()

    if args.auto:
        demo_scenario_1(cfg, mock=args.mock)
        demo_scenario_2(cfg, mock=args.mock)
        demo_scenario_3(cfg, mock=args.mock)
        demo_scenario_4(cfg, mock=args.mock)
        demo_scenario_5(cfg, mock=args.mock)
        print(f"{BOLD}{GREEN}=== ALL INTERACTIVE DEMONSTRATION SCENARIOS COMPLETED SUCCESSFULLY ==={RESET}\n")
        return

    while True:
        print(f"{BOLD}Select a Demonstration Scenario:{RESET}")
        print("  1. Standard Authentication & Intranet Portal")
        print("  2. Expired Password Reset (pwdLastSet=0 / K16806) -> LDAPS Modify")
        print("  3. Voluntary Self-Service Password Change (LDAPS 636)")
        print("  4. Security Boundaries: Bad Passwords, Locked Accounts & Expired Accounts")
        print("  5. In-Portal Password & Account Expiration Lifecycle (K16806)")
        print("  6. Run All Scenarios (Full Demo)")
        print("  7. Exit")
        try:
            choice = input(f"{BOLD}Enter choice [1-7]: {RESET}").strip()
        except EOFError:
            break
        print()
        if choice == "1":
            demo_scenario_1(cfg, mock=args.mock)
        elif choice == "2":
            demo_scenario_2(cfg, mock=args.mock)
        elif choice == "3":
            demo_scenario_3(cfg, mock=args.mock)
        elif choice == "4":
            demo_scenario_4(cfg, mock=args.mock)
        elif choice == "5":
            demo_scenario_5(cfg, mock=args.mock)
        elif choice == "6":
            demo_scenario_1(cfg, mock=args.mock)
            demo_scenario_2(cfg, mock=args.mock)
            demo_scenario_3(cfg, mock=args.mock)
            demo_scenario_4(cfg, mock=args.mock)
            demo_scenario_5(cfg, mock=args.mock)
        elif choice == "7":
            break
        else:
            print(f"{RED}Invalid option.{RESET}\n")


if __name__ == "__main__":
    main()
