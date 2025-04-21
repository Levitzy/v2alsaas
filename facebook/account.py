# Facebook account management

import os
import time
from datetime import datetime

from utils.colors import success, error, info
from config import ACCOUNTS_PATH, EMAIL_PASS_PATH


def save_account(email, user_details, user_id):
    """Save account details to files"""
    try:
        # Format for saving
        account_data = (
            f"{email}|{user_details['password']}|{user_id}|"
            f"{user_details['first_name']} {user_details['last_name']}|"
            f"{user_details['birthday']}|{user_details['gender']}\n"
        )

        # Ensure directory exists
        os.makedirs(os.path.dirname(ACCOUNTS_PATH), exist_ok=True)

        # Save full details
        with open(ACCOUNTS_PATH, "a") as f:
            f.write(account_data)

        # Save just email and password
        with open(EMAIL_PASS_PATH, "a") as f:
            f.write(f"{email}|{user_details['password']}\n")

        success("[+] Account details saved to files")
        return True
    except Exception as e:
        error(f"[!] Error saving account: {e}")
        return False


def print_success(email, user_id, user_details):
    """Print success message with account details"""
    success(
        f"""
⋘▬▭▬▭▬▭▬﴾𓆩OK𓆪﴿▬▭▬▭▬▭▬⋙
﴾𝐕𝐈𝐏﴿ EMAIL : {email}
﴾𝐕𝐈𝐏﴿ ID : {user_id}
﴾𝐕𝐈𝐏﴿ PASSWORD : {user_details["password"]}
﴾𝐕𝐈𝐏﴿ NAME : {user_details["first_name"]} {user_details["last_name"]}
﴾𝐕𝐈𝐏﴿ BIRTHDAY : {user_details["birthday"]} 
﴾𝐕𝐈𝐏﴿ GENDER : {user_details["gender"]}
⋘▬▭▬▭▬▭▬﴾𓆩OK𓆪﴿▬▭▬▭▬▭▬⋙"""
    )


def print_summary(success_status, email, user_details, start_time):
    """Print a summary of the account creation attempt"""
    elapsed_time = time.time() - start_time

    info(f"[+] Account creation completed")

    if success_status:
        success(f"[+] Success! Account created")
        success(f"[+] Email: {email}")
        success(f"[+] Password: {user_details['password']}")
    else:
        error(f"[+] Failed to create account")
        error(f"[+] Facebook may be blocking registration attempts.")
        info(f"[+] Try again later with a different email or IP address.")

    info(f"[+] Time: {elapsed_time:.2f} seconds")


def get_user_email():
    """Ask user for email address"""
    info("\n[+] Enter email for registration")
    email = input("[+] Email: ").strip()

    if not email or "@" not in email:
        error("[!] Invalid email format")
        return None

    return email


def create_facebook_account(email, use_proxies):
    """Orchestrate the account creation process using multiple methods"""
    from facebook.desktop import register_facebook_desktop
    from facebook.mobile import register_facebook_mobile
    from utils.generators import generate_user_details
    from utils.proxy import get_random_proxy, rotate_proxy
    from utils.helpers import handle_between_attempts
    from config import MAX_ATTEMPTS

    used_proxies = []

    for attempt in range(MAX_ATTEMPTS):
        try:
            info(f"\n[+] Attempt {attempt+1}/{MAX_ATTEMPTS} for {email}")

            # Get a random proxy if enabled
            proxies = None
            if use_proxies:
                proxies = rotate_proxy(used_proxies)
                if proxies:
                    used_proxies.append(proxies)

            # Generate user details once per attempt
            user_details = generate_user_details()
            info(f"[+] Name: {user_details['first_name']} {user_details['last_name']}")
            info(f"[+] Password: {user_details['password']}")

            # Method 1: Desktop registration (highest success rate)
            info(f"[*] Trying desktop method (1/2)...")
            success_desktop, user_id_desktop = register_facebook_desktop(
                email, user_details, proxies
            )

            if success_desktop:
                return True, user_details

            # Method 2: Mobile web method
            info(f"[*] Trying mobile method (2/2)...")
            if use_proxies:
                # Rotate proxy for second attempt
                proxies = rotate_proxy(used_proxies)
                if proxies:
                    used_proxies.append(proxies)

            success_mobile, user_id_mobile = register_facebook_mobile(
                email, user_details, proxies
            )

            if success_mobile:
                return True, user_details

            # Handle delay between attempts
            if not handle_between_attempts(attempt, MAX_ATTEMPTS):
                break

        except Exception as e:
            error(f"[×] Error: {e}")
            if not handle_between_attempts(attempt, MAX_ATTEMPTS):
                break

    error(f"[×] All attempts failed")
    return False, None
