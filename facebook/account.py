# Facebook account management - Updated for 2025 security measures

import os
import time
import random
import requests
from datetime import datetime

from utils.colors import success, error, info, warn
from utils.helpers import wait_with_jitter
from config import ACCOUNTS_PATH, EMAIL_PASS_PATH, MAX_ATTEMPTS


def save_account(email, user_details, user_id):
    """Save account details to files with improved handling"""
    try:
        # Create profile URL if not already present
        if "profile_url" not in user_details:
            user_details["profile_url"] = (
                f"https://www.facebook.com/profile.php?id={user_id}"
            )

        # Format for saving with profile URL
        account_data = (
            f"{email}|{user_details['password']}|{user_id}|"
            f"{user_details['first_name']} {user_details['last_name']}|"
            f"{user_details['birthday']}|{user_details['gender']}|"
            f"{user_details['profile_url']}\n"
        )

        # Ensure directory exists
        os.makedirs(os.path.dirname(ACCOUNTS_PATH), exist_ok=True)

        # Save full details
        with open(ACCOUNTS_PATH, "a") as f:
            f.write(account_data)

        # Save just email and password
        with open(EMAIL_PASS_PATH, "a") as f:
            f.write(
                f"{email}|{user_details['password']}|{user_id}|{user_details['profile_url']}\n"
            )

        success("[+] Account details saved to files")
        return True
    except Exception as e:
        error(f"[!] Error saving account: {e}")
        return False


def print_success(email, user_id, user_details):
    """Print success message with account details in a stylish format"""
    # Create profile URL if not already present
    if "profile_url" not in user_details:
        user_details["profile_url"] = (
            f"https://www.facebook.com/profile.php?id={user_id}"
        )

    success(
        f"""
⋘▬▭▬▭▬▭▬﴾𓆩ACCOUNT CREATED𓆪﴿▬▭▬▭▬▭▬⋙
﴾𝐕𝐈𝐏﴿ EMAIL : {email}
﴾𝐕𝐈𝐏﴿ ID : {user_id}
﴾𝐕𝐈𝐏﴿ PASSWORD : {user_details["password"]}
﴾𝐕𝐈𝐏﴿ NAME : {user_details["first_name"]} {user_details["last_name"]}
﴾𝐕𝐈𝐏﴿ BIRTHDAY : {user_details["birthday"]} 
﴾𝐕𝐈𝐏﴿ GENDER : {user_details["gender"]}
﴾𝐕𝐈𝐏﴿ PROFILE : {user_details["profile_url"]}
⋘▬▭▬▭▬▭▬﴾𓆩ACCOUNT CREATED𓆪﴿▬▭▬▭▬▭▬⋙"""
    )


def print_summary(success_status, email, user_details, start_time):
    """Print a summary of the account creation attempt with improved stats"""
    elapsed_time = time.time() - start_time

    # Calculate success rate if we have access to attempt count
    success_rate = "N/A"
    try:
        from utils.attempt_tracker import get_attempt_stats

        stats = get_attempt_stats()
        if stats and stats["total"] > 0:
            success_rate = f"{(stats['success'] / stats['total']) * 100:.1f}%"
    except:
        pass

    info(f"[+] Account creation completed")

    if success_status:
        success(f"[+] Success! Account created")
        success(f"[+] Email: {email}")
        success(f"[+] Password: {user_details['password']}")
        success(f"[+] Name: {user_details['first_name']} {user_details['last_name']}")
        if "profile_url" in user_details:
            success(f"[+] Profile URL: {user_details['profile_url']}")
    else:
        error(f"[+] Failed to create account")
        error(f"[+] Facebook may be blocking registration attempts")
        info(f"[+] Try again later with a different email or IP address")

        # Provide troubleshooting advice
        info(f"[+] Troubleshooting tips:")
        info(f"    - Use a different IP address or proxy")
        info(f"    - Try different mobile/desktop user agents")
        info(f"    - Increase delay between registration attempts")
        info(f"    - Use a different email provider")
        info(f"    - Wait a few hours before trying again")

    # Print statistics
    info(f"[+] Time: {elapsed_time:.2f} seconds")
    if success_rate != "N/A":
        info(f"[+] Current success rate: {success_rate}")


def get_user_email():
    """Ask user for email address with improved validation"""
    info("\n[+] Enter email for registration")
    email = input("[+] Email: ").strip()

    if not email:
        error("[!] No email provided")
        return None

    if "@" not in email:
        error("[!] Invalid email format - missing @ symbol")
        return None

    # Check for common temporary email services
    temp_domains = ["tempmail", "temp-mail", "disposable", "throwaway", "junk", "fake"]
    if any(temp in email.lower() for temp in temp_domains):
        warn("[!] Using a temporary email - Facebook may detect this")
        info(
            "[*] Facebook often blocks or requires additional verification for temporary emails"
        )
        warn("[*] If registration fails, try with a permanent email address")

        # Ask for confirmation
        confirm = input("[?] Continue with this email anyway? (y/n): ").lower()
        if confirm not in ["y", "yes"]:
            return None

    return email


def create_facebook_account(email, use_proxies, browser_fingerprint=None):
    """Orchestrate the account creation process using multiple methods"""
    from facebook.desktop import register_facebook_desktop
    from facebook.mobile import register_facebook_mobile
    from utils.generators import generate_user_details
    from utils.proxy import get_random_proxy, rotate_proxy, update_proxy_status
    from utils.helpers import handle_between_attempts

    used_proxies = []
    start_time = time.time()
    attempted_methods = []
    registration_timeouts = 0

    for attempt in range(MAX_ATTEMPTS):
        try:
            info(f"\n[+] Attempt {attempt+1}/{MAX_ATTEMPTS} for {email}")

            # Get a random proxy if enabled
            proxies = None
            if use_proxies:
                proxies = rotate_proxy(used_proxies)
                if proxies:
                    proxy_display = list(proxies.values())[0]
                    if "@" in proxy_display:
                        proxy_display = proxy_display.split("@")[-1]  # Hide auth info
                    info(f"[*] Using proxy: {proxy_display}")
                    used_proxies.append(proxies)
                else:
                    warn("[!] No more available proxies, attempting without proxy")

            # Generate user details once per attempt
            user_details = generate_user_details()
            info(f"[+] Name: {user_details['first_name']} {user_details['last_name']}")
            info(f"[+] Password: {user_details['password']}")

            # Add browser fingerprint to user details
            if browser_fingerprint:
                user_details.update(browser_fingerprint)

            # Try desktop method first on first attempt
            if attempt == 0 or "desktop" not in attempted_methods:
                info(f"[*] Trying desktop method (1/2)...")
                try:
                    success_desktop, user_id_desktop = register_facebook_desktop(
                        email, user_details, proxies
                    )
                    attempted_methods.append("desktop")

                    if (
                        success_desktop
                        and user_id_desktop
                        and user_id_desktop not in ["0", "Unknown"]
                    ):
                        # Update proxy status if successful
                        if use_proxies and proxies:
                            update_proxy_status(proxies, True)
                        return True, user_details
                except requests.exceptions.Timeout:
                    registration_timeouts += 1
                    warn(f"[!] Desktop registration timed out")
                    # If we get a timeout, try different method next
                except Exception as e:
                    error(f"[×] Desktop registration error: {str(e)}")

            # Add a waiting period between methods
            wait_with_jitter(3.0, 6.0)

            # Try mobile method after desktop
            if "mobile" not in attempted_methods:
                info(f"[*] Trying mobile method (2/2)...")
                if use_proxies and attempt > 0:
                    # Rotate proxy for second attempt
                    proxies = rotate_proxy(used_proxies)
                    if proxies:
                        proxy_display = list(proxies.values())[0]
                        if "@" in proxy_display:
                            proxy_display = proxy_display.split("@")[
                                -1
                            ]  # Hide auth info
                        info(f"[*] Using new proxy: {proxy_display}")
                        used_proxies.append(proxies)

                try:
                    success_mobile, user_id_mobile = register_facebook_mobile(
                        email, user_details, proxies
                    )
                    attempted_methods.append("mobile")

                    if (
                        success_mobile
                        and user_id_mobile
                        and user_id_mobile not in ["0", "Unknown"]
                    ):
                        # Update proxy status if successful
                        if use_proxies and proxies:
                            update_proxy_status(proxies, True)
                        return True, user_details
                except requests.exceptions.Timeout:
                    registration_timeouts += 1
                    warn(f"[!] Mobile registration timed out")
                except Exception as e:
                    error(f"[×] Mobile registration error: {str(e)}")

            # Handle delay between attempts
            if not handle_between_attempts(attempt, MAX_ATTEMPTS):
                break

            # If we've had timeouts, increase the timeout
            if registration_timeouts > 0:
                from config import TIMEOUT

                new_timeout = TIMEOUT + (registration_timeouts * 10)
                info(
                    f"[*] Increasing timeout to {new_timeout} seconds for next attempt"
                )
                TIMEOUT = new_timeout

        except Exception as e:
            error(f"[×] Error: {str(e)}")
            if not handle_between_attempts(attempt, MAX_ATTEMPTS):
                break

    error(f"[×] All attempts failed")
    return False, user_details  # Return user details anyway for reference


def verify_account_created(user_id, email, password):
    """Verify the account was actually created by attempting a simple check"""
    if not user_id or user_id in ["0", "Unknown"]:
        warn("[!] Invalid user ID, account likely not created successfully")
        return False

    try:
        # Create a simple session to check the profile URL
        session = requests.Session()
        profile_url = f"https://www.facebook.com/profile.php?id={user_id}"

        # Add realistic headers
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

        # Check if profile exists
        info(f"[*] Verifying profile existence at: {profile_url}")
        response = session.get(profile_url, timeout=10)

        # Look for indicators that the profile exists
        if response.status_code == 200 and user_id in response.text:
            success(f"[+] Account verified - profile page exists")
            return True
        else:
            warn(
                f"[!] Profile verification failed - page may not exist yet or requires login"
            )
            return False

    except Exception as e:
        warn(f"[!] Error during account verification: {e}")
        return False
