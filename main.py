#!/usr/bin/env python3
# Facebook Account Creator - Enhanced Version for 2025 Security

import time
import sys
import random
import argparse
import os
from datetime import datetime

# Import utility modules
from utils.colors import banner, separator, success, error, info, warn
from utils.proxy import load_proxies, test_proxy, get_random_proxy
from utils.helpers import wait_with_jitter, generate_browser_fingerprint

# Import account handling
from facebook.account import get_user_email, create_facebook_account, print_summary

# Global settings
DEFAULT_EMAIL_DOMAINS = [
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "protonmail.com",
    "aol.com",
    "icloud.com",
]


# Main function with enhanced options
def main():
    # Parse command line arguments for advanced usage
    parser = argparse.ArgumentParser(
        description="Facebook Account Creator - Enhanced 2025 Version"
    )
    parser.add_argument("-e", "--email", help="Email address to use for registration")
    parser.add_argument(
        "-p", "--proxy", action="store_true", help="Use proxies for registration"
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=int,
        default=0,
        help="Additional delay between attempts (seconds)",
    )
    parser.add_argument(
        "-r", "--retries", type=int, default=3, help="Number of retry attempts"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=40, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--max-wait",
        type=int,
        default=0,
        help="Maximum wait time between attempts (overrides default)",
    )

    args = parser.parse_args()

    # Show banner
    banner()

    # Print welcome message
    success(f"[+] Facebook Account Creator - Advanced Version")
    info(f"[+] Starting: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    info(f"[+] Security systems updated for 2025 Facebook protection")

    # Override settings from command line
    if args.retries:
        from config import MAX_ATTEMPTS

        MAX_ATTEMPTS = args.retries
        info(f"[+] Set retry attempts to: {MAX_ATTEMPTS}")

    if args.timeout:
        from config import TIMEOUT

        TIMEOUT = args.timeout
        info(f"[+] Set request timeout to: {TIMEOUT}s")

    if args.delay:
        from config import DELAY_BETWEEN_ATTEMPTS

        min_delay, max_delay = DELAY_BETWEEN_ATTEMPTS
        DELAY_BETWEEN_ATTEMPTS = (min_delay + args.delay, max_delay + args.delay)
        info(f"[+] Increased delay between attempts to: {DELAY_BETWEEN_ATTEMPTS}")

    if args.max_wait:
        from config import DELAY_BETWEEN_ATTEMPTS

        min_delay, _ = DELAY_BETWEEN_ATTEMPTS
        DELAY_BETWEEN_ATTEMPTS = (min_delay, args.max_wait)
        info(f"[+] Set maximum delay between attempts to: {args.max_wait}s")

    # Check and handle proxy usage
    use_proxies = args.proxy
    if not use_proxies:
        # If not specified by command line, ask interactively
        use_proxies_input = input("[?] Use proxies? (y/n): ").lower()
        use_proxies = use_proxies_input in ["y", "yes"]

    if use_proxies:
        # Load and test proxies with improved feedback
        proxy_loaded = load_proxies()
        if proxy_loaded:
            info("[*] Testing proxy configuration...")
            proxy = get_random_proxy()
            if proxy:
                proxy_display = list(proxy.values())[0]
                proxy_display = (
                    proxy_display.split("@")[-1]
                    if "@" in proxy_display
                    else proxy_display
                )
                info(f"[*] Selected proxy for testing: {proxy_display}")
                proxy_works = test_proxy(proxy)
                if not proxy_works:
                    error("[!] Proxy test failed. You may continue or disable proxies.")
                    use_anyway = input(
                        "[?] Continue with proxies anyway? (y/n): "
                    ).lower()
                    use_proxies = use_anyway in ["y", "yes"]
                else:
                    success("[+] Proxy test successful!")
            else:
                error("[!] Could not get a valid proxy")
                use_proxies = False
        else:
            error("[!] No proxies loaded")
            use_proxies = False

    # Get email address
    email = args.email
    if not email:
        email = get_user_email()

    if not email:
        error("[!] No valid email provided")
        return

    info(f"[+] Using email: {email}")

    # Create a browser fingerprint for this session
    session_fingerprint = generate_browser_fingerprint()
    # Get platform information safely with a fallback
    platform = session_fingerprint.get(
        "platform", session_fingerprint.get("device", {}).get("platform", "Unknown")
    )
    info(f"[+] Generated browser fingerprint: {platform} device")

    # Record start time for performance tracking
    start_time = time.time()

    # Create account with improved error handling
    try:
        # Run the account creation process
        success_status, user_details = create_facebook_account(
            email, use_proxies, session_fingerprint
        )

        # If account creation failed but we have details, we still want to show them
        if not success_status and not user_details:
            error("[!] Account creation failed completely")
            separator()
            return

        # Print summary
        separator()
        print_summary(success_status, email, user_details, start_time)
        separator()

        # Suggest next steps if successful
        if success_status:
            suggest_next_steps(email, user_details)

    except KeyboardInterrupt:
        print("\n")
        error("[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        error(f"[!] Unhandled error: {e}")
        separator()


def suggest_next_steps(email, user_details):
    """Suggest next steps after successful account creation"""
    info("\n[+] Next steps:")

    # Check temp email
    if any(
        domain in email.lower()
        for domain in [
            "temp",
            "tmp",
            "tempmail",
            "disposable",
            "cloudtempmail",
            "throwaway",
            "fake",
        ]
    ):
        info("[+] → Check your temporary email to confirm the account")
    else:
        info("[+] → Check your email to confirm the account")

    # Login suggestion
    info("[+] → Wait 5-10 minutes before logging in for the first time")
    info("[+] → When logging in, use the same browser fingerprint if possible")
    info("[+] → Use the same IP address when logging in to avoid security checks")

    # Account details were saved
    success(f"[+] Account details saved to:")
    info(f"    - Full details: facebook_accounts.txt")
    info(f"    - Login credentials: email_pass.txt")

    # Profile information
    if "profile_url" in user_details:
        info(f"[+] Profile URL: {user_details['profile_url']}")
        info(f"[+] Add friends and content to make your account look legitimate")


# Entry point
if __name__ == "__main__":
    main()
