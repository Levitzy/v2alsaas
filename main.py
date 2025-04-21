#!/usr/bin/env python3
# Facebook Account Creator - Improved Version

import time
import sys

# Import utility modules
from utils.colors import banner, separator, success, error, info
from utils.proxy import load_proxies, test_proxy, get_random_proxy

# Import account handling
from facebook.account import get_user_email, create_facebook_account, print_summary


# Main function
def main():
    # Show banner
    banner()

    # Print welcome message
    success(f"[+] Facebook Account Creator - Advanced Version")
    info(f"[+] Starting: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Ask user if they want to use proxies
    use_proxies_input = input("[?] Use proxies? (y/n): ").lower()
    use_proxies = use_proxies_input in ["y", "yes"]

    if use_proxies:
        # Load and test proxies
        if load_proxies():
            info("[*] Testing proxy configuration...")
            proxy = get_random_proxy()
            if proxy:
                proxy_works = test_proxy(proxy)
                if not proxy_works:
                    error("[!] Proxy test failed. You may continue or disable proxies.")
                    use_anyway = input(
                        "[?] Continue with proxies anyway? (y/n): "
                    ).lower()
                    use_proxies = use_anyway in ["y", "yes"]
            else:
                error("[!] Could not get a valid proxy")
                use_proxies = False
        else:
            error("[!] No proxies loaded")
            use_proxies = False

    # Get email address
    email = get_user_email()
    if not email:
        error("[!] No valid email provided")
        return

    info(f"[+] Using email: {email}")

    start_time = time.time()

    # Create account
    try:
        success_status, user_details = create_facebook_account(email, use_proxies)

        # Print summary
        separator()
        print_summary(success_status, email, user_details, start_time)
        separator()

    except KeyboardInterrupt:
        print("\n")
        error("[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        error(f"[!] Unhandled error: {e}")
        separator()


# Entry point
if __name__ == "__main__":
    main()
