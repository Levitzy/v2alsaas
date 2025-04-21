# Facebook Account Creator Configuration

import os
import random

# Global settings
USE_PROXIES = False  # Default value, will be updated from user input
MAX_ATTEMPTS = 3
DELAY_BETWEEN_ATTEMPTS = (3, 5)  # Range in seconds
TIMEOUT = 30

# Paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PROXIES_PATH = os.path.join(ROOT_DIR, "proxies.txt")
ACCOUNTS_PATH = os.path.join(ROOT_DIR, "facebook_accounts.txt")
EMAIL_PASS_PATH = os.path.join(ROOT_DIR, "email_pass.txt")

# Facebook URLs
FB_MOBILE_URL = "https://m.facebook.com"
FB_DESKTOP_URL = "https://www.facebook.com"

# Browser fingerprinting
SCREEN_RESOLUTIONS = [
    "1920x1080", "1366x768", "1536x864", "1440x900", 
    "1280x720", "1600x900", "1280x800", "1280x1024"
]

# Color settings
SUCCESS_COLOR = "\x1b[38;5;22m"
ERROR_COLOR = "\x1b[38;5;196m"
INFO_COLOR = "\x1b[38;5;33m"
RESET_COLOR = "\x1b[0m"

# Mobile user agents
MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.66 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]

# Desktop user agents (newest browsers)
DESKTOP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

# Anti-detection settings
COMMON_LANGUAGES = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-CA,en;q=0.9", "en-AU,en;q=0.9"]
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

# Security token fallback
DEFAULT_FORM_FIELDS = {
    "desktop": {
        "firstname": "",
        "lastname": "",
        "reg_email__": "",
        "reg_email_confirmation__": "",
        "reg_passwd__": "",
        "birthday_day": "",
        "birthday_month": "",
        "birthday_year": "",
        "sex": "",
        "websubmit": "Sign Up",
        "referrer": "",
        "name_suggest_elig": "false",
        "nsid": "",
        "reg_instance": "",
        "locale": "en_US",
        "client_id": "1",
        "cver": "regular",
    },
    "mobile": {
        "firstname": "",
        "lastname": "",
        "reg_email__": "",
        "reg_email_confirmation__": "",
        "reg_passwd__": "",
        "birthday_day": "",
        "birthday_month": "",
        "birthday_year": "",
        "sex": "",
        "websubmit": "Sign Up",
        "referrer": "mobile_basic_reg",
        "locale": "en_US",
    }
}

# Browser fingerprinting
def get_random_browser_properties():
    """Generate random browser properties for fingerprinting evasion"""
    return {
        "screen_resolution": random.choice(SCREEN_RESOLUTIONS),
        "color_depth": random.choice([24, 32]),
        "pixel_ratio": random.choice([1, 1.5, 2, 2.5, 3]),
        "timezone_offset": random.randint(-720, 720),  # Minutes from UTC
        "language": random.choice(COMMON_LANGUAGES),
        "accept": random.choice(ACCEPT_HEADERS),
        "platform": random.choice(["Windows", "Macintosh", "Linux", "Android", "iPhone"])
    }
    