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
    "1920x1080",
    "1366x768",
    "1536x864",
    "1440x900",
    "1280x720",
    "1600x900",
    "1280x800",
    "1280x1024",
    "2560x1440",
    "3840x2160",
    "2880x1800",
    "1920x1200",
]

# Color settings
SUCCESS_COLOR = "\x1b[38;5;22m"
ERROR_COLOR = "\x1b[38;5;196m"
INFO_COLOR = "\x1b[38;5;33m"
RESET_COLOR = "\x1b[0m"

# Updated Mobile user agents (2025)
MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.101 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.85 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-A756B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-F946B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/284.0.613445224 Mobile/15E148 Safari/604.1",
]

# Updated Desktop user agents (2025)
DESKTOP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36",
]

# Anti-detection settings
COMMON_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

# Updated Security token fallback
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
        "terms": "on",
        "datause": "on",
        "acknowledge_understanding": "on",
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
        "terms": "on",
        "datause": "on",
        "acknowledge_understanding": "on",
    },
}


# Browser fingerprinting
def get_random_browser_properties():
    """Generate random browser properties for fingerprinting evasion"""
    # Choose a platform first to create consistent properties
    platform = random.choice(["Windows", "Macintosh", "Linux", "Android", "iPhone"])

    # Set properties based on platform for better consistency
    if platform == "Windows":
        user_agent = random.choice(
            [ua for ua in DESKTOP_USER_AGENTS if "Windows" in ua]
        )
        pixel_ratio = random.choice([1, 1.25, 1.5, 2])
        color_depth = random.choice([24, 30])
    elif platform == "Macintosh":
        user_agent = random.choice(
            [ua for ua in DESKTOP_USER_AGENTS if "Macintosh" in ua]
        )
        pixel_ratio = random.choice([1, 2, 2.5])
        color_depth = 30
    elif platform == "Linux":
        user_agent = random.choice([ua for ua in DESKTOP_USER_AGENTS if "Linux" in ua])
        pixel_ratio = random.choice([1, 1.5, 2])
        color_depth = 24
    elif platform == "Android":
        user_agent = random.choice([ua for ua in MOBILE_USER_AGENTS if "Android" in ua])
        pixel_ratio = random.choice([1.5, 2, 2.5, 3, 3.5])
        color_depth = 32
    else:  # iPhone/iOS
        user_agent = random.choice(
            [ua for ua in MOBILE_USER_AGENTS if "iPhone" in ua or "iPad" in ua]
        )
        pixel_ratio = random.choice([2, 3])
        color_depth = 32

    # Mobile devices use different screen resolutions
    if platform in ["Android", "iPhone"]:
        screen_resolution = random.choice(
            [
                "412x915",
                "390x844",
                "360x780",
                "414x896",
                "375x812",
                "428x926",
                "393x851",
                "360x800",
                "384x854",
            ]
        )
    else:
        screen_resolution = random.choice(SCREEN_RESOLUTIONS)

    return {
        "screen_resolution": screen_resolution,
        "color_depth": color_depth,
        "pixel_ratio": pixel_ratio,
        "timezone_offset": random.randint(-720, 720),  # Minutes from UTC
        "language": random.choice(COMMON_LANGUAGES),
        "accept": random.choice(ACCEPT_HEADERS),
        "platform": platform,
        "user_agent": user_agent,
    }
