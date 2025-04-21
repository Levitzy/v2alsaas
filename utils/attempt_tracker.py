# Attempt tracking utility to monitor success rates

import os
import json
import time
from datetime import datetime, timedelta
from utils.colors import info, error

# File to store attempt statistics
STATS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "attempt_stats.json",
)

# Ensure the data directory exists
os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)


def get_attempt_stats():
    """Get current attempt statistics"""
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, "r") as f:
                stats = json.load(f)
            return stats
        else:
            # Initialize with default stats
            return {
                "total": 0,
                "success": 0,
                "failure": 0,
                "last_attempt": None,
                "last_success": None,
                "daily_stats": {},
                "hourly_success_rate": {},
            }
    except Exception as e:
        error(f"[!] Error reading stats: {e}")
        return None


def update_attempt_stats(success=False):
    """Update attempt statistics"""
    try:
        # Get current stats
        stats = get_attempt_stats() or {
            "total": 0,
            "success": 0,
            "failure": 0,
            "last_attempt": None,
            "last_success": None,
            "daily_stats": {},
            "hourly_success_rate": {},
        }

        # Update counts
        stats["total"] += 1
        if success:
            stats["success"] += 1
            stats["last_success"] = datetime.now().isoformat()
        else:
            stats["failure"] += 1

        stats["last_attempt"] = datetime.now().isoformat()

        # Update daily stats
        today = datetime.now().strftime("%Y-%m-%d")
        if today not in stats["daily_stats"]:
            stats["daily_stats"][today] = {"total": 0, "success": 0}

        stats["daily_stats"][today]["total"] += 1
        if success:
            stats["daily_stats"][today]["success"] += 1

        # Update hourly success rate
        current_hour = datetime.now().strftime("%Y-%m-%d %H:00")
        if current_hour not in stats["hourly_success_rate"]:
            stats["hourly_success_rate"][current_hour] = {"total": 0, "success": 0}

        stats["hourly_success_rate"][current_hour]["total"] += 1
        if success:
            stats["hourly_success_rate"][current_hour]["success"] += 1

        # Clean up old hourly stats (keep only last 7 days)
        cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
        stats["hourly_success_rate"] = {
            k: v
            for k, v in stats["hourly_success_rate"].items()
            if k.split(" ")[0] >= cutoff
        }

        # Clean up old daily stats (keep only last 30 days)
        cutoff = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        stats["daily_stats"] = {
            k: v for k, v in stats["daily_stats"].items() if k >= cutoff
        }

        # Save updated stats
        with open(STATS_FILE, "w") as f:
            json.dump(stats, f, indent=2)

        return stats

    except Exception as e:
        error(f"[!] Error updating stats: {e}")
        return None


def get_success_rate():
    """Get current success rate as percentage"""
    stats = get_attempt_stats()
    if not stats or stats["total"] == 0:
        return 0

    return (stats["success"] / stats["total"]) * 100


def get_best_time_to_register():
    """Analyze hourly success rates to determine the best time to register"""
    stats = get_attempt_stats()
    if not stats or not stats["hourly_success_rate"]:
        return None

    # Calculate success rate for each hour that has at least 3 attempts
    hourly_rates = {}
    for hour, data in stats["hourly_success_rate"].items():
        if data["total"] >= 3:  # Only consider hours with enough data
            hourly_rates[hour] = (data["success"] / data["total"]) * 100

    if not hourly_rates:
        return None

    # Find the hour with the highest success rate
    best_hour = max(hourly_rates.items(), key=lambda x: x[1])
    return {
        "hour": best_hour[0],
        "success_rate": best_hour[1],
    }


def print_stats_summary():
    """Print a summary of attempt statistics"""
    stats = get_attempt_stats()
    if not stats:
        info("[*] No statistics available yet")
        return

    success_rate = (
        (stats["success"] / stats["total"]) * 100 if stats["total"] > 0 else 0
    )

    info("\n[+] Registration Statistics:")
    info(f"    Total attempts: {stats['total']}")
    info(f"    Successful registrations: {stats['success']}")
    info(f"    Failed registrations: {stats['failure']}")
    info(f"    Overall success rate: {success_rate:.1f}%")

    # Show today's stats
    today = datetime.now().strftime("%Y-%m-%d")
    if today in stats["daily_stats"]:
        today_stats = stats["daily_stats"][today]
        today_rate = (
            (today_stats["success"] / today_stats["total"]) * 100
            if today_stats["total"] > 0
            else 0
        )
        info(
            f"    Today's success rate: {today_rate:.1f}% ({today_stats['success']}/{today_stats['total']})"
        )

    # Show best registration time if available
    best_time = get_best_time_to_register()
    if best_time:
        hour_display = datetime.strptime(
            best_time["hour"].split(" ")[1], "%H:00"
        ).strftime("%I %p")
        info(
            f"    Best time to register: {hour_display} ({best_time['success_rate']:.1f}% success rate)"
        )
