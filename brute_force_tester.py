#!/usr/bin/env python3
"""
Login brute-force tester — FOR USE ONLY AGAINST YOUR OWN AUTH ENDPOINTS.

Point this at your own app's login endpoint to test rate-limiting,
lockout policies, and password strength enforcement. Do not point
this at third-party services (Gmail, etc.) — it won't work against
them anyway (captchas, IP bans, MFA) and doing so is illegal.

Usage:
    python brute_force_tester.py \
        --url http://localhost:8000/api/login \
        --user test@myapp.local \
        --wordlist passwords.txt \
        --field-user email --field-pass password \
        --success-string "\"token\""

The script POSTs {field-user: user, field-pass: candidate} as JSON
and checks the response for --success-string. It stops on first hit,
respects --delay between attempts, and reports how many attempts
were made before a lockout/block (HTTP 423/429 or repeated failures)
so you can measure your own defenses.
"""

import argparse
import sys
import time

import requests


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True, help="Login endpoint URL (must be your own app)")
    p.add_argument("--user", required=True, help="Username/email to test")
    p.add_argument("--wordlist", required=True, help="Path to newline-separated password list")
    p.add_argument("--field-user", default="email", help="JSON field name for username")
    p.add_argument("--field-pass", default="password", help="JSON field name for password")
    p.add_argument("--success-string", required=True, help="Substring in response body that indicates success")
    p.add_argument("--delay", type=float, default=0.5, help="Seconds to wait between attempts")
    p.add_argument("--max-attempts", type=int, default=0, help="Stop after N attempts (0 = no limit)")
    p.add_argument(
        "--i-own-this-target",
        action="store_true",
        required=True,
        help="Confirms you have authorization to test this endpoint (required flag)",
    )
    return p.parse_args()


def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def main():
    args = parse_args()
    passwords = load_wordlist(args.wordlist)

    attempts = 0
    for pw in passwords:
        if args.max_attempts and attempts >= args.max_attempts:
            print(f"[stopped] reached max-attempts={args.max_attempts}")
            break

        attempts += 1
        payload = {args.field_user: args.user, args.field_pass: pw}

        try:
            resp = requests.post(args.url, json=payload, timeout=10)
        except requests.RequestException as e:
            print(f"[error] request failed: {e}")
            continue

        if resp.status_code in (423, 429):
            print(f"[locked-out] after {attempts} attempts — status {resp.status_code}. "
                  f"Lockout/rate-limit triggered correctly.")
            break

        if args.success_string in resp.text:
            print(f"[success] password found after {attempts} attempts: {pw!r}")
            break

        print(f"[{attempts}] tried {pw!r} -> {resp.status_code} (no match)")
        time.sleep(args.delay)
    else:
        print(f"[done] exhausted wordlist ({attempts} attempts), no match, no lockout triggered.")


if __name__ == "__main__":
    main()
