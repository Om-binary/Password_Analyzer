"""
Password Strength Analyzer
============================
A tool that evaluates the strength of user-entered passwords, checks
length/complexity/uniqueness, suggests stronger alternatives, and
(optionally) prevents reuse of old passwords using a local hashed
password history database.

Author: <your name here>
Project: Cyber Security Internship - Mini Project 1 (Thiranex)
"""

import re
import hashlib
import json
import os
import secrets
import string
from datetime import datetime

HISTORY_FILE = "password_history.json"

# ---------------------------------------------------------------------------
# 1. Core strength evaluation
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "111111",
    "123123", "letmein", "iloveyou", "admin", "welcome", "monkey",
    "password1", "1234567890", "football", "dragon", "master"
}


def check_length(password: str) -> dict:
    """Score based on password length."""
    length = len(password)
    if length < 8:
        return {"score": 0, "message": "Too short (minimum 8 characters)"}
    elif length < 12:
        return {"score": 1, "message": "Acceptable length, but longer is better"}
    elif length < 16:
        return {"score": 2, "message": "Good length"}
    else:
        return {"score": 3, "message": "Excellent length"}


def check_complexity(password: str) -> dict:
    """Score based on character variety: lowercase, uppercase, digits, symbols."""
    checks = {
        "lowercase": re.search(r"[a-z]", password) is not None,
        "uppercase": re.search(r"[A-Z]", password) is not None,
        "digits": re.search(r"[0-9]", password) is not None,
        "symbols": re.search(r"[^a-zA-Z0-9]", password) is not None,
    }
    variety = sum(checks.values())
    missing = [k for k, v in checks.items() if not v]
    return {"score": variety, "checks": checks, "missing": missing}


def check_uniqueness(password: str) -> dict:
    """Penalize common passwords, repeated characters, and sequential patterns."""
    issues = []
    score = 3

    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is a very common/leaked password")
        score = 0

    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains 3+ repeated characters in a row (e.g. 'aaa')")
        score -= 1

    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"]
    lowered = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in lowered:
                issues.append("Contains a keyboard/alphabet/number sequence")
                score -= 1
                break

    score = max(0, score)
    return {"score": score, "issues": issues}


def calculate_overall_strength(password: str) -> dict:
    """Combine all checks into a final verdict."""
    length_result = check_length(password)
    complexity_result = check_complexity(password)
    uniqueness_result = check_uniqueness(password)

    total_score = (
        length_result["score"]
        + complexity_result["score"]
        + uniqueness_result["score"]
    )
    # Max possible: 3 (length) + 4 (complexity) + 3 (uniqueness) = 10
    max_score = 10
    percentage = round((total_score / max_score) * 100)

    if percentage < 30:
        verdict = "VERY WEAK"
    elif percentage < 50:
        verdict = "WEAK"
    elif percentage < 70:
        verdict = "MODERATE"
    elif percentage < 90:
        verdict = "STRONG"
    else:
        verdict = "VERY STRONG"

    return {
        "password_length": len(password),
        "length_result": length_result,
        "complexity_result": complexity_result,
        "uniqueness_result": uniqueness_result,
        "total_score": total_score,
        "max_score": max_score,
        "percentage": percentage,
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# 2. Suggest a stronger password
# ---------------------------------------------------------------------------

def suggest_strong_password(length: int = 14) -> str:
    """Generate a cryptographically strong random password suggestion."""
    if length < 12:
        length = 12
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        result = calculate_overall_strength(candidate)
        if result["verdict"] in ("STRONG", "VERY STRONG"):
            return candidate


def improve_existing_password(password: str) -> str:
    """Take the user's password and strengthen it rather than discarding it,
    so the suggestion still feels familiar/memorable."""
    improved = password
    if not re.search(r"[A-Z]", improved):
        improved = improved[0].upper() + improved[1:] if improved else improved
    if not re.search(r"[0-9]", improved):
        improved += str(secrets.randbelow(90) + 10)
    if not re.search(r"[^a-zA-Z0-9]", improved):
        improved += secrets.choice("!@#$%^&*")
    while len(improved) < 12:
        improved += secrets.choice(string.ascii_letters + string.digits)
    return improved


# ---------------------------------------------------------------------------
# 3. Optional: prevent reuse of old passwords (hashed history)
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """One-way SHA-256 hash. We never store plaintext passwords."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_history() -> list:
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []


def save_history(history: list) -> None:
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def is_password_reused(password: str, history: list) -> bool:
    hashed = _hash_password(password)
    return any(entry["hash"] == hashed for entry in history)


def add_to_history(password: str, history: list) -> list:
    history.append({
        "hash": _hash_password(password),
        "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return history


# ---------------------------------------------------------------------------
# 4. Display helpers
# ---------------------------------------------------------------------------

def print_report(password: str, result: dict, reused: bool) -> None:
    bar_length = 30
    filled = round((result["percentage"] / 100) * bar_length)
    bar = "█" * filled + "-" * (bar_length - filled)

    print("\n" + "=" * 50)
    print(" PASSWORD STRENGTH REPORT")
    print("=" * 50)
    print(f" Password length     : {result['password_length']} characters")
    print(f" Strength            : {result['verdict']} ({result['percentage']}%)")
    print(f" [{bar}]")
    print("-" * 50)
    print(" Length check        :", result["length_result"]["message"])

    missing = result["complexity_result"]["missing"]
    if missing:
        print(" Missing char types  :", ", ".join(missing))
    else:
        print(" Character variety   : Excellent (all types used)")

    if result["uniqueness_result"]["issues"]:
        print(" Issues found        :")
        for issue in result["uniqueness_result"]["issues"]:
            print("   -", issue)
    else:
        print(" Pattern check       : No common patterns detected")

    if reused:
        print(" ⚠ REUSE WARNING     : This password was used before!")

    print("=" * 50)


# ---------------------------------------------------------------------------
# 5. Main program
# ---------------------------------------------------------------------------

def main():
    print("=" * 50)
    print(" PASSWORD STRENGTH ANALYZER")
    print(" (type 'exit' to quit)")
    print("=" * 50)

    history = load_history()

    while True:
        password = input("\nEnter a password to analyze: ")
        if password.lower() == "exit":
            print("Goodbye!")
            break
        if password == "":
            print("Please enter a non-empty password.")
            continue

        result = calculate_overall_strength(password)
        reused = is_password_reused(password, history)
        print_report(password, result, reused)

        if result["verdict"] in ("VERY WEAK", "WEAK", "MODERATE") or reused:
            print("\nSuggestions to strengthen your password:")
            print(" 1. Improved version of your password:")
            print("   ->", improve_existing_password(password))
            print(" 2. Randomly generated strong password:")
            print("   ->", suggest_strong_password())

        save_choice = input(
            "\nSave this password to history (to prevent future reuse)? [y/N]: "
        ).strip().lower()
        if save_choice == "y":
            history = add_to_history(password, history)
            save_history(history)
            print("Saved (only a secure hash is stored, never the plaintext).")


if __name__ == "__main__":
    main()
