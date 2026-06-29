"""
Simple test/demo script for password_analyzer.py
Run this to see sample output without typing interactively.
"""

from password_analyzer import calculate_overall_strength, print_report, is_password_reused

test_passwords = [
    "123456",
    "password",
    "Summer2023",
    "Tr0ub4dor&3",
    "G7$kP9!mZq2@vL",
]

if __name__ == "__main__":
    print("Running demo on sample passwords...\n")
    history = []
    for pw in test_passwords:
        result = calculate_overall_strength(pw)
        reused = is_password_reused(pw, history)
        print(f"\n>>> Testing password: {pw}")
        print_report(pw, result, reused)
