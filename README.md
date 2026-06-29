# 🔐 Password Strength Analyzer

A Python command-line tool that evaluates the strength of user-entered passwords, checks their length, complexity, and uniqueness, suggests stronger alternatives, and optionally prevents reuse of previously used passwords using a securely hashed local history.

> Built as part of the **Cyber Security Virtual Internship – Mini Project** .

## 📋 Features

-  **Length check** — flags passwords under 8 characters, rewards longer ones
-  **Complexity check** — verifies presence of lowercase, uppercase, digits, and symbols
-  **Uniqueness check** — detects common/leaked passwords, repeated characters (`aaa`), and keyboard/alphabet sequences (`1234`, `qwerty`)
-  **Strength scoring** — combines all checks into a percentage score and verdict: `VERY WEAK` → `WEAK` → `MODERATE` → `STRONG` → `VERY STRONG`
-  **Smart suggestions** — offers both an improved version of your existing password and a randomly generated strong password
-  **(Optional) Password reuse prevention** — stores a **SHA-256 hash** (never the plaintext) of previously used passwords in `password_history.json` and warns if you try to reuse one

## 🛠️ Tech Stack

- Python 3 (standard library only — `re`, `hashlib`, `json`, `secrets`, `string`)
- No external dependencies required

## 📂 Project Structure

```
password-strength-analyzer/
├── password_analyzer.py    # Main program (run this)
├── test_analyzer.py        # Demo script with sample passwords
├── README.md
└── .gitignore
```

## 🚀 How to Run

```bash
# Clone the repo
git clone https://github.com/<your-username>/password-strength-analyzer.git
cd password-strength-analyzer

# Run the interactive analyzer
python3 password_analyzer.py

# OR run the demo with pre-set sample passwords
python3 test_analyzer.py
```

## 🖥️ Sample Output

```
==================================================
 PASSWORD STRENGTH REPORT
==================================================
 Password length     : 8 characters
 Strength            : VERY WEAK (20%)
 [██████------------------------]
--------------------------------------------------
 Length check        : Acceptable length, but longer is better
 Missing char types  : uppercase, digits, symbols
 Issues found        :
   - This is a very common/leaked password
==================================================

Suggestions to strengthen your password:
 1. Improved version of your password:
   -> Password45!
 2. Randomly generated strong password:
   -> Qj8$vR2pL!mXkD
```

```
==================================================
 PASSWORD STRENGTH REPORT
==================================================
 Password length     : 14 characters
 Strength            : VERY STRONG (90%)
 [███████████████████████████---]
--------------------------------------------------
 Length check        : Good length
 Character variety   : Excellent (all types used)
 Pattern check       : No common patterns detected
==================================================
```

## 🔒 How the Optional Reuse-Prevention Works

When you choose to save a password, the program **never stores the plaintext**. Instead it computes a one-way `SHA-256` hash and saves only that hash plus a timestamp to `password_history.json`. On future checks, it hashes the new input and compares hashes — so even if `password_history.json` is leaked, the original passwords cannot be recovered.

## 📚 What I Learned

- How password strength is evaluated in real-world systems (length, entropy, character variety)
- Common attack patterns: dictionary attacks, sequential patterns, character repetition
- Why plaintext passwords should never be stored, and how one-way hashing (SHA-256) protects stored credentials
- Basic applied cryptography concepts: hashing vs encryption, and using Python's `secrets` module for cryptographically secure random generation (instead of `random`)

## 📄 License

This project is open-source and available for educational use.
