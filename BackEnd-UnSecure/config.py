import base64
import os
import hashlib
import time

# Simple in-memory storage for password history and failed login attempts
# In a real app you'd store this in a database
password_history = {}
login_attempts = {}

# Dictionary words to deny (example set)
dictionary_words = {"password", "123456", "qwerty", "letmein", "admin"}

# Password Complexity Check
def password_validation(password, username=None):
    if len(password) < 10:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*()-_+=' for c in password):
        return False
    if password.lower() in dictionary_words:
        return False
    return True

def is_password_reused(username, new_hashed):
    history = password_history.get(username, [])
    return new_hashed in history

def update_password_history(username, new_hashed):
    history = password_history.setdefault(username, [])
    history.insert(0, new_hashed)
    password_history[username] = history[:3]

def record_failed_attempt(username):
    now = time.time()
    attempts = login_attempts.setdefault(username, [])
    attempts.append(now)
    login_attempts[username] = [t for t in attempts if now - t <= 1800]  # only keep within 30 minutes

def is_user_locked(username):
    now = time.time()
    attempts = login_attempts.get(username, [])
    recent_attempts = [t for t in attempts if now - t <= 1800]
    return len(recent_attempts) >= 3
