import hashlib
import hmac
import os
import json
import re

# Load security settings from the config file
def load_config():
    with open('config.json', 'r') as f:
        return json.load(f)

def validate_password_complexity(password):
    """
    Requirement 1b: Check password complexity based on config file.
    Ensures minimum length (12), numbers, and special characters.
    """
    config = load_config()
    if len(password) < config['min_length']:
        return False, f"Password must be at least {config['min_length']} characters."
    if config['require_numbers'] and not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if config['require_special_char'] and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain a special character."
    return True, "Valid"

def hash_password_hmac(password, salt=None):
    """
    Requirement 1c: Store password using HMAC + Salt.
    """
    config = load_config()
    if not salt:
        # Generate a unique 16-byte salt for each user
        salt = os.urandom(16).hex()
    
    # Secret key from config + unique salt
    key = config['hmac_secret_key'].encode()
    message = (password + salt).encode()
    
    # Create the hash using HMAC-SHA256
    pw_hash = hmac.new(key, message, hashlib.sha256).hexdigest()
    return pw_hash, salt

def generate_sha1_token(raw_value):
    """
    Requirement 5c: Generate a random value defined using SHA-1.
    Used for the 'Forgot Password' recovery process.
    """
    return hashlib.sha1(raw_value.encode()).hexdigest()