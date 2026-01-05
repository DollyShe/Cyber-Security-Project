import json
import time
import pyotp
import hashlib
import secrets
import os
from enum import Enum
from collections import defaultdict
from typing import Union
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from MetricsCollector import *

class LoginResult(Enum):
    OK = "ok"
    NO_SUCH_USER = "no_such_user"
    BAD_PASSWORD = "bad_password"
    TOTP_REQUIRED = "totp_required"
    BAD_TOTP = "bad_totp"
    TOTP_TIMEOUT = "totp_timeout"
    RATE_LIMITED = "rate_limited"
    LOCKED = "locked_account"
    CAPTCHA_REQUIRED = "captcha_required"
    CAPTCHA_FAILED = "captcha_failed"

class Server:
    # Server-side pepper (should be stored securely, e.g., environment variable)
    PEPPER = os.environ.get("PASSWORD_PEPPER", "S3cr3tP3pp3r!@#$%^&*()")

    def __init__(self, TOTP: bool = False, RL: bool = False, lockout: bool = False,
                 sha256_salt: bool = False, bcrypt_hash: bool = False, argon2_hash: bool = False,
                 captcha: bool = False, pepper: bool = False):
        with open("users.json") as f:
            self.DB = json.load(f)

        if argon2_hash:
            self.hashing = "argon2"
        elif bcrypt_hash:
            self.hashing = "bcrypt"
        elif sha256_salt:
            self.hashing = "sha256_salt"
        else:
            self.hashing = None
        
        self.protections = {
            'totp': TOTP,
            'rate_limiting': RL,
            'lockout': lockout,
            'captcha': captcha,
            'pepper': pepper,
            'hash_mode': self.hashing
        }
        
        # Initialize Argon2 hasher if needed
        if argon2_hash:
            self.argon2_hasher = PasswordHasher(
                time_cost=TIME,            # Number of iterations
                memory_cost=MEMORY * 1024, #(Note: Argon2 uses KiB, so 64 * 1024)
                parallelism=PARALLELISM    # Number of parallel threads
            )

        # Hash passwords if hashing is enabled and passwords are plain text
        if self.hashing:
            self._hash_passwords_if_needed()
            self.save_hashed_passwords()

        # TOTP setup
        if TOTP:
            self.add_totp()
            self.save()
        else:
            self.remove_totp()
            self.save()
        self.totp_challenges = {}

        # Rate limiting setup
        if RL:
            self.rate_limit = defaultdict(list)
        else:
            self.rate_limit = None
        
        # Account lockout setup
        if lockout:
            self.lockout = True
            self.add_lockout_fields()
        else: 
            self.lockout = False
        
        # CAPTCHA setup
        if captcha:
            self.captcha_challenges = {}  # {username: expiry_time}
            self.captcha_threshold = THRESHOLD  # Failed attempts before CAPTCHA required
            self.captcha_attempts = defaultdict(int)
    
    def add_lockout_fields(self):
        for user in self.DB:
            self.DB[user]["failed_attempts"] = 0
            self.DB[user]["locked"] = False
    
    def get_protection(self):
        return self.protections

    # ==================== PASSWORD HASHING ====================
    
    def _add_pepper(self, password: str) -> str:
        """Add pepper to password if enabled"""
        if self.protections.get('pepper'):
            return password + self.PEPPER
        return password
    
    def _hash_password_sha256_salt(self, password: str) -> dict:
        """Hash password using SHA-256 with random salt"""
        salt = secrets.token_hex(32)
        peppered = self._add_pepper(password)
        hashed = hashlib.sha256((peppered + salt).encode()).hexdigest()
        return {"hash": hashed, "salt": salt, "algorithm": "sha256_salt"}
    
    def _verify_sha256_salt(self, password: str, stored: dict) -> bool:
        """Verify password against SHA-256 + salt hash"""
        peppered = self._add_pepper(password)
        computed = hashlib.sha256((peppered + stored["salt"]).encode()).hexdigest()
        return secrets.compare_digest(computed, stored["hash"])
    
    def _hash_password_bcrypt(self, password: str) -> dict:
        """Hash password using bcrypt"""
        peppered = self._add_pepper(password)
        # Truncate to 72 bytes (bcrypt limit)
        password_bytes = peppered.encode('utf-8')[:72]
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=COST))
        return {"hash": hashed.decode('utf-8'), "algorithm": "bcrypt"}
    
    def _verify_bcrypt(self, password: str, stored: dict) -> bool:
        """Verify password against bcrypt hash"""
        peppered = self._add_pepper(password)
        try:
            password_bytes = peppered.encode('utf-8')[:72]
            return bcrypt.checkpw(password_bytes, stored["hash"].encode('utf-8'))
        except Exception:
            return False
    
    def _hash_password_argon2(self, password: str) -> dict:
        """Hash password using Argon2 (winner of Password Hashing Competition)"""
        peppered = self._add_pepper(password)
        hashed = self.argon2_hasher.hash(peppered)
        return {"hash": hashed, "algorithm": "argon2"}
    
    def _verify_argon2(self, password: str, stored: dict) -> bool:
        """Verify password against Argon2 hash"""
        peppered = self._add_pepper(password)
        try:
            self.argon2_hasher.verify(stored["hash"], peppered)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    
    def hash_password(self, password: str) -> Union[dict, str]:
        """Hash password using configured algorithm"""
        if self.protections.get('hash_mode') == "sha256_salt":
            return self._hash_password_sha256_salt(password)
        elif self.protections.get('hash_mode') == "bcrypt":
            return self._hash_password_bcrypt(password)
        elif self.protections.get('hash_mode') == "argon2":
            return self._hash_password_argon2(password)
        else:
            return password  # No hashing, return plain text
    
    def verify_password(self, password: str, stored_password) -> bool:
        """Verify password against stored hash or plain text"""
        # If stored_password is a dict, it's hashed
        if isinstance(stored_password, dict):
            algorithm = stored_password.get("algorithm")
            if algorithm == "sha256_salt":
                return self._verify_sha256_salt(password, stored_password)
            elif algorithm == "bcrypt":
                return self._verify_bcrypt(password, stored_password)
            elif algorithm == "argon2":
                return self._verify_argon2(password, stored_password)
        # Plain text comparison (for backwards compatibility)
        return secrets.compare_digest(password.encode('utf-8'), stored_password.encode('utf-8'))
    
    def _hash_passwords_if_needed(self):
        """Hash all plain text passwords in the database"""
        for username in self.DB:
            password = self.DB[username]["password"]
            # Only hash if it's still plain text (string, not dict)
            if isinstance(password, str):
                self.DB[username]["password"] = self.hash_password(password)
    
    def save_hashed_passwords(self):
        with open("hashed_passwords.json", "w") as f:
            json.dump(self.DB, f, indent=2)

    # ==================== CAPTCHA ====================
    
    def _check_captcha_required(self, username: str) -> bool:
        """Check if CAPTCHA is required for this user"""
        if not self.protections.get('captcha'):
            return False
        return self.captcha_attempts[username] >= self.captcha_threshold
    
    def request_captcha(self, username: str) -> str:
        """Generate a CAPTCHA challenge"""
        challenge = secrets.token_hex(4).upper()
        self.captcha_challenges[username] = {
            "challenge": challenge,
            "expires": time.time() + 60  # 1 minutes
        }
        return challenge
    
    def verify_captcha(self, username: str, response: str = None, solve: bool = False) -> LoginResult:
        """Verify CAPTCHA response"""
        if username not in self.captcha_challenges:
            return LoginResult.NO_SUCH_USER
        
        challenge_data = self.captcha_challenges[username]
        
        # Check expiration
        if time.time() > challenge_data["expires"]:
            del self.captcha_challenges[username]
            return LoginResult.CAPTCHA_FAILED
        
        # Auto-solve for authorized users (simulation)
        if solve:
            response = challenge_data["challenge"]
        
        if response == challenge_data["challenge"]:
            del self.captcha_challenges[username]
            self.captcha_attempts[username] = 0  # Reset attempts
            return LoginResult.OK
        
        return LoginResult.CAPTCHA_FAILED

    # ==================== TOTP ====================

    def remove_totp(self):
        self.DB["alex"]["totp_secret"] = None
        self.DB["alex"]["totp_enabled"] = False
        self.DB["taylor"]["totp_secret"] = None
        self.DB["taylor"]["totp_enabled"] = False

        self.DB["jules"]["totp_secret"] = None
        self.DB["jules"]["totp_enabled"] = False
        self.DB["sophie"]["totp_secret"] = None
        self.DB["sophie"]["totp_enabled"] = False

        self.DB["gamer01"]["totp_secret"] = None
        self.DB["gamer01"]["totp_enabled"] = False
        self.DB["bluebird"]["totp_secret"] = None
        self.DB["bluebird"]["totp_enabled"] = False

    def add_totp(self):
        self.DB["alex"]["totp_secret"] = pyotp.random_base32()
        self.DB["alex"]["totp_enabled"] = True
        self.DB["taylor"]["totp_secret"] = pyotp.random_base32()
        self.DB["taylor"]["totp_enabled"] = True

        self.DB["jules"]["totp_secret"] = pyotp.random_base32()
        self.DB["jules"]["totp_enabled"] = True
        self.DB["sophie"]["totp_secret"] = pyotp.random_base32()
        self.DB["sophie"]["totp_enabled"] = True

        self.DB["gamer01"]["totp_secret"] = pyotp.random_base32()
        self.DB["gamer01"]["totp_enabled"] = True
        self.DB["bluebird"]["totp_secret"] = pyotp.random_base32()
        self.DB["bluebird"]["totp_enabled"] = True

    def login_totp(self, username : str, code : str) -> LoginResult:
        if not self.DB[username]["totp_enabled"] or not self.DB[username]["totp_secret"]:
            print("ERROR: TOTP not enabled for this user\n")
            return LoginResult.NO_SUCH_USER
        expire = self.totp_challenges.get(username)
        if expire is None:
            # no active challenge; you can require password step first
            return LoginResult.TOTP_REQUIRED
        if time.time() > expire:
            del self.totp_challenges[username]
            return LoginResult.TOTP_TIMEOUT
        totp = pyotp.TOTP(self.DB[username]["totp_secret"])
        if totp.verify(code):
            return LoginResult.OK
        return LoginResult.BAD_TOTP

    # =================== SERVER ===================

    def register(self):
        user_name = input("Please choose a username. You'll use this to sign in. ")
        while user_name in self.DB.keys():
            user_name = input("That username is already taken. Please choose another. ")
        password = input("Please choose a password: ")
        self.DB[user_name] = {
            "user_name": user_name,
            "password": password
            }
        print("Account created successfully!")

    def get_username(self):
        user_name = input("Please enter your username. ")
        if user_name not in self.DB:
            raise Exception("Username not found. Please try again or register first.")
        return user_name
    
    def get_password(self):
        return input("Please enter your password. ")
    
    def login(self, username : str , password : str) -> LoginResult:
        if username not in self.DB:
            return LoginResult.NO_SUCH_USER
        # Check rate limiting
        if self.rate_limit != None:
            now = time.time()
            login_attempts = self.rate_limit[username]
            self.rate_limit[username] = [t for t in login_attempts if now - t < WINDOW]
            if len(self.rate_limit[username]) >= MAX_ATTEMPTS:
                return LoginResult.RATE_LIMITED
            self.rate_limit[username].append(now)
        # Check account lockout
        if self.lockout:
            if self.DB[username]["locked"]:
                return LoginResult.LOCKED
        # Check CAPTCHA requirement
        # If CAPTCHA required, verify it first
        if self._check_captcha_required(username):
            # Ensure there is an active challenge
            if username not in self.captcha_challenges:
                self.request_captcha(username)
                # You can store challenge internally and return just CAPTCHA_REQUIRED
                return LoginResult.CAPTCHA_REQUIRED
            # Verify response
            return self.verify_captcha(username, response=password)

        # Verify password (handles both hashed and plain text)
        stored_password = self.DB[username]["password"]
        if not self.verify_password(password, stored_password):
            # Track failed attempts for CAPTCHA
            if self.protections.get('captcha'):
                self.captcha_attempts[username] += 1

            # Track failed attempts for lockout
            if self.lockout:
                self.DB[username]["failed_attempts"] += 1
                if self.DB[username]["failed_attempts"] >= MAX_FAILS:
                    self.DB[username]["locked"] = True
            return LoginResult.BAD_PASSWORD
        
        # Password correct - check for TOTP
        if self.DB[username]["totp_enabled"]:
            self.totp_challenges[username] = time.time() + 30
            return LoginResult.TOTP_REQUIRED
        
        # Success - reset failed attempts
        if self.lockout:
            self.DB[username]["failed_attempts"] = 0

        return LoginResult.OK

    def save(self):
        with open("users.json", "w") as f:
            json.dump(self.DB, f, indent=2)

# S = Server()
# print("Welcome to the server.")
# while (True):
    
#     print("Please choose an action:")
#     print("1. register")
#     print("2. login")
#     print("3. login with totp")
#     print("4. exit")

#     user_input = input()
#     try:
#         action = int(user_input)
#     except ValueError:
#         print("Invalid input. Please enter a valid number.")
#         continue

#     try:
#         match action:
#             case 1:
#                 S.register()
#             case 2:
#                 username = S.get_username()
#                 S.login()
#             case 3:
#                 pass
#             case 4:
#                 print("")
#                 break
#             case _:  # Default case (wildcard)
#                 print("ERROR: Unknown action, please try again")
    
#     except Exception as e:
#         print("ERROR: ", e)
# S.save()

# S = Server(TOTP=False, RL=False, lockout=True)
# S.add_lockout_fields()
# S.save()