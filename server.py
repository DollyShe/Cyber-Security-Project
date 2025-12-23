import json
import time, pyotp
from enum import Enum
from collections import defaultdict

class LoginResult(Enum):
    OK = "ok"
    NO_SUCH_USER = "no_such_user"
    BAD_PASSWORD = "bad_password"
    TOTP_REQUIRED = "totp_required"
    BAD_TOTP = "bad_totp"
    TOTP_TIMEOUT = "totp_timeout"
    RATE_LIMITED = "rate_limited"
    LOCKED = "locked_account"

class Server:
    def __init__(self, TOTP : bool, RL : bool, lockout : bool):
        with open("users.json") as f:
            self.DB = json.load(f)
        if TOTP:
            self.add_totp()
        else:
            self.remove_totp()
        self.totp_challenges = {}
        if RL:
            self.rate_limit = defaultdict(list)
            self.MAX_ATTEMPTS = 5 # atempt
            self.WINDOW = 60  # seconds
        else:
            self.rate_limit = None
        if lockout:
            self.lockout = True
            self.MAX_FAILS = 10 # atempt
            self.add_lockout_fields()
        else: 
            self.lockout = False
    
    def add_lockout_fields(self):
        for user in self.DB:
            self.DB[user]["failed_attempts"] = 0
            self.DB[user]["locked"] = False

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
        if self.rate_limit != None:
            now = time.time()
            login_attempts = self.rate_limit[username]
            self.rate_limit[username] = [t for t in login_attempts if now - t < self.WINDOW]
            if len(self.rate_limit[username]) >= self.MAX_ATTEMPTS:
                return LoginResult.RATE_LIMITED
            self.rate_limit[username].append(now)
        if self.lockout:
            if self.DB[username]["locked"]:
                return LoginResult.LOCKED
        while password != self.DB[username]["password"]:
            if self.lockout:
                self.DB[username]["failed_attempts"] += 1
                if self.DB[username]["failed_attempts"] >= self.MAX_FAILS:
                    self.DB[username]["locked"] = True
                    return LoginResult.BAD_PASSWORD
            return LoginResult.BAD_PASSWORD
        if self.DB[username]["totp_enabled"]:
            self.totp_challenges[username] = time.time() + 30
            return LoginResult.TOTP_REQUIRED
        if self.lockout:
            self.DB[username]["failed_attempts"] = 0
        return LoginResult.OK

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

    def save(self):
        with open("users.json", "w") as f:
            json.dump(self.DB, f, indent=2)

# S = Server()
print("Welcome to the server.")
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