import json
import time, pyotp
from enum import Enum


class LoginResult(Enum):
    OK = "ok"
    NO_SUCH_USER = "no_such_user"
    BAD_PASSWORD = "bad_password"
    TOTP_REQUIRED = "totp_required"
    BAD_TOTP = "bad_totp"
    TOTP_TIMEOUT = "totp_timeout"

class Server:
    def __init__(self):
        with open("users.json") as f:
            self.DB = json.load(f)
        self.totp_challenges = {}
    
    def register(self):
        user_name = input("Please choose a username. You'll use this to sign in. ")
        while user_name in self.DB.keys():
            user_name = input("That username is already taken. Please choose another. ")
        password = input("Please choose a password: ")
        self.DB[user_name] = {
        "user_name": user_name,
        "password": password}
        print("Account created successfully!")

    def add_totp(self):
        self.DB["alex"]["totp_secret"] =  pyotp.random_base32()
        self.DB["alex"]["totp_enabled"] = True
        self.DB["taylor"]["totp_secret"] =  pyotp.random_base32()
        self.DB["taylor"]["totp_enabled"] = True

        self.DB["jules"]["totp_secret"] =  pyotp.random_base32()
        self.DB["jules"]["totp_enabled"] = True
        self.DB["sophie"]["totp_secret"] =  pyotp.random_base32()
        self.DB["sophie"]["totp_enabled"] = True

        self.DB["gamer01"]["totp_secret"] =  pyotp.random_base32()
        self.DB["gamer01"]["totp_enabled"] = True
        self.DB["bluebird"]["totp_secret"] =  pyotp.random_base32()
        self.DB["bluebird"]["totp_enabled"] = True
    
    def get_username(self):
        user_name = input("Please enter your username. ")
        if user_name not in self.DB:
            raise Exception("Username not found. Please try again or register first.")
        return user_name
    
    def get_password(self):
        return input("Please enter your password. ")
    
    def login(self, username, password) -> LoginResult:
        if username not in self.DB:
            return LoginResult.NO_SUCH_USER
        while password != self.DB[username]["password"]:
            return LoginResult.BAD_PASSWORD
        if self.DB[username]["totp_enabled"]:
            self.totp_challenges[username] = time.time() + 30
            return LoginResult.TOTP_REQUIRED
        return LoginResult.OK

    def login_totp(self, username, code) -> LoginResult:
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
