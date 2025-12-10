from server import *
from user import *
import random

class Attempt:
    def __init__(self):
        self.server = Server()
        self.DB = self.server.DB
        self.authorized_users = {}
        self.init_authorized_users()
        self.unauthorized_user = Unauthorized_user(self.DB.keys())

    def init_authorized_users(self):
        for username in self.DB.keys():
            self.authorized_users[username] = Authorized_user(username, self.DB[username]["password"], self.DB[username]["totp_secret"],self.DB[username]["totp_enabled"])
    
    def random_authorized_user_attempt(self):
        # random_username = random.choice(list(self.DB.keys()))
        print(self.authorized_users)
        random_username = "alex"
        print(f"user {random_username} is trying to log")
        self.server.login(random_username, self.DB[random_username]["password"])
        if self.DB[random_username]["totp_enabled"]:
            print(f"user {random_username} is trying to log in with TOTP")
            if not self.server.login_totp(random_username, self.authorized_users[random_username].get_totp_code()):
                print("ERROR: login with TOTP failed with authorized user!")
            
a = Attempt()
a.random_authorized_user_attempt()