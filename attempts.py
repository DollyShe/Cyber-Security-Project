from server import *
from user import *
import random
import logging

GROUP_SEED = 526338897

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),          # console
        logging.FileHandler("attempts.log", mode="w") # file
    ]
)

class Attempt:
    def __init__(self):
        logging.info(f"Program started - {GROUP_SEED}")
        self.server = Server()
        self.DB = self.server.DB
        self.authorized_users = {}
        self.init_authorized_users()
        self.unauthorized_user = Unauthorized_user(self.DB.keys())

    def init_authorized_users(self):
        for username in self.DB.keys():
            self.authorized_users[username] = Authorized_user(username, self.DB[username]["password"], self.DB[username]["totp_secret"],self.DB[username]["totp_enabled"])
    
    def random_authorized_user_attempt(self):
        random_username = random.choice(list(self.DB.keys()))
        # random_username = "alex"
        password = self.DB[random_username]["password"]
        logging.info(f"user {random_username} is trying to login with the password: {password}")
        self.server.login(random_username, password)
        if self.DB[random_username]["totp_enabled"]:
            logging.info(f"user {random_username} is requested to input the TOTP code")
            if not self.server.login_totp(random_username, self.authorized_users[random_username].get_totp_code()):
                logging.error("login with TOTP failed with authorized user!")
                return
        logging.info("login succeeded")
    
    def random_unauthorized_user_attempt(self):
        pass
    
    def brute_force(self):
        # get 10 random usernames
        usernames = random.sample(list(self.DB.keys()), 10)
        with open("BF_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
        for username in usernames:
            for password in passwords:
                logging.info(f"user {username} is trying to login with the password: {password}")
                if self.server.login(username, password):
                    logging.info("login succeeded for unauthorized user! via Brute Force.")
                    return
        logging.info("login failed for unauthorized user via Brute Force.")
    
    def password_spraying(self, username):
        with open("PS_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
        for username in self.unauthorized_user.list_of_usernames:
            for password in passwords:
                if self.server.login(username, password):
                    logging.info("login succeeded for unauthorized user! via Password Spraying.")
                    return
        logging.info("login failed for unauthorized user via Password Spraying.")

            
a = Attempt()
a.random_authorized_user_attempt()