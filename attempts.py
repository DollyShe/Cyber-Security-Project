from server import *
from user import *
import random
import logging
import secrets

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
        logging.info(f"-> LOGIN_ATTEMPT user={random_username}")
        if self.server.login(random_username, password):
            if self.DB[random_username]["totp_enabled"]:
                code = self.authorized_users[random_username].get_totp_code()
                logging.info(f"-> LOGIN_ATTEMPT_WITH_TOTP user={random_username}")
                if not self.server.login_totp(random_username, code):
                    logging.error(f"[FAIL] LOGIN_FAILED user={random_username} even though he's an authorized user!")
                    return
            logging.info(f"[OK] LOGIN_SUCCESS user={random_username}")
            return
        logging.warning(f"[FAIL] LOGIN_FAILED user={random_username}")
    
    def random_unauthorized_user_attempt(self):
        random_username = random.choice(list(self.DB.keys()))
        password = random.choice(list(passwords))
        logging.info(f"-> LOGIN_ATTEMPT user={random_username}")
        if self.server.login(random_username, password):
            if self.DB[random_username]["totp_enabled"]:
                code = f"{secrets.randbelow(1_000_000):06d}"
                logging.info(f"-> LOGIN_ATTEMPT_WITH_TOTP user={random_username}")
                if not self.server.login_totp(random_username, code):
                    logging.error(f"[FAIL] LOGIN_FAILED user={random_username} and he's an unauthorized user :)")
                    return
            logging.info(f"[OK] LOGIN_SUCCESS user={random_username}")
            return
        logging.warning(f"[FAIL] LOGIN_FAILED user={random_username}")
    
    def brute_force(self, username):
        with open("BF_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
        for password in passwords:
            logging.info(f"-> LOGIN_ATTEMPT user={username}")
            if self.server.login(username, password) == LoginResult.OK:
                logging.info(f"[OK] LOGIN_SUCCESS user={username}")
                return
            logging.warning(f"[FAIL] LOGIN_FAILED user={username}")
        
    
    def password_spraying(self):
        with open("PS_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
        for username in self.unauthorized_user.list_of_usernames:
            for password in passwords:
                logging.info(f"-> LOGIN_ATTEMPT user={username}")
                if self.server.login(username, password):
                    if self.DB[username]["totp_enabled"]:
                        code = f"{secrets.randbelow(1_000_000):06d}"
                        logging.info(f"-> LOGIN_ATTEMPT_WITH_TOTP user={username}")
                        while self.server.login_totp(username, code) != LoginResult.TOTP_TIMEOUT:
                            code = f"{secrets.randbelow(1_000_000):06d}"
                    logging.info(f"[OK] LOGIN_SUCCESS user={username}")
                    break
                logging.warning(f"[FAIL] LOGIN_FAILED user={username}")
        # logging.warning("login failed for unauthorized user via Password Spraying.")


# with open("BF_passwords.txt", "r") as file:
#     lines = file.readlines()
# passwords = [line.strip() for line in lines]        
# a = Attempt()
# for i in range(0,10):
#     a.random_authorized_user_attempt()
#     a.random_authorized_user_attempt()
#     a.random_unauthorized_user_attempt()
#     a.random_unauthorized_user_attempt()
#     a.random_unauthorized_user_attempt()

a = Attempt()
# a.password_spraying()
a.brute_force("sunnyday")
# a.brute_force("morgan")
