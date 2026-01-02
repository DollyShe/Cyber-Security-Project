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
    def __init__(self, TOTP : bool = False, RL : bool = False, lockout : bool = False, captcha: bool = False):
        logging.info(f"Program started - {GROUP_SEED}")
        self.server = Server(TOTP=TOTP, RL=RL, lockout=lockout, captcha=captcha)
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
                    logging.error(f"[FAIL] LOGIN_FAIL user={random_username} even though he's an authorized user!")
                    return
            logging.info(f"[OK] LOGIN_SUCCESS user={random_username}")
            return
        logging.warning(f"[FAIL] LOGIN_FAIL user={random_username}")
    
    def random_unauthorized_user_attempt(self):
        random_username = random.choice(list(self.DB.keys()))
        password = random.choice(list(passwords))
        logging.info(f"-> LOGIN_ATTEMPT user={random_username}")
        if self.server.login(random_username, password):
            if self.DB[random_username]["totp_enabled"]:
                code = f"{secrets.randbelow(1_000_000):06d}"
                logging.info(f"-> LOGIN_ATTEMPT_WITH_TOTP user={random_username}")
                if not self.server.login_totp(random_username, code):
                    logging.error(f"[FAIL] LOGIN_FAIL user={random_username} and he's an unauthorized user :)")
                    return
            logging.info(f"[OK] LOGIN_SUCCESS user={random_username}")
            return
        logging.warning(f"[FAIL] LOGIN_FAIL user={random_username}")
    
    def brute_force(self, username : str):
        with open("BF_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
        for password in passwords:
            logging.info(f"-> LOGIN_ATTEMPT user={username}")
            result = self.server.login(username, password)
            if result == LoginResult.OK:
                logging.info(f"[OK] LOGIN_SUCCESS user={username}")
                return
            # if result == LoginResult.TOTP_REQUIRED: not sure if to add this
            #     logging.warning(f"[FAIL] LOGIN_FAIL user={username} due to {result}")
            #     break
            logging.warning(f"[FAIL] LOGIN_FAIL user={username} due to {result}")
        
    def password_spraying(self):
        count = 0
        with open("PS_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
        for username in self.unauthorized_user.list_of_usernames:
            for password in passwords:
                logging.info(f"-> LOGIN_ATTEMPT user={username}")
                result = self.server.login(username, password)
                if result == LoginResult.OK:
                    logging.info(f"[OK] LOGIN_SUCCESS user={username}")
                    count += 1
                    break
                logging.warning(f"[FAIL] LOGIN_FAIL user={username} due to {result}")
        if count > 0:
            logging.info(f"login succeeded for unauthorized user via Password Spraying for {count} users over {len(self.unauthorized_user.list_of_usernames)}")
        else:
            logging.info(f"login failed for unauthorized user via Password Spraying for all {len(self.unauthorized_user.list_of_usernames)} users")


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

a = Attempt(captcha=True)
a.password_spraying()
# a.brute_force("taylor") # easy password with lockout fails after 10 passwords
# a.brute_force("morgan")
