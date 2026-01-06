from server import *
from user import *
import random
import logging
import secrets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),          # console
        logging.FileHandler("attempts.log", mode="w") # file
    ]
)

class Attempt:
    def __init__(self, TOTP: bool = False, RL: bool = False, lockout: bool = False,
                 sha256_salt: bool = False, bcrypt_hash: bool = False, argon2_hash: bool = False,
                 captcha: bool = False, pepper: bool = False):
        logging.info(f"Program started - {GROUP_SEED}")
        self.server = Server(TOTP=TOTP, RL=RL, lockout=lockout, sha256_salt=sha256_salt, bcrypt_hash=bcrypt_hash, argon2_hash=argon2_hash,
                 captcha=captcha, pepper=pepper)
        self.DB = self.server.DB
        self.authorized_users = {}
        self.init_authorized_users()
        self.unauthorized_user = Unauthorized_user(self.DB.keys())
        self.metrics = MetricsCollector()

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
        with open("BF_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
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
            start = time.perf_counter()
            result = self.server.login(username, password)
            latency_ms = (time.perf_counter() - start) * 1000
            self.metrics.record_attempt(username, self.server.protections, result.value, latency_ms)
            if result == LoginResult.OK:
                logging.info(f"[OK] LOGIN_SUCCESS user={username}")
                return
            logging.warning(f"[FAIL] LOGIN_FAIL user={username} due to {result.value}")
        
    def password_spraying(self):
        with open("PS_passwords.txt", "r") as file:
            lines = file.readlines()
        passwords = [line.strip() for line in lines]
        hacked_users = list()
        for password in passwords:
            for username in self.unauthorized_user.list_of_usernames:
                if username in hacked_users:
                    continue
                logging.info(f"-> LOGIN_ATTEMPT user={username}")
                start = time.perf_counter()
                result = self.server.login(username, password)
                latency_ms = (time.perf_counter() - start) * 1000
                self.metrics.record_attempt(username, self.server.protections, result.value, latency_ms)
                if result == LoginResult.OK:
                    hacked_users.append(username)
                    logging.info(f"[OK] LOGIN_SUCCESS user={username}")
                    continue
                logging.warning(f"[FAIL] LOGIN_FAIL user={username} due to {result.value}")
        if len(hacked_users) > 0:
            logging.info(f"login succeeded for unauthorized user via Password Spraying for {len(hacked_users)} users over {len(self.unauthorized_user.list_of_usernames)}")
        else:
            logging.info(f"login failed for unauthorized user via Password Spraying for all {len(self.unauthorized_user.list_of_usernames)} users")

    def add_stats(self):
        a.metrics.save_to_csv("attempts.csv")
        with open("attempts.log", "a") as f:
            stats = a.metrics.get_stats()
            f.write(stats)
            print(stats)

# a = Attempt()
# a = Attempt(TOTP=True)
# a = Attempt(RL=True)
# a = Attempt(lockout=True)
# a = Attempt(captcha=True)
# a = Attempt(sha256_salt=True)
# a = Attempt(bcrypt_hash=True)
# a = Attempt(argon2_hash=True)

# Mix:
# a = Attempt(argon2_hash=True, pepper=True) # doesn't show anything interesting
# a = Attempt(bcrypt_hash=True, RL=True)
# a = Attempt(sha256_salt=True, pepper=True)
a = Attempt(argon2_hash=True, lockout=True)

# a.password_spraying()

a.brute_force("taylor") # easy password with lockout fails after 10 passwords with TOTP
# a.brute_force("max") # Medium password
# a.brute_force("daniel") # Strong password

a.add_stats()
