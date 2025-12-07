import pyotp

class Authorized_user:
    def __init__(self, username : str, password : str, enable_totp : bool):
        self.username = username
        self.password = password
        self.totp_enabled = enable_totp
        if enable_totp:
            self.totp = pyotp.random_base32()
        self.totp = None
    
    def add_totp(self):
        self.totp = None


class Unauthorized_user:
    def __init__(self, username : str):
        self.username = username
    
    def brute_force(self):
        pass

    def password_spraying(self):
        pass