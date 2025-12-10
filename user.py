import pyotp

class Authorized_user:
    def __init__(self, username : str, password : str, totp_secret : str, enable_totp : bool):
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.totp_enabled = enable_totp
    
    def get_totp(self):
        if not self.totp_enabled or not self.totp_secret:
            return None
        return pyotp.TOTP(self.totp_secret)


class Unauthorized_user:
    def __init__(self, username : str):
        self.username = username
    
    def brute_force(self):
        pass

    def password_spraying(self):
        pass
