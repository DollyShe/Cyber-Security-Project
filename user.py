import pyotp

class Authorized_user:
    def __init__(self, username : str, password : str, totp_secret : str, enable_totp : bool):
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.totp_enabled = enable_totp
    
    def get_totp_code(self):
        if not self.totp_enabled or not self.totp_secret:
            return None
        totp = pyotp.TOTP(self.totp_secret)
        return totp.now()


class Unauthorized_user:
    def __init__(self, usernames : list):
        self.list_of_usernames = usernames
