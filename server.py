import json
import pyotp

class Server:
    def __init__(self):
        with open("users.json") as f:
            self.DB = json.load(f)
    
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
        for user_name in self.DB:
            self.DB[user_name] = {
                "password": self.DB[user_name]["password"],
                "totp_secret" : None,
                "totp_enabled": False}
    
    def get_username(self):
        user_name = input("Please enter your username. ")
        if user_name not in self.DB:
            raise Exception("Username not found. Please try again or register first.")
        return user_name
    
    def get_password(self):
        return input("Please enter your password. ")
    
    def login(self, username, password):
        while password != self.DB[username]["password"]:
            print("Password is incorrect. Try again. ")
            password = self.get_password()
        print("You're in. Welcome back!\n")

    def login_totp(self):
        totp = pyotp.random_base32()

    
    def save(self):
        with open("users.json", "w") as f:
            json.dump(self.DB, f, indent=2)


S = Server()
print("Welcome to the server.")
while (True):
    
    print("Please choose an action:")
    print("1. register")
    print("2. login")
    print("3. login with totp")
    print("4. exit")

    user_input = input()
    try:
        action = int(user_input)
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        continue

    try:
        match action:
            case 1:
                S.register()
            case 2:
                username = S.get_username()
                S.login()
            case 3:
                pass
            case 4:
                print("")
                break
            case _:  # Default case (wildcard)
                print("ERROR: Unknown action, please try again")
    
    except Exception as e:
        print("ERROR: ", e)


S.save()
