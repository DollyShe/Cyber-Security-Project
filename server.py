import json

class Server:
    def __init__(self):
        with open("users.json") as f:
            users = json.load(f)
        self.DB = {u["username"]: u for u in users}
    
    def register(self):
        user_name = input("Please choose a username. You'll use this to sign in. ")
        while user_name in self.DB.keys():
            user_name = input("That username is already taken. Please choose another. ")
        password = input("Please choose a password: ")
        self.DB[user_name] = {
        "user_name": user_name,
        "password": password}
        print("Account created successfully!")

    def login(self):
        user_name = input("Please enter your username. ")
        if user_name not in self.DB:
            print("Username not found. Please try again or register first.")
            return
        password = input("Please enter your password. ")
        while password != self.DB[user_name]["password"]:
            print("Password is incorrect. Try again. ")
            password = input("Please enter your password. ")
        print("You're in. Welcome back!\n")

    def login_totp(self):
        pass
    
    def save(self):
        with open("users.json", "w") as f:
            json.dump(self.DB, f, indent=2)


S = Server()
print("Welcome to the server.")
while (True):
    
    print("Please choose an action:")
    print("1. register")
    print("2. login")
    print("3. login")
    print("4. exit")

    user_input = input()
    try:
        action = int(user_input)
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        continue

    match action:
        case 1:
            S.register()
        case 2:
            S.login()
        case 3:
            pass
        case 4:
            print("")
            break
        case _:  # Default case (wildcard)
            print("Unknown action, please try again")

S.save()
