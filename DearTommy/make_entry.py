# make_entry.py
import os, base64, hashlib, json

def make_hash(password, iterations=200_000):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode(), iterations

# Edit this dictionary with usernames and plaintext passwords you want to embed. FORMAT "USERNAME" : "PASSWORD"
users = {

}

creds = {}
for username, password in users.items():
    salt_b64, dk_b64, iters = make_hash(password)
    creds[username] = {"salt": salt_b64, "dk": dk_b64, "iterations": iters}

# Print the dictionary in Python literal form for easy copy/paste
print("Paste the following dictionary into your app as CREDENTIAL_STORE:\n")
print(json.dumps(creds, indent=4))