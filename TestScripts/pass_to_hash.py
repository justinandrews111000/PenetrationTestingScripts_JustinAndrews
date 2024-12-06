import json
import hashlib


debug = False
passwords_file = r"WordLists\10-million-password-list-top-100000\10-million-password-list-top-100000"
password_and_hash_file = r"WordLists\10-million-password-list-top-100000\10-million-password-list-top-100000-and-hashes.txt"

pass_and_hash_dict = {}
with open(password_and_hash_file, "w") as pass_hash:

    with open(passwords_file, "r") as passwords:

        for password in passwords:
            password = password.strip(" ")
            password = password.strip("\n")
            pass_and_hash_dict[password] = hashlib.sha256(password.encode()).hexdigest()
            
            if debug:
                print(f"{password}:{pass_and_hash_dict[password]}")

        json.dump(pass_and_hash_dict, pass_hash)
