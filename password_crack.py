import hashlib
import os
import string
from itertools import permutations
from first_names import fnames2
from passlib.hash import htdigest, sha512_crypt
from passlib.hash import pbkdf2_sha256, md5_crypt

shadow_file = open('/Users/mac/Downloads/cys_test/shadow.txt')
hash_to_password = {}
visited_groups = {}


# Creating a list from username, salt and password
def extract_info():
    f = open('/Users/mac/Downloads/cys_test/shadow.txt', "r")
    lines = f.read().split()
    f.close()

    # extract username, salts, hashes into lists
    usernames = []
    salts = []
    hashes = []

    for line in lines:
        if "$6" in line:
            # clean out the entries into expected part
            sections = line.split("$")
            # clean out the entries into expected part
            usernames.append(sections[0].split(":")[0])
            # clean out the entries into expected part
            salts.append(sections[2])
            # clean out the entries into expected part
            hashes.append(sections[3].split(":")[0])
    return usernames, salts, hashes


def read_shadow_file():
    user_password_map = {}
    for line in shadow_file:
        fields = line.strip().split(':')
        # print(fields)
        password_info = fields[1].strip().split('$')

        if len(fields) >= 2:
            username = fields[0]
            hashed_password = fields[1]
            user_password_map[username] = password_info[3]

    return user_password_map


class PasswordCracker:
    def __init__(self, first_names, days, months, special_characters):
        self.first_names = first_names
        self.days = days
        self.months = months
        self.special_characters = special_characters

    # Fastest function for possible combinations
    def possible_combinations(self):
        all_combinations = []

        for fname in self.first_names:
            for month in self.months:
                for day in self.days:
                    for special_character in list(self.special_characters):
                        password = [fname, month, day, special_character]
                        all_combinations.append(password)

        return all_combinations

   
    def generate_permutations(self, n, elements, result):
        if n == 1:
            result.append(elements.copy())
        else:
            for i in range(n - 1):
                self.generate_permutations(n - 1, elements, result)
                if n % 2 == 0:
                    elements[i], elements[n - 1] = elements[n - 1], elements[i]
                else:
                    elements[0], elements[n - 1] = elements[n - 1], elements[0]
            self.generate_permutations(n - 1, elements, result)

    def your_password(self, no, username, salt, password_hash):
        if (password_hash in hash_to_password) or (no in visited_groups):
            
            return
        else:
            combinations = self.possible_combinations()
            for combination in combinations:
                permutations_list = []
                self.generate_permutations(
                    len(combination), combination, permutations_list)
                possible_passwords = [''.join(map(str, e))
                                      for e in permutations_list]

                for password in possible_passwords:
                   

                    result = sha512_crypt.using(rounds=5000, salt=str(
                        salt)).hash(str(password)).split("$")[-1]
                    result_lower = \
                        sha512_crypt.using(rounds=5000, salt=str(salt)).hash(
                            str(password).lower()).split("$")[-1]

                    if result == password_hash:
                        hash_to_password[password_hash] = password
                        visited_groups[no] = True
                        print(
                            "===========================================================")
                        print(
                            f"Group {no}: My guess for {username} password is {password}")
                        print(
                            "===========================================================")
                        return
                  

                    if result_lower == password_hash:
                        hash_to_password[password_hash] = password
                        visited_groups[no] = True
                        print(
                            "====================================================================")
                        print(
                            f"Group {no}: My guess for {username} password is {password.lower()}")
                        print(
                            "====================================================================")
                        return


# special_characters = "!@#$%^&*()-=_+[]{}|;:'\",.<>?/£§"
special_characters = string.punctuation
days = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18",
        "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31"]
months = ["01", "02", "03", "04", "05",
          "06", "07", "08", "09", "10", "11", "12"]


username_to_pass = read_shadow_file()
(usernames, salts, hashes) = extract_info()

for i in range(len(hashes)):
    for group_no, names in fnames2.items():
        password_cracker = PasswordCracker(
            first_names=names,
            days=days,
            months=months,
            special_characters=special_characters
        )
        print(
            f"In Group {group_no} - {names}: Finding a password of {usernames[i]}")
        print(f"With salt {salts[i]} to similar hash of: {hashes[i]}...")
        password_cracker.your_password(
            group_no, usernames[i], salts[i], hashes[i])
# my_hash = sha512_crypt.using(rounds=5000, salt="UkVWmimFfBcmgeuh").hash("25marvellous@09").split("$")[-1]
# print(my_hash)
