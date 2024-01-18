import hashlib
import os
from itertools import permutations
from first_names import fnames, fnames2
from passlib.hash import htdigest
from passlib.hash import pbkdf2_sha256, md5_crypt

shadow_file = open('/Users/mac/Downloads/cys_test/shadow.txt')
hash_to_password = {}
visited_groups = {}


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


def identify_hash_algorithm(hash_string):
    hash_length = len(hash_string)

    # Check hash length to narrow down possibilities
    if hash_length == 32:
        return "MD5"
    elif hash_length == 40:
        return "SHA-1"
    elif hash_length == 64:
        return "SHA-256"
    elif hash_length == 128:
        return "SHA-512"

    # Check for common prefixes or signatures
    if hash_string.startswith("$pbkdf2-sha256$"):
        return "PBKDF2-SHA256"

    # Add more checks as needed for other algorithms

    # If no match is found
    return "Unknown Algorithm"


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

    # Fastest for generating permutations
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

    def your_password(self, no, username, password_hash):
        if (password_hash in hash_to_password) or (no in visited_groups):
            # print(f"{hash_to_password[password_hash]} is the reveal of {password_hash}")
            return
        else:
            combinations = self.possible_combinations()
            for combination in combinations:
                permutations_list = []
                self.generate_permutations(len(combination), combination, permutations_list)
                possible_passwords = [''.join(map(str, e)) for e in permutations_list]

                for password in possible_passwords:
                    bytes_ = password.encode('utf-8')
                    bytes_lower = password.lower().encode('utf-8')
                    bytes_upper = password.upper().encode('utf-8')

                    hash_algo = identify_hash_algorithm(password_hash)

                    # MD5 hashing
                    if hash_algo == "MD5":
                        result = hashlib.md5(bytes_).hexdigest()
                        result_lower = hashlib.md5(bytes_lower).hexdigest()
                        result_upper = hashlib.md5(bytes_upper).hexdigest()

                    # SHA-1 hashing
                    elif hash_algo == "SHA-1":
                        result = hashlib.sha1(bytes_).hexdigest()
                        result_lower = hashlib.sha1(bytes_lower).hexdigest()
                        result_upper = hashlib.sha1(bytes_upper).hexdigest()

                    # SHA-256 hashing
                    elif hash_algo == "SHA-256":
                        result = hashlib.sha256(bytes_).hexdigest()
                        result_lower = hashlib.sha256(bytes_lower).hexdigest()
                        result_upper = hashlib.sha256(bytes_upper).hexdigest()

                    # SHA-384 hashing
                    # result = hashlib.sha384(bytes_).hexdigest()
                    # result_lower = hashlib.sha384(bytes_lower).hexdigest()

                    # SHA-512 hashing
                    else:
                        result = hashlib.sha512(bytes_).hexdigest()
                        result_lower = hashlib.sha512(bytes_lower).hexdigest()
                        result_upper = hashlib.sha512(bytes_upper).hexdigest()

                    if result == password_hash:
                        hash_to_password[password_hash] = password
                        visited_groups[no] = True
                        print(f"{no}: My guess for {username} password is {password}")
                        return

                    if result_lower == password_hash:
                        hash_to_password[password_hash] = password
                        visited_groups[no] = True
                        print(f"{no}: My guess for {username} password is {password.lower()}")
                        return

                    if result_upper == password_hash:
                        hash_to_password[password_hash] = password
                        visited_groups[no] = True
                        print(f"{no}: My guess for {username} password is {password.lower()}")
                        return


# Example Usage
special_characters = "!@#$%^&*()-=_+[]{}|;:'\",.<>?/£§"
months = list(range(1, 13))
days = list(range(1, 32))
my_password = "10@Mofi13"

password_cracker = PasswordCracker(
    first_names=fnames[1],  # Replace with actual first names
    days=days,
    months=months,
    special_characters=special_characters
)

bytes_ = my_password.encode('utf-8')
sha512_result = hashlib.sha512(bytes_).hexdigest()

# .............................................................
# dummy_hash = "163d6dc7e05504f091c7dec094c18893"
# hash_algo = identify_hash_algorithm(dummy_hash)

# print(f"The identified algorithm is: {algorithm}")
# print(f"The hash algorithm used ==> {hash_algo}")
# .............................................................


username_to_pass = read_shadow_file()

for username, hashed_password in username_to_pass.items():
    for group_no, names in fnames2.items():
        password_cracker = PasswordCracker(
            first_names=names,
            days=days,
            months=months,
            special_characters=special_characters
        )
        print(f"In Group {group_no}: Finding a password to similar hash of: {hashed_password}...")
        password_cracker.your_password(group_no, username, hashed_password)
