import hashlib
import requests
import sys

def request_api_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching request from api! Status code: {res.status_code}. Check API!')
    return res

def password_leaks_count(hashes,hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode()).hexdigest().upper()
    first5, last = sha1password[:5], sha1password[5:]
    response = request_api_data(first5)
    return password_leaks_count(response,last)

def main(args):
    for password in args:
        count = pwned_api_check(password)

        if count:
            print(f'The password {password} has been seen {count} times!')
        else:
            print(f'The password {password} has not been used!')
    return 'Done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))



