import hashlib
import requests
import sys

def request_api_data(query_char):
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url)

  if (res.status_code != 200):
    raise RuntimeError(f"Error fetching")
  return res

def get_password_leaks(hashes, hash_to_check):
  # hashes.text => full text
  # for line in hashes.text -> character
  hashes = (line.split(':') for line in hashes.text.splitlines())

  for h, count in hashes:
    if h == hash_to_check:
      return count
  return 0     

def pwned_api_check(password):
  sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1_password[:5], sha1_password[5:]
  response = request_api_data(first5_char)
  return get_password_leaks(response, tail)

def main(args):
  for arg in args:
    result = pwned_api_check(arg)
    if (result):
      print(f"{arg} has been seen {result} times before.")
    else:
      print(f'{arg} is a safety password')  

if __name__ == '__main__':
  main(sys.argv[1:])
