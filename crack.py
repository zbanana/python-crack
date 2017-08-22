import sys
from crypt import crypt

def main():
	# Make sure argument count is 2
	if not len(sys.argv) == 2:
		print("Usage: python3 crack.py hash")
		exit(1)

	hash = sys.argv[1]
	print(crack(hash))
	exit(0)

def crack(hash):
	salt = hash[:2]
	print("salt is {}".format(salt))
	alphabet = list(range(65, 65 + 26)) + list(range(97, 123))
	
	# we know password is at most 4 characters long
	for n in range(4):
		print("Checking passwords with {} characters".format(n + 1))
		pwd = ""
		for i in alphabet:
			pwd = chr(i)
			if n == 0:
				# print("Checking {}".format(pwd))
				if crypt(pwd, salt) == hash:
					return pwd
				else:
					continue
			for j in alphabet:
				pwd = chr(i) + chr(j)
				if n == 1:
					# print("Checking {}".format(pwd))
					if crypt(pwd, salt) == hash:
						return pwd
					else:
						continue	
				for k in alphabet:
					pwd = chr(i) + chr(j) + chr(k)
					if n == 2:
						# print("Checking {}".format(pwd))
						if crypt(pwd, salt) == hash:
							return pwd
						else:
							continue	
					for l in alphabet:
						pwd = chr(i) + chr(j) + chr(k) + chr(l)
						if n == 3:
							print("Checking {}".format(pwd))
							if crypt(pwd, salt) == hash:
								return pwd
	return "Couldn't crack the password!"

if __name__ == "__main__":
	main()