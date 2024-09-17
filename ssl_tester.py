#!/bin/python3
import sys,os

try:
	import json
except:
	print('[!] json is not installed. Try "pip install json"')
	sys.exit(0)


try:
	import argparse
except:
	print('[!] argparse is not installed. Try "pip install argparse"')
	sys.exit(0)

# Common Vulns
rc4_list = []
lucky13_list = []
winshock_list = []
beast_list = []
logjam_list = []
drown_list = []
freak_list = []
sweet32_list = []
poodle_list = []
breach_list = []

# Protocols
tls1_list = []
tls1_1_list = []
ssl2_list = []
ssl3_list = []

def test_ssl(filename):
	with open(filename, 'r') as f:
		data = f.read().split()
		for url in data:
			os.system("testssl --quiet --json %s" % url)

def parse_results():
	files = os.listdir()
	for file in files:
		if '.json' in file:
			with open(file, 'r') as jsonfile:
				data = json.load(jsonfile)
				url = ""
				for i in data:
					if 'service' in i['id']:
						url = i['ip'] + ':' + i['port']
						#print("• %s\n" % url)
					
					# checking vulnerabilities
					if 'RC4' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							rc4_list.add(url)

					if 'LUCKY13' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							lucky13_list.add(url)

					if 'winshock' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							winshock_list.add(url)
					if 'BEAST' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							beast_list.add(url)														

					if 'LOGJAM' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							logjam_list.add(url)		

					if 'DROWN' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							drown_list.add(url)		

					if 'FREAK' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							freak_list.add(url)		

					if 'SWEET32' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							sweet32_list.add(url)		


					if 'POODLE_SSL' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							poodle_list.add(url)		

					if 'BREACH' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							breach_list.add(url)		

					# checking vulnerable protocols
					if 'SSLv2' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							breach_list.add(url)	


					if 'SSLv3' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							breach_list.add(url)	


					if 'TLS1' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							breach_list.add(url)	


					if 'TLS1_1' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							breach_list.add(url)	
						


def print_summary():
	print("[!] Printing VULNERABILITIES and the affected hosts\n")
	
	print("[+] RC4\n")
	for i in rc4_list:
		print(i)
		print("\n")

	print("[+] LUCKY13\n")
	for i in lucky13_list:
		print(i)
		print("\n")

	print("[+] WINSHOCK\n")
	for i in winshock_list:
		print(i)
		print("\n")

	print("[+] BEAST\n")
	for i in beast_list:
		print(i)
		print("\n")

	print("[+] LOGJAM\n")
	for i in logjam_list:
		print(i)
		print("\n")

	print("[+] DROWN\n")
	for i in drown_list:
		print(i)
		print("\n")

	print("[+] FREAK\n")
	for i in freak_list:
		print(i)
		print("\n")

	print("[+] SWEET32\n")
	for i in sweet32_list:
		print(i)
		print("\n")

	print("[+] POODLE\n")
	for i in poodle_list:
		print(i)
		print("\n")

	print("[+] BREACH\n")
	for i in breach_list:
		print(i)
		print("\n")


	print("[!] Printing VULNERABLE PROTOCOLS and the affected hosts\n")

	print("[+] SSLv2\n")
	for i in ssl2_list:
		print(i)
		print("\n")

	print("[+] SSLv3\n")
	for i in ssl3_list:
		print(i)
		print("\n")

	print("[+] TLS 1\n")
	for i in tls1_list:
		print(i)
		print("\n")

	print("[+] TLS 1.1\n")
	for i in tls1_1_list:
		print(i)
		print("\n")

def main():
	# Parsing arguments
	parser = argparse.ArgumentParser(description='SSL_Tester is used to check SSL protocols and chipers.\n\n', epilog='Thanks for using me!')
	parser.add_argument('-f', '--file', action='store', dest='file', help='File of URLs to test')
	parser.add_argument('--only-parse', action="store_true", dest='parse', help='Only parse previous results')
	global args
	args =  parser.parse_args()

	#Usage
	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(0)

	if args.file:
		if not args.parse:
			test_ssl(args.file)
		parse_results()
		print_summary()
	else:
		parser.print_help()
		sys.exit()

try:
	if __name__ == "__main__":
		main()
except KeyboardInterrupt:
	print("[!] Keyboard Interrupt. Shutting down")
