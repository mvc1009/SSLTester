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
				
					# checking vulnerabilities
					if 'RC4' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							rc4_list.append(url)

					elif 'LUCKY13' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							lucky13_list.append(url)

					elif 'winshock' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							winshock_list.append(url)
					elif 'BEAST' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							beast_list.append(url)														

					elif 'LOGJAM' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							logjam_list.append(url)		

					elif 'DROWN' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							drown_list.append(url)		

					elif 'FREAK' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							freak_list.append(url)		

					elif 'SWEET32' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							sweet32_list.append(url)		


					elif 'POODLE_SSL' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							poodle_list.append(url)		

					elif 'BREACH' == i['id']:
						if i['finding'] and "not vulnerable" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							breach_list.append(url)		

					# checking vulnerable protocols
					elif 'SSLv2' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							breach_list.append(url)	


					elif 'SSLv3' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							breach_list.append(url)	


					elif 'TLS1' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							breach_list.append(url)	


					elif 'TLS1_1' == i['id']:
						if i['finding'] and "not offered" not in i['finding']:
							url = i['ip'] + ':' + i['port']
							breach_list.append(url)	
						


def print_summary():
	print("[!] Printing VULNERABILITIES and the affected hosts\n")
	
	print("[+] RC4")
	for i in rc4_list:
		print(i)
	print("\n")

	print("[+] LUCKY13")
	for i in lucky13_list:
		print(i)
	print("\n")

	print("[+] WINSHOCK")
	for i in winshock_list:
		print(i)
	print("\n")

	print("[+] BEAST")
	for i in beast_list:
		print(i)
	print("\n")

	print("[+] LOGJAM")
	for i in logjam_list:
		print(i)
	print("\n")

	print("[+] DROWN")
	for i in drown_list:
		print(i)
	print("\n")

	print("[+] FREAK")
	for i in freak_list:
		print(i)
	print("\n")

	print("[+] SWEET32")
	for i in sweet32_list:
		print(i)
	print("\n")

	print("[+] POODLE")
	for i in poodle_list:
		print(i)
	print("\n")

	print("[+] BREACH")
	for i in breach_list:
		print(i)
	print("\n")

	print("[!] Printing VULNERABLE PROTOCOLS and the affected hosts\n")

	print("[+] SSLv2")
	for i in ssl2_list:
		print(i)
	print("\n")

	print("[+] SSLv3")
	for i in ssl3_list:
		print(i)
	print("\n")

	print("[+] TLS 1")
	for i in tls1_list:
		print(i)
	print("\n")

	print("[+] TLS 1.1")
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
