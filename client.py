import socket
import json
import rsa
from binascii import hexlify
import os
import threading
import sys
import math
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

n = None

def setkeys():
	prime1 = 7  # First prime number
	prime2 = 13  # Second prime number
	n = prime1 * prime2
	fi = (prime1 - 1) * (prime2 - 1)
	e = 2
	while True:
		if math.gcd(e, fi) == 1:
			break
		e += 1
	# d = (k*Φ(n) + 1) / e for some integer k

	d = 2
	while True:
		if (d * e) % fi == 1:
			break
		d += 1
	return e, d

def encrypt(message, public_key):
    global n
    e = public_key
    encrypted_text = 1
    while e > 0:
        encrypted_text *= message
        encrypted_text %= n
        e -= 1
    return encrypted_text
 
 
# To decrypt the given number
def decrypt(encrypted_text, private_key):
    global n
    d = private_key
    decrypted = 1
    while d > 0:
        decrypted *= encrypted_text
        decrypted %= n
        d -= 1
    return decrypted

def encoder(message, public_key):
	e = public_key
	encoded = []
    # Calling the encrypting function in encoding function

	for letter in message:
		encoded.append(encrypt(ord(letter)), public_key)
	return encoded
 
 
def decoder(encoded, private_key):
	d = private_key
	s = ''
    # Calling the decrypting function decoding function

	for num in encoded:
		s += chr(decrypt(num, d))
	return s

class Client:
	DISCONNECT_MESSAGE = "!DISCONNECT"
	HASH_METOD = "MD5"

	def __init__(self, ADDR, username):
		self.ADDR = ADDR
		self.username = username
		self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.active_users = {}
		self.generate_key()

	

	def generate_key(self):
		try:
			with open(f'{self.username}/priv.key', 'rb') as f:
				self.privkeybytes = f.read()
				privkeystr = self.privkeybytes.decode('utf-8')
				self.privkey = int(privkeystr)
		except IOError:
			os.makedirs(self.username, exist_ok=True)
			self.pubkey, self.privkey = setkeys()
			try:
				with open(f'{self.username}/pub.key', 'wb') as f:
					pubkeystr = str(self.pubkey)
					f.write(pubkeystr.encode('utf-8'))
				with open(f'{self.username}/priv.key', 'wb') as f:
					privkeystr = str(self.privkey)
					f.write(privkeystr.encode('utf-8'))
			except Exception as e:
				print(f"Error: {e}")
		finally:
			with open(f'{self.username}/pub.key', 'rb') as f:
				pub_file_contentbytes = f.read()
				pubfilestr = pub_file_contentbytes.decode('utf-8')
				pub_file_content = int(pubfilestr)
			self.pubkey = pub_file_content

	def disconnection(self):
		data = {"sender": self.username, "receiver": "disconnect", "msg": self.DISCONNECT_MESSAGE}
		self.client.send(json.dumps(data).encode())

	def send_broadcast(self, msg):
		for receiver in self.active_users:
			self.send(receiver, msg)

	def send(self, receiver, msg):
		try:
			pem_public_key = self.active_users[receiver]
			pubkey_recv = serialization.load_pem_public_key(str(pem_public_key).encode('utf-8'), backend=default_backend()) 
		except Exception as e:
			print(f"Error loading PEM-encoded public key: {e}")
		crypto = encoder(msg, pubkey_recv)
		print(crypto)
		data = {"sender": self.username, "receiver": receiver, "msg": crypto.hex()}
		self.client.send(json.dumps(data).encode())

	def update_users(self, users):
		del users[self.username]
		self.active_users = users

	def init_data(self):
		data = {"username": self.username, "pubkey": self.pubkey}
		self.client.send(json.dumps(data).encode())

	def listen(self):
		self.init_data()
		while True:
			data = self.client.recv(1024).decode()
			data = json.loads(data)
			if "users" in data.keys():
				self.update_users(data["users"])
			else:
				crypto = bytes.fromhex(data["msg"])
				msg = decoder(crypto, self.privkey)
				print(msg)
				print(f"\n[NEW MESSAGE VERIFIED] {data['sender']}: {msg} \nMessage: ", end="")

	def run(self):
		try: 
			print(f"[CONNECTION] Starting connection to {ADDR}")
			self.client.connect(self.ADDR)
			thread = threading.Thread(target=self.listen)
			thread.start()
			while True:
				msg = input("Message: ")
				if msg == self.DISCONNECT_MESSAGE:
					self.disconnection()
					break
				print(f"\n[ACTIVE USERS] {list(self.active_users.keys()) + ['broadcast']}")
				receiver = input("Receiver: ")
				if receiver not in list(self.active_users.keys()) + ["broadcast"]:
					print(f"not a valid username")
					continue
				if receiver == "broadcast":
					self.send_broadcast(msg.encode())
				else:
					self.send(receiver, msg.encode())
		except Exception as e:
			# print(e)
			pass


IP = socket.gethostbyname(socket.gethostname())
PORT = 8000
ADDR = (IP, PORT)

username = input("Insert username: ")
client = Client(ADDR, username)
client.run()
