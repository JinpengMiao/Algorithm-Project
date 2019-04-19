#!/usr/bin/python

import Crypto.Cipher as Cipher
import Crypto.Signature as Sign
import Crypto.Hash as Hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_cipper
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sign
from Crypto.Hash import SHA1

class Rsa:

	# encryption and decryption signature
	def __int__(self, cipher_lib = PKCS1_v1_5_cipper, sign_lib = PKCS1_v1_5_sign, hash_lib = SHA1, pub_file = None, pri_file = None, pub_skey = None, pri_skey = None, pub_key = None, pri_key = None, reversed_size = 11):
		
		#encryp and decryp lib
		self.cipher_lib = cipher_lib
		self.sign_lib = sign_lib
		self.hash_lib = hash_lib

		#public key and private key
		if pub_key:
			self.pub_key = pub_key
		elif pub_skey:
			self.pub_key = RSA.importKey(pub_skey)
		elif pub_file:
			self.pub_key = RSA.importKey(open(pub_file).read())

		if pri_key:
			self.pri_key = pri_key
		elif pri_skey:
			self.pri_key = RSA.importKey(pri_skey)
		elif pri_file:
			self.pri_key = RSA.importKey(open(pri_file).read())

		#block and reserve size
		self.block_reversed_size = reversed_size

	#calculate the block sizxe based on key length
	def get_block_size(self, rsa_key):
		try:
			# RSA only work for limited-size operation
			reserve_size = self.block_reversed_size
			key_size = rsa_key.size_in_bits()
			if (key_size % 8) != 0:
				raise RuntimeError('RSA key length error')

			# private key to decrypt
			if rsa_key.has_private():
				reserve_size = 0

			bs = int(key_size / 8) - reserve_size
		except Exception as err:
			print('calculation of block size error', rsa_key, err)
		return bs

	def block_data(self, data, rsa_key):
		bs = self.get_block_size(rsa_key)
		for i in range(0, len(data), bs):
			yield data[i:i + bs]

#encrypt
def enc_bytes(self, data, key=None):
	text = b''
	try: 
		rsa_key = self.pri_key
		if key:
			rsa_key = key

		cipher = self.cipher_lib.new(rsa_key)
		for dat in self.block_data(data, rsa_key):
			if type(self.cipher_lib) == Cipher.PKCS1_OAEP:
				cur_text = cipher.decrypt(dat)
			else:
				cur_text = cipher.decrypt(dat, 'decryption error')
			text += cur_text
	except Exception as err:
		print('RSA decryption failed', data, err)
	return text

#RSA signature
def sign_bytes(self, data, key=None):
	signature = ''
	try:
		rsa_key = self.pri_key
		if key:
			rsa_key = key

		h = self.hash_lib.new(data)
		signature = self.sign_lib.new(rsa_key).sign(h)
	except Exception as err:
		print('RSA signature failed', '', err)
	return signature

#RSA signature examine
def sign_verify(self, data, sig, key=None):
	try:
		rsa_key = self.pub_key
		if key:
			rsa_key = key
		h = self.hash_lib.new(data)
		self.sign_lib.new(rsa_key).verify(h, sig)
		ret = True
	except (ValueError, TypeError):
		ret = False
	return ret

def main():
	pass

if __name__ == '__main__':
	main()








