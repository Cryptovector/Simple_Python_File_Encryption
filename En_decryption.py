import os, sys, argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
backend = default_backend()


def Gen_Scrypt_Instance(salt):
	kdf = Scrypt(
		salt=salt,
		length=32,
		n=2**17, #2**14
		r=8,
		p=1,
		backend=backend
	)
	return kdf

def Generate_Key_Scrypt(Key): #Standart Zeros wird dann aufgefüllt mit weiteren Zeros um entschleusselbar zu sein
	salt = os.urandom(16)
	kdf = Gen_Scrypt_Instance(salt)
	Der_Key = kdf.derive(Key)
	Der_Key_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
	Der_Key_Hash.update(Der_Key)
	print("----Key derivation on Encryption Complete----")
	return (salt + Der_Key_Hash.finalize()), Der_Key 

def Decrypt_Key_Scrypt(salt, Hash, Key): #Standart Zeros | Key unvollstaendig | 2 ** Rounds  
	kdf = Gen_Scrypt_Instance(salt)
	Der_Key = kdf.derive(Key)
	Der_Key_Hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
	Der_Key_Hash.update(Der_Key)
	if constant_time.bytes_eq(Hash, Der_Key_Hash.finalize()):
		print("----Key derivation on Decryption Complete----")
		return Der_Key
	else:
		return 0	

def encrypt_file(key, in_filename, out_filename=None): #, chunksize=64*1024
	
	if not out_filename:
		out_filename = in_filename + '.enc'

	Data, Enc_Key = Generate_Key_Scrypt(key)
	in_file = open(in_filename, "rb") 
	File_Data = in_file.read()
	in_file.close()	

	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(Enc_Key), modes.CBC(iv), backend=backend)
	HMAC = hmac.HMAC(Enc_Key, hashes.SHA256(), backend=default_backend())
	encryptor = cipher.encryptor()

	Paddinglength = (15 - (len(File_Data) % 16)) #(16 - len(File_Data) % 16)
	File_Data += bytearray(Paddinglength) + bytes([Paddinglength])
	HMAC.update(iv)
	HMAC.update(File_Data)
	AC = HMAC.finalize()
	encrypt_file = encryptor.update(File_Data) + encryptor.finalize()

	with open(out_filename, 'wb') as outfile:
	 	outfile.write(Data + AC + iv + encrypt_file)

	print("---Encryption Complete---")  	



def decrypt_file(key, in_filename, out_filename=None): #, chunksize=24*1024

	if not out_filename:
		out_filename = os.path.splitext(in_filename)[0]

	in_file = open(in_filename, "rb") 
	File_Data = in_file.read()
	in_file.close()

	Data = File_Data[0:48]
	AC = File_Data[48:80]
	iv = File_Data[80:96]
	encrypt_file = File_Data[96:]
	
	Der_Key = Decrypt_Key_Scrypt(Data[:-32], Data[-32:], key)
	if not Der_Key:
		print("Key derivation has failed")
		return 0

	cipher = Cipher(algorithms.AES(Der_Key), modes.CBC(iv), backend=backend)
	HMAC = hmac.HMAC(Der_Key, hashes.SHA256(), backend=default_backend())
	decryptor = cipher.decryptor()

	decrypt_file = decryptor.update(encrypt_file) + decryptor.finalize()
	HMAC.update(iv)
	HMAC.update(decrypt_file)
	HMAC.verify(AC)

	with open(out_filename, 'wb') as outfile:
		outfile.write(decrypt_file[0:(0-(decrypt_file[-1]+1))])#len(decrypt_file)-(Paddinglength+1)

	print("---Decryption Complete---") 	


if __name__ == "__main__":

	parser = argparse.ArgumentParser(description='File En or Decryption')
	parser.add_argument('-e','--encrypt', action='store_false')
	parser.add_argument('-d','--decrypt', action='store_false')
	parser.add_argument('-k', '--key',
			action="store", dest="key",
			help="Key string for File En or Decryption", default="")
	parser.add_argument('-f', '--file',
			action="store", dest="filepath",
			help="File to De and Encrypt", default="", required=True)
	parser.add_argument('-o', '--outfile',
			action="store", dest="outfilepath",
			help="File to write Processed Data", default="")

	args = parser.parse_args()

	if (args.decrypt ^ args.encrypt):

		Outfile = None
		if not args.outfilepath == "":
			Outfile = args.outfilepath

		key	= bytes(args.key, 'utf-8')

		if not args.encrypt:
			encrypt_file(key, args.filepath, Outfile)
		if not args.decrypt:	
			decrypt_file(key, args.filepath, Outfile)
	else:
		print("Usage: use -d or -e")