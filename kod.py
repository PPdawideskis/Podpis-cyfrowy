import base64
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import hashlib
import os, sys

def toBase64(string):
    return base64.b64encode(string)
def generate_keys():
    modulus_length = 256*4
    private_key = RSA.generate(modulus_length, Random.new().read)
    public_key = private_key.publickey()
    return private_key, public_key

pri, pub = generate_keys()

path = "C:/Users/dawid/Desktop/kodowanie"
dirs = os.listdir(path)

for file in dirs:
    print(file)
    
download_file = input("Jaki plik chcesz zaszyfrować? ")

open_file = open(download_file, "rb")

read_file = open_file.read()
#print(read_file)

hash = SHA256.new()
hash.update(read_file)
signature = pss.new(pri).sign(hash)

fsave=open("signedMessage.txt", "wb")
fsave.write(signature)
fsave.close()

path = "C:/Users/dawid/Desktop/kodowanie"
dirs = os.listdir(path)

for file in dirs:
    print(file)

download_file_verify = input("Jaki plik chcesz sprawdzic? ")
download_file_sign = input("Wybierz podpisany plik ")

file_verify = open(download_file_verify, "rb")
file_verify_open = file_verify.read()

hash2 = SHA256.new()
hash2.update(file_verify_open)
verifier = pss.new(pub)
file_sign = open(download_file_sign, "rb")
file_sign_open = file_sign.read()

try:
    verifier.verify(hash2, file_sign_open)
    print("Podpis sie zgadza!")
except(ValueError, TypeError):
    print("Podpis sie nie zgadza, zly plik!")