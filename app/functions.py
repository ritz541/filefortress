import os, scrypt
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

def get_db():
    client = MongoClient('mongodb+srv://apple:Iwanttosuckherboobs@cluster0.arozz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
    db = client['encryption_db']
    return db


def encrypt_file(filepath, password):
    # Generate a salt and derive a key from the password
    salt = os.urandom(16)
    key = scrypt.hash(password, salt, N=16384, r=8, p=1, buflen=32)

    # Initialize AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    # Read and encrypt the file data
    with open(filepath, 'rb') as f:
        plaintext_data = f.read()
    ciphertext_data = iv + salt + cipher.encrypt(pad(plaintext_data, AES.block_size))

    return ciphertext_data



def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        # Read the IV and salt from the file
        iv = f.read(16)
        salt = f.read(16)
        ciphertext_data = f.read()

    # Derive the key from the password and salt
    key = scrypt.hash(password, salt, N=16384, r=8, p=1, buflen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad the data
    decrypted_data = unpad(cipher.decrypt(ciphertext_data), AES.block_size)
    return decrypted_data
