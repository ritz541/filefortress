import scrypt, os, shutil
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import session
from werkzeug.utils import secure_filename
from flask import current_app as app

def get_db():
    # Get the MongoDB URI from the environment variable
    mongo_uri = os.getenv('MONGO_URI')
    
    if mongo_uri:
        # Connect to the MongoDB cluster
        client = MongoClient(mongo_uri)
        
    else:
        client = MongoClient('mongodb://localhost:27017')

    # Select the database
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

    # Decrypt the data
    try:
        decrypted_data = cipher.decrypt(ciphertext_data)
        # Try unpadding the data
        decrypted_data = unpad(decrypted_data, AES.block_size)
    except ValueError:
        # If unpadding fails, just return the raw decrypted data
        return cipher.decrypt(ciphertext_data)
    return decrypted_data

def get_file_path(filename):
    
    safe_filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    return filepath

def get_file_size(filename):
    def format_size(size):
        # List of size units
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        
        # If the size is 0, return '0 B'
        if size == 0:
            return '0 B'
        
        # Calculate the appropriate unit
        unit_index = 0
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024.0
            unit_index += 1
        
        # Format the size with one decimal place
        return f"{size:.1f} {units[unit_index]}"

    filepath = get_file_path(filename)
    try:
        file_size = os.path.getsize(filepath)
        return format_size(file_size)
    except FileNotFoundError:
        return None