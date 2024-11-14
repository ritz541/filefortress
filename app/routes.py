from flask import render_template, redirect, request, url_for, flash, send_file
import config
from app import app
import scrypt, os
from werkzeug.utils import secure_filename
from app.functions import get_db, encrypt_file, decrypt_file


db = get_db()
users_collection = db['users']


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        salt = os.urandom(16)
        
        hashed_password = scrypt.hash(password, salt)
        
        users_collection.insert_one({
            "username": username,
            "password": hashed_password,
            "salt": salt
        })
        
        
        print("User registered with username:", username)
        
        return redirect(url_for('register'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Retrieve the user document from the database
        user = users_collection.find_one({"username": username})

        if user:
            # Retrieve the stored hash and salt from the database
            stored_hash = user['password']
            stored_salt = user['salt']

            # Hash the entered password with the stored salt
            entered_hash = scrypt.hash(password, stored_salt)

            # Compare the hashed entered password with the stored hash
            if entered_hash == stored_hash:
                print("Login successful!")
                return redirect(url_for('dashboard'))  # Redirect to the dashboard or homepage
            else:
                print("Invalid password!")
                flash("Invalid password", "error")
        else:
            print("User not found!")
            flash("User not found", "error")

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')  # Placeholder for your dashboard page



@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['file']
        password = request.form.get('password')

        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file and password:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Encrypt the file
            encrypted_data = encrypt_file(filepath, password)

            # Save or replace the file with encrypted content
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)

            flash('File uploaded and encrypted successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('upload.html')



@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['file']
        password = request.form.get('password')

        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file and password:
            # Save the uploaded file temporarily
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(filepath)

            try:
                # Decrypt the file
                decrypted_data = decrypt_file(filepath, password)

                # Save the decrypted content to a new file
                decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + file.filename)
                with open(decrypted_filepath, 'wb') as f:
                    f.write(decrypted_data)

                flash('File decrypted successfully!', 'success')
                return send_file(decrypted_filepath, as_attachment=True)

            except ValueError as e:
                flash('Incorrect password or decryption failed.', 'error')
                return redirect(request.url)

    return render_template('decrypt.html')
