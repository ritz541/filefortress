from flask import render_template, redirect, request, url_for, flash, send_file, session, current_app
import config
from app import app
import scrypt, os, time
from werkzeug.utils import secure_filename, safe_join
from app.functions import get_db, encrypt_file, decrypt_file

db = get_db()
users_collection = db['users']
encrypted_files_collection = db['encrypted_files']
decrypted_files_collection = db['decrytped_files']

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    
    if 'username' in session:
        # flash("You are already logged in", 'warning')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        salt = os.urandom(16)
        hashed_password = scrypt.hash(password, salt)
        
        users_collection.insert_one({
            "email": email,
            "username": username,
            "password": hashed_password,
            "salt": salt
        })
        
        return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        # username = request.form.get('username')
        password = request.form.get('password')
        
        user = users_collection.find_one({"email": email})

        if user:
            stored_hash = user['password']
            stored_salt = user['salt']
            entered_hash = scrypt.hash(password, stored_salt)

            if entered_hash == stored_hash:
                username = user['username']
                session['logged_in'] = True
                session['username'] = username
                flash('You have successfully logged in! Redirecting in 3..2..1', 'success')
                return render_template('login.html', title='Login', delayed_redirect=url_for('dashboard'))
            else:
                flash("Invalid password", "error")
        else:
            flash("User not found", "error")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('You are not logged in', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        flash('You are not logged in', 'warning')
        return redirect(url_for('login'))
    
    user = users_collection.find_one({
        'username': session['username']
    })
    user_id = user['_id']
    
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

            encrypted_data = encrypt_file(filepath, password)

            with open(filepath, 'wb') as f:
                f.write(encrypted_data)

            flash('File uploaded and encrypted successfully!', 'success')
            
            
            #add file name into new table and associate it with user id from users collection with file id.
            
            encrypted_files_collection.insert_one({
                'file_name': filename,
                'user_id': user_id
            })
            
            return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = users_collection.find_one({
        'username': session['username']
    })
    user_id = user['_id']
    
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
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(filepath)

            try:
                decrypted_data = decrypt_file(filepath, password)

                decrypted_filename = 'decrypted_' + file.filename
                decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
                with open(decrypted_filepath, 'wb') as f:
                    f.write(decrypted_data)

                flash('File decrypted successfully!', 'success')
                
                decrypted_files_collection.insert_one({
                    "file_name": decrypted_filename,
                    "user_id": user_id
                })

                safe_filepath = safe_join(current_app.root_path, app.config['UPLOAD_FOLDER'], decrypted_filename)
                if os.path.exists(decrypted_filepath):
                    return send_file(decrypted_filepath, as_attachment=True)
                else:
                    flash('Decrypted file could not be found.', 'error')
                    return redirect(request.url)

                # return send_file(safe_filepath, as_attachment=True)

            except ValueError as e:
                flash('Incorrect password or decryption failed.', 'error')
                return redirect(request.url)
            except Exception as e:
                # flash(f'An error occurred: {str(e)}', 'error')
                return redirect(request.url)

    return render_template('decrypt.html')
