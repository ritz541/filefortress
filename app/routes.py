from flask import render_template, redirect, request, flash, url_for, send_file, session
from app import app
import config
import scrypt, os, time
from werkzeug.utils import secure_filename
from app.functions import get_db, encrypt_file, decrypt_file
from bson.objectid import ObjectId
from datetime import datetime

# file = request.files['file']
# FILEPATH = filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
# file.save(filepath)

db = get_db()
all_files_collection = db['all_files']
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
    
    if 'username' in session:
        # flash("You are already logged in", 'warning')
        return redirect(url_for('dashboard'))
    
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
    
    user = users_collection.find_one({
        'username': session['username']
    })
    user_id = user['_id']
    
    # Fetch data from MongoDB and convert to lists
    encrypted_files = list(encrypted_files_collection.find({'user_id': user_id}))
    decrypted_files = list(decrypted_files_collection.find({'user_id': user_id}))

# Pass these lists to the template
    return render_template('dashboard.html', encrypted_files=encrypted_files, decrypted_files=decrypted_files)


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
            
            upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            encrypted_files_collection.insert_one({
                'file_name': filename,
                'user_id': user_id,
                'upload_date': upload_date
            })
            
            all_files_collection.insert_one({
                'file_name': filename,
                'user_id': user_id,
                'upload_date': upload_date
            })
            
            
            
            return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    # Ensure user is logged in (uncomment this if login is implemented)
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({
        'username': session.get('username')  # Use `get` to avoid KeyError
    })
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))  # Redirect to login if user not found
    
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

                # Save the decrypted file
                decrypted_filename = 'decrypted_' + file.filename
                decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
                with open(decrypted_filepath, 'wb') as f:
                    f.write(decrypted_data)

                upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Insert into collections
                decrypted_files_collection.insert_one({
                    "file_name": decrypted_filename,
                    "user_id": user_id,
                    'upload_date': upload_date
                })
                all_files_collection.insert_one({
                    "file_name": decrypted_filename,
                    "user_id": user_id,
                    'upload_date': upload_date
                })

                # Flash a success message and redirect to dashboard
                flash('File decrypted successfully!', 'success')
                return redirect(url_for('dashboard'))

            except ValueError:
                flash('Incorrect password or decryption failed.', 'error')
                return redirect(request.url)
            except Exception as e:
                flash(f'An error occurred: {str(e)}', 'error')
                return redirect(request.url)

    return render_template('decrypt.html')

@app.route('/download/<file_name>')
def download(file_name):
    file_path = os.path.join(os.path.dirname(__file__), '..', 'uploads', file_name)
    return send_file(file_path, as_attachment=True)

@app.route('/delete/<file_id>', methods=['POST'])
def delete(file_id):
    try:
        # Convert file_id string to ObjectId
        object_id = ObjectId(file_id)

        # Attempt to delete from both collections
        encrypted_result = encrypted_files_collection.delete_one({"_id": object_id})
        decrypted_result = decrypted_files_collection.delete_one({"_id": object_id})

        # Determine the outcome
        if encrypted_result.deleted_count > 0 or decrypted_result.deleted_count > 0:
            flash('File deleted successfully!', 'success')
        else:
            flash('File not found in either collection.', 'warning')

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')

    # Redirect back to the dashboard with updated data
    return redirect(url_for('dashboard'))
