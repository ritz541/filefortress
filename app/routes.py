from flask import render_template, redirect, request, flash, url_for, send_file, session
from app import app
import config
import scrypt, os, hmac, random
from werkzeug.utils import secure_filename
from app.functions import get_db, encrypt_file, decrypt_file
from bson.objectid import ObjectId
from datetime import datetime


db = get_db()
all_files_collection = db['all_files']
users_collection = db['users']
encrypted_files_collection = db['encrypted_files']
decrypted_files_collection = db['decrytped_files']
group_chat_collection = db['group_chat']

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    alert_message = None

    if 'username' in session:
        # User is already logged in
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if user already exists
        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            alert_message = "An account with this email already exists."
        else:
            # Generate salt and hashed password
            salt = os.urandom(16)
            hashed_password = scrypt.hash(password, salt)

            # Insert new user into the database
            users_collection.insert_one({
                "email": email,
                "username": username,
                "password": hashed_password,
                "salt": salt
            })

            alert_message = "Registration successful. You can now log in."
            return render_template('register.html', alert_message=alert_message)

    return render_template('register.html', alert_message=alert_message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect to dashboard if already logged in
    if 'username' in session:
        return redirect(url_for('dashboard'))

    alert_message = None

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch the user from the database
        user = users_collection.find_one({"email": email})

        if user:
            stored_hash = user['password']
            stored_salt = user['salt']
            entered_hash = scrypt.hash(password, stored_salt)

            # Securely compare hashes
            if hmac.compare_digest(entered_hash, stored_hash):
                # Set session variables and redirect
                username = user['username']
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                alert_message = "Invalid password. Please try again."
        else:
            alert_message = "User not found. Please register first."

    # Render login page with an optional alert message
    return render_template('login.html', title='Login', alert_message=alert_message)

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
    alert_message = None  # To hold the alert message

    if 'username' not in session:
        flash('You are not logged in', 'warning')
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'username': session['username']})
    user_id = user['_id']
    
    if request.method == 'POST':
        if 'file' not in request.files:
            alert_message = 'No file part provided.'
            return render_template('upload.html', alert_message=alert_message)

        file = request.files['file']
        password = request.form.get('password')

        if not file.filename:
            alert_message = 'No file selected.'
            return render_template('upload.html', alert_message=alert_message)

        if file and password:
            try:
                # Secure the filename and save the file
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # Encrypt the file
                encrypted_data = encrypt_file(filepath, password)
                with open(filepath, 'wb') as f:
                    f.write(encrypted_data)

                # Save file metadata in the database
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

                alert_message = 'File uploaded and encrypted successfully!'
                return render_template('upload.html', alert_message=alert_message)
            except Exception as e:
                alert_message = f"An error occurred: {str(e)}"
                return render_template('upload.html', alert_message=alert_message)

    return render_template('upload.html', alert_message=alert_message)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    alert_message = None  # Variable to hold alert messages

    # Check if user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({'username': session.get('username')})
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    user_id = user['_id']

    if request.method == 'POST':
        # Check if file part exists
        if 'file' not in request.files:
            alert_message = 'No file part provided.'
            return render_template('decrypt.html', alert_message=alert_message)

        file = request.files['file']
        password = request.form.get('password')

        # Check if a file is selected
        if not file.filename:
            alert_message = 'No file selected.'
            return render_template('decrypt.html', alert_message=alert_message)

        if file and password:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(filepath)

            try:
                # Attempt to decrypt the file
                decrypted_data = decrypt_file(filepath, password)

                # Save the decrypted file
                decrypted_filename = 'decrypted_' + file.filename
                decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
                with open(decrypted_filepath, 'wb') as f:
                    f.write(decrypted_data)

                # Record the decryption in the database
                upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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

                alert_message = 'File decrypted successfully!'
                return render_template('decrypt.html', alert_message=alert_message)

            except ValueError:
                alert_message = 'Incorrect password or decryption failed.'
                return render_template('decrypt.html', alert_message=alert_message)
            except Exception as e:
                alert_message = f'An error occurred: {str(e)}'
                return render_template('decrypt.html', alert_message=alert_message)

    return render_template('decrypt.html', alert_message=alert_message)

@app.route('/download/<file_name>')
def download(file_name):
    file_path = os.path.join(os.path.dirname(__file__), '..', 'uploads', file_name)
    return send_file(file_path, as_attachment=True)

@app.route('/delete/<file_id>', methods=['POST'])
def delete(file_id):
    try:
        # Validate and convert file_id to ObjectId
        try:
            object_id = ObjectId(file_id)
        except Exception as e:
            flash('Invalid file ID.', 'warning')
            return redirect(url_for('dashboard'))

        # Try to delete the file record from both collections
        encrypted_result = encrypted_files_collection.delete_one({"_id": object_id})
        decrypted_result = decrypted_files_collection.delete_one({"_id": object_id})
        all_result = all_files_collection.delete_one({"_id": object_id})

        # Check deletion results
        if any([encrypted_result.deleted_count, decrypted_result.deleted_count, all_result.deleted_count]):
            flash('File deleted successfully!', 'success')
        else:
            flash('File not found in any collection.', 'warning')

    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')

    # Redirect back to the dashboard
    return redirect(url_for('dashboard'))

@app.route('/group_chat', methods=['GET', 'POST'])
def group_chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'username': session['username']})
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    user_id = user['_id']

    if request.method == 'POST':
        message = request.form.get('message')
        if message and message.strip():
            # Add some randomization to message IDs for extra "secrecy"
            message_id = f"MSG-{random.randint(1000, 9999)}-{random.randint(100, 999)}"
            
            group_chat_collection.insert_one({
                "message_id": message_id,
                "message": message.strip(),
                "username": session['username'],
                "user_id": user_id,
                "timestamp": datetime.now(),
                "encryption_status": "SECURED"  # Just for show
            })

    # Get messages with sorting
    messages = list(group_chat_collection.find({}).sort("timestamp", -1).limit(50))
    messages.reverse()
    
    return render_template('group_chat.html', messages=messages)