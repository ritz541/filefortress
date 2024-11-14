import os

import scrypt
from app import app


# Set the upload folder and maximum upload size
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# Set the secret key for session management
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'





