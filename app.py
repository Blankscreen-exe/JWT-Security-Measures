from flask import Flask, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# --------------------------- 1. Use HTTPS ------------------------------------
# Ensure the app runs over HTTPS, enforced via a reverse proxy like nginx or gunicorn, and also use HSTS headers.

@app.before_request
def enforce_https():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.after_request
def apply_hsts(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# --------------------------- 2. Short-Lived JWT Tokens -----------------------
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(minutes=15)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated

# --------------------------- 3. Refresh Tokens -------------------------------
@app.route('/refresh-token', methods=['POST'])
@token_required
def refresh_token():
    token = jwt.encode({'exp': datetime.datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']}, app.config['SECRET_KEY'])
    return jsonify({'token': token})

# --------------------------- 4. Store Tokens Securely ------------------------
# In production, make sure tokens are stored in HttpOnly, Secure cookies, or local storage with strict security.

# --------------------------- 5. Implement Rate Limiting ----------------------
limiter = Limiter(app, key_func=get_remote_address, default_limits=["100 per day", "10 per minute"])

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    auth = request.json
    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('Could not verify', 401)
    
    # Example hardcoded user
    if auth['username'] == 'user' and check_password_hash(generate_password_hash('password'), auth['password']):
        token = jwt.encode({'exp': datetime.datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']}, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return make_response('Could not verify', 401)

# --------------------------- 6. Avoid Storing Sensitive Data -----------------
# Never log or store sensitive data like passwords in logs, make sure to hash passwords.

# --------------------------- 7. Strong Password Policies ---------------------
# Passwords should have strong requirements like length and complexity.
# Use password hashing for storage, here is an example using werkzeug.security.

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method='sha256')
    # Save the user with hashed password
    return jsonify({'message': 'User registered successfully'})

# --------------------------- 8. Input Validation & Sanitization ---------------
@app.route('/data', methods=['POST'])
@token_required
def process_data():
    data = request.json
    if 'username' not in data or len(data['username']) < 3:
        return jsonify({'message': 'Invalid input'}), 400
    # Process the data safely
    return jsonify({'message': 'Data processed successfully'})

# --------------------------- 9. Prevent CSRF ---------------------------------
# Flask-WTF can be used to prevent CSRF in forms, or you can manually check CSRF tokens in JSON requests.

@app.after_request
def set_csrf_token(response):
    response.headers['X-CSRFToken'] = 'your_csrf_token_here'
    return response

# --------------------------- 10. Secure Headers ------------------------------
@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --------------------------- 11. Encryption for Sensitive Data ----------------
# Encrypt sensitive data before storage or transmission.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    public_key = private_key.public_key()
    message = request.json.get('message').encode('utf-8')
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return jsonify({'ciphertext': ciphertext.hex()})

# --------------------------- 12. Regular Security Updates --------------------
# Make sure all dependencies (Flask, libraries) are updated regularly.
# Use `pip list --outdated` and keep them up to date with `pip install --upgrade <package>`.

# --------------------------- 13. Logging and Monitoring ----------------------
import logging

logging.basicConfig(filename='app.log', level=logging.INFO)

@app.route('/action', methods=['POST'])
@token_required
def action():
    logging.info(f'Action performed by user at {datetime.datetime.utcnow()}')
    return jsonify({'message': 'Action logged'})

if __name__ == '__main__':
    app.run(debug=True)