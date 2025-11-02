import sqlite3
import secrets
import base64
import json
from datetime import datetime, timedelta
from pathlib import Path
import threading
import logging
import pyotp
from flask import Flask, request, jsonify, session, g, render_template, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
def configure_logging():
    if app.logger.handlers:
        return
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = secrets.token_hex(32)  # Generate secure secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['MAPBOX_TOKEN'] = os.environ.get('MAPBOX_TOKEN', '')

instance_dir = Path(app.instance_path)
instance_dir.mkdir(parents=True, exist_ok=True)

database_path = instance_dir / 'medical_supplies.db'
app.config['DATABASE'] = str(database_path)
SCHEMA_PATH = Path(app.root_path) / 'schema.sql'
RESOURCE_TYPES_PATH = Path(app.root_path) / 'static/data/resource_types.json'

_db_initialized = False
_db_lock = threading.Lock()

DATABASE = app.config['DATABASE']

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
_generated_admin_password = None
_generated_admin_totp_secret = None
_generated_admin_totp_uri = None


def load_resource_types():
    try:
        with open(RESOURCE_TYPES_PATH, 'r', encoding='utf-8') as resource_file:
            data = json.load(resource_file)
            if not isinstance(data, list):
                raise ValueError('Resource types config must be a list')
            return data
    except FileNotFoundError:
        app.logger.error('Resource types configuration missing at %s', RESOURCE_TYPES_PATH)
    except Exception as exc:
        app.logger.error('Failed to load resource types: %s', exc)
    return []


app.config['RESOURCE_TYPES'] = load_resource_types()
app.config['RESOURCE_TYPE_VALUES'] = {item['value'] for item in app.config['RESOURCE_TYPES']}

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self' https://api.mapbox.com https://*.tiles.mapbox.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://api.mapbox.com blob:; worker-src 'self' blob:; child-src 'self' blob:; style-src 'self' 'unsafe-inline' https://api.mapbox.com; img-src 'self' data: https://*.mapbox.com https://api.mapbox.com blob:; connect-src 'self' https://api.mapbox.com https://*.tiles.mapbox.com https://events.mapbox.com"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.before_request
def _ensure_schema_ready():
    ensure_db_initialized()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    try:
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as schema_file:
            schema_sql = schema_file.read()
    except FileNotFoundError as exc:
        app.logger.error('Database schema file not found: %s', SCHEMA_PATH)
        raise

    db.executescript(schema_sql)

    ensure_totp_column(db)

    global _generated_admin_password
    global _generated_admin_totp_secret
    global _generated_admin_totp_uri

    if ADMIN_PASSWORD:
        password_hash = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256', salt_length=16)
        db.execute(
            '''INSERT INTO moderators (username, password_hash)
               VALUES (?, ?)
               ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash''',
            (ADMIN_USERNAME, password_hash)
        )
        app.logger.info('Moderator credentials for %s loaded from ADMIN_PASSWORD environment variable.', ADMIN_USERNAME)
    else:
        cursor = db.execute('SELECT id, totp_secret FROM moderators WHERE username = ?', (ADMIN_USERNAME,))
        row = cursor.fetchone()
        if row is None:
            generated_password = secrets.token_urlsafe(16)
            _generated_admin_password = generated_password
            totp_secret = pyotp.random_base32()
            _generated_admin_totp_secret = totp_secret
            _generated_admin_totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=ADMIN_USERNAME, issuer_name='AidMap')
            password_hash = generate_password_hash(generated_password, method='pbkdf2:sha256', salt_length=16)
            db.execute(
                'INSERT INTO moderators (username, password_hash, totp_secret) VALUES (?, ?, ?)',
                (ADMIN_USERNAME, password_hash, totp_secret)
            )
            app.logger.warning('Generated one-time admin password for %s; set ADMIN_PASSWORD to override.', ADMIN_USERNAME)
            app.logger.warning('Generated credentials - Username: %s, Password: %s', ADMIN_USERNAME, generated_password)
            app.logger.warning('Generated TOTP secret for %s; enroll it in an authenticator app immediately.', ADMIN_USERNAME)
            app.logger.warning('Generated TOTP secret value: %s', totp_secret)
            app.logger.warning('Enroll by scanning the otpauth URI in your authenticator app: %s', _generated_admin_totp_uri)
        elif not row['totp_secret']:
            totp_secret = pyotp.random_base32()
            _generated_admin_totp_secret = totp_secret
            _generated_admin_totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=ADMIN_USERNAME, issuer_name='AidMap')
            db.execute('UPDATE moderators SET totp_secret = ? WHERE id = ?', (totp_secret, row['id']))
            app.logger.warning('Generated TOTP secret for existing moderator %s; enroll it in an authenticator app immediately.', ADMIN_USERNAME)
            app.logger.warning('Generated TOTP secret value: %s', totp_secret)
            app.logger.warning('Enroll by scanning the otpauth URI in your authenticator app: %s', _generated_admin_totp_uri)

    db.commit()


def ensure_totp_column(db):
    cursor = db.execute("PRAGMA table_info(moderators)")
    columns = {row['name'] for row in cursor.fetchall()}
    if 'totp_secret' not in columns:
        db.execute('ALTER TABLE moderators ADD COLUMN totp_secret TEXT')
        app.logger.info('Added totp_secret column to moderators table.')


def ensure_db_initialized():
    global _db_initialized
    if _db_initialized:
        return

    with _db_lock:
        if _db_initialized:
            return

        if not database_path.exists():
            database_path.touch(exist_ok=True)

        init_db()
        _db_initialized = True

def require_moderator(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('moderator_logged_in'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/favicon.ico')
def favicon():
    response = send_from_directory(app.static_folder, 'AidMap.png', mimetype='image/png')
    response.headers['Cache-Control'] = 'public, max-age=31536000'
    return response

def get_vote_token():
    """Get or create vote token from cookie"""
    token = request.cookies.get('vote_token')
    if not token:
        token = secrets.token_urlsafe(32)
    return token

@app.route('/')
def index():
    token = app.config.get('MAPBOX_TOKEN')
    if not token:
        app.logger.error('MAPBOX_TOKEN environment variable is not set.')
        return 'Server configuration error: MAPBOX_TOKEN is not set.', 500
    return render_template('index.html', mapbox_token=token, resource_types=app.config['RESOURCE_TYPES'])

@app.route('/api/submissions', methods=['GET'])
def get_submissions():
    """Get all approved submissions"""
    try:
        db = get_db()
        cursor = db.execute('''SELECT id, latitude, longitude, resource_type, 
                              description, votes, approved_at 
                              FROM submissions WHERE status = 'approved' 
                              ORDER BY approved_at DESC''')
        
        submissions = []
        for row in cursor.fetchall():
            submissions.append({
                'id': row['id'],
                'latitude': row['latitude'],
                'longitude': row['longitude'],
                'resource_type': row['resource_type'],
                'description': row['description'],
                'votes': row['votes'],
                'approved_at': row['approved_at']
            })
        
        return jsonify(submissions)
    except Exception as e:
        print(f"Error in get_submissions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions/<int:submission_id>/image', methods=['GET'])
def get_image(submission_id):
    """Get image for approved submission"""
    db = get_db()
    cursor = db.execute('''SELECT image_data, image_mime FROM submissions 
                          WHERE id = ? AND status = 'approved' AND image_data IS NOT NULL''',
                       (submission_id,))
    row = cursor.fetchone()
    
    if not row:
        return '', 404
    
    encoded = base64.b64encode(row['image_data']).decode('utf-8')
    return jsonify({'image': encoded, 'mime': row['image_mime']})

@app.route('/api/submit', methods=['POST'])
def submit_location():
    """Submit new location (pending approval)"""
    try:
        data = request.form
        
        # Validate required fields
        latitude = float(data.get('latitude'))
        longitude = float(data.get('longitude'))
        resource_type = data.get('resource_type', '').strip()
        description = data.get('description', '').strip()
        
        if not resource_type or not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            return jsonify({'error': 'Invalid data'}), 400

        if app.config['RESOURCE_TYPE_VALUES'] and resource_type not in app.config['RESOURCE_TYPE_VALUES']:
            return jsonify({'error': 'Unknown resource type'}), 400
        
        # Limit text lengths
        if len(resource_type) > 100 or len(description) > 1000:
            return jsonify({'error': 'Text too long'}), 400
        
        # Handle image upload
        image_data = None
        image_mime = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename and file.content_type in ['image/jpeg', 'image/png', 'image/jpg']:
                image_data = file.read()
                image_mime = file.content_type
        
        db = get_db()
        cursor = db.execute('''INSERT INTO submissions 
                              (latitude, longitude, resource_type, description, image_data, image_mime)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (latitude, longitude, resource_type, description, image_data, image_mime))
        db.commit()
        
        return jsonify({'success': True, 'id': cursor.lastrowid}), 201
        
    except (ValueError, KeyError) as e:
        return jsonify({'error': 'Invalid data'}), 400

@app.route('/api/vote/<int:submission_id>', methods=['POST'])
def vote(submission_id):
    """Vote for an approved submission"""
    vote_token = get_vote_token()
    
    db = get_db()
    
    # Check if submission exists and is approved
    cursor = db.execute('SELECT id FROM submissions WHERE id = ? AND status = ?',
                       (submission_id, 'approved'))
    if not cursor.fetchone():
        return jsonify({'error': 'Submission not found'}), 404
    
    # Check if already voted (within last 30 days)
    cursor = db.execute('''SELECT voted_at FROM votes 
                          WHERE submission_id = ? AND vote_token = ?
                          AND voted_at > datetime('now', '-30 days')''',
                       (submission_id, vote_token))
    
    if cursor.fetchone():
        return jsonify({'error': 'Already voted'}), 400
    
    try:
        db.execute('INSERT INTO votes (submission_id, vote_token) VALUES (?, ?)',
                  (submission_id, vote_token))
        db.execute('UPDATE submissions SET votes = votes + 1 WHERE id = ?',
                  (submission_id,))
        db.commit()
        
        response = jsonify({'success': True})
        response.set_cookie('vote_token', vote_token, max_age=60*60*24*365)  # 1 year
        return response
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Already voted'}), 400

@app.route('/api/moderator/login', methods=['POST'])
def moderator_login():
    """Moderator login"""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    db = get_db()
    cursor = db.execute('SELECT password_hash, totp_secret FROM moderators WHERE username = ?', (username,))
    row = cursor.fetchone()
    
    session.pop('moderator_logged_in', None)
    session.pop('moderator_username', None)
    session.pop('totp_enrolled', None)
    session.pop('mfa_pending', None)

    if row and check_password_hash(row['password_hash'], password):
        session.permanent = True
        if row['totp_secret']:
            session['mfa_pending'] = username
            return jsonify({'success': True, 'requires_2fa': True})

        session['moderator_logged_in'] = True
        session['moderator_username'] = username
        session['totp_enrolled'] = False
        return jsonify({'success': True, 'requires_2fa': False})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/moderator/logout', methods=['POST'])
def moderator_logout():
    """Moderator logout"""
    session.pop('moderator_logged_in', None)
    session.pop('moderator_username', None)
    session.pop('totp_enrolled', None)
    session.pop('mfa_pending', None)
    return jsonify({'success': True})


@app.route('/api/moderator/login/totp', methods=['POST'])
def moderator_login_totp():
    """Verify moderator TOTP code"""
    pending_username = session.get('mfa_pending')
    if not pending_username:
        return jsonify({'error': 'No pending 2FA challenge'}), 400

    data = request.get_json(silent=True) or {}
    code_raw = str(data.get('code', '') or '')
    code = ''.join(ch for ch in code_raw if ch.isdigit())
    if not code:
        return jsonify({'error': 'Invalid code'}), 400

    db = get_db()
    cursor = db.execute('SELECT totp_secret FROM moderators WHERE username = ?', (pending_username,))
    row = cursor.fetchone()

    if not row or not row['totp_secret']:
        session.pop('mfa_pending', None)
        return jsonify({'error': '2FA not configured'}), 400

    totp = pyotp.TOTP(row['totp_secret'])
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Invalid code'}), 401

    session.pop('mfa_pending', None)
    session['moderator_logged_in'] = True
    session['moderator_username'] = pending_username
    session['totp_enrolled'] = True
    session.permanent = True
    return jsonify({'success': True})

@app.route('/api/moderator/check', methods=['GET'])
def check_moderator():
    """Check if moderator is logged in"""
    return jsonify({
        'logged_in': session.get('moderator_logged_in', False),
        'totp_enrolled': session.get('totp_enrolled', False)
    })


@app.route('/api/moderator/2fa/enroll', methods=['POST'])
@require_moderator
def enroll_totp():
    """Enroll the current moderator in TOTP-based 2FA"""
    username = session.get('moderator_username')
    if not username:
        return jsonify({'error': 'Session missing username'}), 400

    db = get_db()
    cursor = db.execute('SELECT totp_secret FROM moderators WHERE username = ?', (username,))
    row = cursor.fetchone()

    if not row:
        return jsonify({'error': 'Moderator not found'}), 404

    if row['totp_secret']:
        session['totp_enrolled'] = True
        return jsonify({'error': '2FA already enabled'}), 400

    secret = pyotp.random_base32()
    db.execute('UPDATE moderators SET totp_secret = ? WHERE username = ?', (secret, username))
    db.commit()

    totp_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name='AidMap')
    session['totp_enrolled'] = True

    return jsonify({'success': True, 'secret': secret, 'otpauth_url': totp_uri})

@app.route('/api/moderator/pending', methods=['GET'])
@require_moderator
def get_pending():
    """Get all pending submissions"""
    db = get_db()
    cursor = db.execute('''SELECT id, latitude, longitude, resource_type, 
                          description, created_at 
                          FROM submissions WHERE status = 'pending' 
                          ORDER BY created_at ASC''')
    
    submissions = []
    for row in cursor.fetchall():
        submissions.append({
            'id': row['id'],
            'latitude': row['latitude'],
            'longitude': row['longitude'],
            'resource_type': row['resource_type'],
            'description': row['description'],
            'created_at': row['created_at']
        })
    
    return jsonify(submissions)

@app.route('/api/moderator/submissions/<int:submission_id>/image', methods=['GET'])
@require_moderator
def get_pending_image(submission_id):
    """Get image for any submission (moderator only)"""
    db = get_db()
    cursor = db.execute('''SELECT image_data, image_mime FROM submissions 
                          WHERE id = ? AND image_data IS NOT NULL''',
                       (submission_id,))
    row = cursor.fetchone()
    
    if not row:
        return '', 404
    
    encoded = base64.b64encode(row['image_data']).decode('utf-8')
    return jsonify({'image': encoded, 'mime': row['image_mime']})

@app.route('/api/moderator/approve/<int:submission_id>', methods=['POST'])
@require_moderator
def approve_submission(submission_id):
    """Approve a pending submission"""
    db = get_db()
    db.execute('''UPDATE submissions SET status = 'approved', approved_at = CURRENT_TIMESTAMP 
                 WHERE id = ? AND status = 'pending' ''',
              (submission_id,))
    db.commit()
    
    if db.total_changes == 0:
        return jsonify({'error': 'Submission not found'}), 404
    
    return jsonify({'success': True})

@app.route('/api/moderator/reject/<int:submission_id>', methods=['POST'])
@require_moderator
def reject_submission(submission_id):
    """Reject a pending submission"""
    db = get_db()
    db.execute('DELETE FROM submissions WHERE id = ? AND status = ?',
              (submission_id, 'pending'))
    db.commit()
    
    if db.total_changes == 0:
        return jsonify({'error': 'Submission not found'}), 404
    
    return jsonify({'success': True})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("Initializing database...")
    with app.app_context():
        ensure_db_initialized()
    print("Database initialized successfully!")
    configure_logging()
    if ADMIN_PASSWORD:
        app.logger.info("Moderator credentials loaded from environment - Username: %s", ADMIN_USERNAME)
    elif _generated_admin_password:
        app.logger.warning("SECURITY WARNING: A temporary moderator password was generated.")
        app.logger.warning("Generated credentials - Username: %s, Password: %s", ADMIN_USERNAME, _generated_admin_password)
        app.logger.warning("Set the ADMIN_PASSWORD environment variable or change the password after login.")
        if _generated_admin_totp_secret:
            app.logger.warning("2FA REQUIRED: A temporary TOTP secret was generated for the moderator account.")
            app.logger.warning("TOTP secret: %s", _generated_admin_totp_secret)
            if _generated_admin_totp_uri:
                app.logger.warning("TOTP provisioning URI: %s", _generated_admin_totp_uri)
            app.logger.warning("Enroll this secret in an authenticator app before attempting to log in.")
    else:
        app.logger.info("Moderator credentials unchanged; ensure the existing password is strong.")
        if _generated_admin_totp_secret:
            app.logger.warning("2FA REQUIRED: A TOTP secret was generated for the moderator account.")
            app.logger.warning("TOTP secret: %s", _generated_admin_totp_secret)
            if _generated_admin_totp_uri:
                app.logger.warning("TOTP provisioning URI: %s", _generated_admin_totp_uri)
            app.logger.warning("Enroll this secret in an authenticator app before attempting to log in.")
    app.logger.info("Starting server on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)