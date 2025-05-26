from flask import Flask, jsonify, request, send_from_directory, make_response, redirect
from flask_cors import CORS
import bcrypt
import os
import json
from werkzeug.utils import secure_filename
from cms import ContentManager
import logging
from functools import wraps
import jwt
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Configure CORS more explicitly
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:8000",
            "http://localhost:8080",
            "https://kosge-frontend.onrender.com",
            "https://kosge-frontend-kqxo.onrender.com",
            "https://kos-frontend.onrender.com",
            "https://kos-frontend-kqxo.onrender.com",
            "https://kos-2.onrender.com"
        ],
        "methods": ["GET", "POST", "DELETE", "OPTIONS", "PUT"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Initialize CMS
content_manager = ContentManager(
    os.path.join(os.path.dirname(__file__), 'content'))

# Get the absolute path of the current directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
PARTICIPANTS_FILE = os.path.join(BASE_DIR, 'participants.json')
BANNERS_FILE = 'banners.json'
JWT_SECRET = os.environ.get('JWT_SECRET', 'supersecretkey')
JWT_ALGORITHM = 'HS256'
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme')
SECTIONS_FILE = 'sections.json'
SLIDESHOW_FILE = 'slideshow.json'
PROGRAM_FILE = 'program.json'

logger.info(f'Base directory: {BASE_DIR}')
logger.info(f'Upload folder: {UPLOAD_FOLDER}')

# Create uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    logger.info(f'Creating upload directory: {UPLOAD_FOLDER}')
    os.makedirs(UPLOAD_FOLDER)
    logger.info('Upload directory created successfully')

# Create empty participants file if it doesn't exist
if not os.path.exists(PARTICIPANTS_FILE):
    with open(PARTICIPANTS_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f)

# Add debug logging for participants file
logger.info(f'Participants file path: {PARTICIPANTS_FILE}')
if os.path.exists(PARTICIPANTS_FILE):
    logger.info('Participants file exists')
    with open(PARTICIPANTS_FILE, 'r', encoding='utf-8') as f:
        try:
            participants = json.load(f)
            logger.info(f'Number of participants: {len(participants)}')
        except json.JSONDecodeError as e:
            logger.error(f'Error reading participants file: {e}')
else:
    logger.warning('Participants file does not exist')

# Dummy-User (später DB)
DUMMY_USER = {
    'username': 'admin',
    # Passwort: 'kosge2024!' (bcrypt-hash)
    'password_hash': b'$2b$12$ZCgWXzUdmVX.PnIfj4oeJOkX69Tu1rVZ51zGYe3kSloANnwMaTlBW'
}

ALLOWED_EXTENSIONS = {'png'}


def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get(
        'Origin')
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS, PUT'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


@app.after_request
def after_request(response):
    return add_cors_headers(response)


@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin",
                             request.headers.get('Origin'))
        response.headers.add("Access-Control-Allow-Methods",
                             "GET, POST, DELETE, OPTIONS, PUT")
        response.headers.add("Access-Control-Allow-Headers",
                             "Content-Type, Authorization")
        return response


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_participants():
    if not os.path.exists(PARTICIPANTS_FILE):
        return []
    with open(PARTICIPANTS_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return []


def save_participants(participants):
    with open(PARTICIPANTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(participants, f, ensure_ascii=False, indent=2)


@app.route('/api/health', methods=['GET'])
def health():
    try:
        # Check if we can read participants file
        participants = load_participants()
        # Check if uploads directory exists
        uploads_exist = os.path.exists(UPLOAD_FOLDER)

        return jsonify({
            'status': 'healthy',
            'participants_count': len(participants),
            'uploads_directory': uploads_exist,
            'base_dir': BASE_DIR,
            'python_version': os.environ.get('PYTHON_VERSION', '3.11.11'),
            'environment': os.environ.get('FLASK_ENV', 'production')
        }), 200
    except Exception as e:
        logger.error(f'Health check failed: {str(e)}')
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username == DUMMY_USER['username'] and bcrypt.checkpw(password.encode(), DUMMY_USER['password_hash']):
        # Dummy-Token (später JWT)
        return jsonify({'token': 'dummy-token', 'user': username}), 200
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/banners', methods=['POST'])
def upload_banner():
    if 'file' not in request.files:
        logger.error('No file part in request')
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        logger.error('No selected file')
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        logger.info(f'Saving file to: {save_path}')
        try:
            file.save(save_path)
            logger.info(f'File saved successfully: {save_path}')
            # Verify file exists after saving
            if os.path.exists(save_path):
                logger.info(f'File exists at: {save_path}')
                logger.info(f'File size: {os.path.getsize(save_path)} bytes')
            else:
                logger.error(f'File not found after saving: {save_path}')
            url = f'/api/uploads/{filename}'
            return jsonify({'url': url, 'filename': filename}), 201
        except Exception as e:
            logger.error(f'Error saving file: {str(e)}')
            return jsonify({'error': f'Failed to save file: {str(e)}'}), 500
    logger.error('Invalid file type')
    return jsonify({'error': 'Invalid file type. Only PNG allowed.'}), 400


@app.route('/api/banners', methods=['GET'])
def list_banners():
    files = [f for f in os.listdir(UPLOAD_FOLDER) if allowed_file(f)]
    urls = [f'/api/uploads/{f}' for f in files]
    return jsonify({'banners': urls}), 200


@app.route('/api/banners/<filename>', methods=['DELETE'])
def delete_banner(filename):
    filename = secure_filename(filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not allowed_file(filename):
        return jsonify({'error': 'Invalid file type.'}), 400
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({'success': True, 'filename': filename}), 200
    else:
        return jsonify({'error': 'File not found.'}), 404


@app.route('/api/uploads/<filename>')
def uploaded_file(filename):
    logger.info(f'Attempting to serve file: {filename}')
    logger.info(f'Upload folder: {UPLOAD_FOLDER}')
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    logger.info(f'Full file path: {file_path}')

    if not os.path.exists(file_path):
        logger.error(f'File not found: {file_path}')
        return jsonify({'error': 'File not found'}), 404

    try:
        logger.info(f'File exists, size: {os.path.getsize(file_path)} bytes')
        response = send_from_directory(UPLOAD_FOLDER, filename)

        # Add CORS headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'

        # Set content type for PNG files
        if filename.lower().endswith('.png'):
            response.headers['Content-Type'] = 'image/png'

        return response
    except Exception as e:
        logger.error(f'Error serving file {filename}: {str(e)}')
        return jsonify({'error': f'Error serving file: {str(e)}'}), 500


@app.route('/api/participants', methods=['POST'])
def add_participant():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')
    banner = data.get('banner')
    if not name:
        return jsonify({'error': 'Name ist erforderlich.'}), 400
    participant = {
        'name': name,
        'email': email,
        'message': message,
        'banner': banner
    }
    participants = load_participants()
    participants.append(participant)
    save_participants(participants)
    return jsonify({'success': True, 'participant': participant}), 201


@app.route('/api/participants', methods=['GET'])
def get_participants():
    try:
        participants = load_participants()
        response = jsonify({'participants': participants})
        # Add CORS headers
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add(
            'Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Content-Type', 'application/json')
        return response, 200
    except Exception as e:
        logger.error(f'Error getting participants: {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/participants', methods=['OPTIONS'])
def participants_options():
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response


# CMS Routes
@app.route('/api/cms/content/<section>', methods=['GET'])
def get_content(section):
    language = request.args.get('language')
    content = content_manager.get_content(section, language)
    if content:
        return jsonify(content), 200
    return jsonify({'error': 'Content not found'}), 404


@app.route('/api/cms/content/<section>', methods=['POST'])
def create_content(section):
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    metadata = data.get('metadata', {})

    if not all([title, content]):
        return jsonify({'error': 'Title and content are required'}), 400

    success = content_manager.create_content(section, title, content, metadata)
    if success:
        return jsonify({'success': True, 'section': section}), 201
    return jsonify({'error': 'Failed to create content'}), 500


@app.route('/api/cms/content/<section>', methods=['PUT'])
def update_content(section):
    data = request.get_json()
    content = data.get('content')
    metadata = data.get('metadata', {})
    language = data.get('language')

    if not content:
        return jsonify({'error': 'Content is required'}), 400

    success = content_manager.update_content(
        section, content, metadata, language)
    if success:
        return jsonify({'success': True, 'section': section}), 200
    return jsonify({'error': 'Failed to update content'}), 404


@app.route('/api/cms/content/<section>/translate/<target_language>', methods=['POST'])
def translate_content(section, target_language):
    success = content_manager.translate_content(section, target_language)
    if success:
        return jsonify({'success': True, 'section': section, 'language': target_language}), 200
    return jsonify({'error': 'Translation failed'}), 400


@app.route('/api/cms/sections', methods=['GET'])
def list_sections():
    language = request.args.get('language')
    sections = content_manager.list_sections(language)
    return jsonify({'sections': sections}), 200


@app.route('/api/cms/content/<section>', methods=['DELETE'])
def delete_content(section):
    language = request.args.get('language')
    success = content_manager.delete_content(section, language)
    if success:
        return jsonify({'success': True}), 200
    return jsonify({'error': 'Content not found'}), 404


# Add a root route that redirects to frontend or shows API status
@app.route('/')
def index():
    # Check if this is a browser request (has Accept header with text/html)
    if 'text/html' in request.headers.get('Accept', ''):
        # Redirect to frontend
        return redirect('https://kosge-frontend.onrender.com')
    # Otherwise return API status as JSON
    return jsonify({
        'status': 'online',
        'message': 'KOSGE API Server',
        'version': '1.0.0',
        'endpoints': {
            'health': '/api/health',
            'login': '/api/login',
            'banners': '/api/banners',
            'participants': '/api/participants',
            'cms': '/api/cms/content/<section>'
        }
    }), 200


# Add a route for favicon.ico to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return '', 204  # Return no content status


# JWT Auth Decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            jwt.decode(token[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


# Hilfsfunktionen für Banner
def load_banners():
    if not os.path.exists(BANNERS_FILE):
        return []
    with open(BANNERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_banners(banners):
    with open(BANNERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(banners, f, ensure_ascii=False, indent=2)


# API: Banner-Liste (öffentlich)
@app.route('/api/banners', methods=['GET'])
def get_banners():
    banners = load_banners()
    return jsonify({'banners': banners})


# API: Banner hinzufügen/ersetzen (Admin)
@app.route('/api/banners', methods=['POST'])
@admin_required
def add_or_replace_banner():
    data = request.json
    url = data.get('url')
    index = data.get('index')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    banners = load_banners()
    if index is not None and 0 <= index < len(banners):
        banners[index] = url
    else:
        banners.append(url)
    save_banners(banners)
    return jsonify({'banners': banners})


# API: Banner löschen (Admin)
@app.route('/api/banners/<int:index>', methods=['DELETE'])
@admin_required
def delete_banner(index):
    banners = load_banners()
    if 0 <= index < len(banners):
        banners.pop(index)
        save_banners(banners)
        return jsonify({'banners': banners})
    return jsonify({'error': 'Invalid index'}), 400


# API: Admin-Login (JWT)
@app.route('/api/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = jwt.encode({
            'user': username,
            'exp': datetime.utcnow() + timedelta(hours=12)
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401


# Hilfsfunktionen für Sektionen

def load_sections():
    if not os.path.exists(SECTIONS_FILE):
        return {}
    with open(SECTIONS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_sections(sections):
    with open(SECTIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(sections, f, ensure_ascii=False, indent=2)

# API: Alle Sektionen (mehrsprachig)


@app.route('/api/sections', methods=['GET'])
def get_sections():
    return jsonify(load_sections())

# API: Einzelne Sektion


@app.route('/api/sections/<section>', methods=['GET'])
def get_section(section):
    sections = load_sections()
    if section in sections:
        return jsonify({section: sections[section]})
    return jsonify({'error': 'Section not found'}), 404

# API: Sektionstext ändern (mehrsprachig, Admin)


@app.route('/api/sections/<section>', methods=['PUT'])
@admin_required
def update_section(section):
    data = request.json
    lang = data.get('lang')
    text = data.get('text')
    if not lang or not text:
        return jsonify({'error': 'Missing lang or text'}), 400
    sections = load_sections()
    if section not in sections:
        sections[section] = {}
    sections[section][lang] = text
    save_sections(sections)
    return jsonify({section: sections[section]})

# Hilfsfunktionen für Slideshow/Programm


def load_slideshow():
    if not os.path.exists(SLIDESHOW_FILE):
        return []
    with open(SLIDESHOW_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_slideshow(slides):
    with open(SLIDESHOW_FILE, 'w', encoding='utf-8') as f:
        json.dump(slides, f, ensure_ascii=False, indent=2)


def load_program():
    if not os.path.exists(PROGRAM_FILE):
        return []
    with open(PROGRAM_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_program(program):
    with open(PROGRAM_FILE, 'w', encoding='utf-8') as f:
        json.dump(program, f, ensure_ascii=False, indent=2)

# API: Slideshow (GET/POST/DELETE)


@app.route('/api/slideshow', methods=['GET'])
def get_slideshow():
    return jsonify({'slideshow': load_slideshow()})


@app.route('/api/slideshow', methods=['POST'])
@admin_required
def add_or_replace_slideshow():
    data = request.json
    url = data.get('url')
    index = data.get('index')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    slides = load_slideshow()
    if index is not None and 0 <= index < len(slides):
        slides[index] = url
    else:
        slides.append(url)
    save_slideshow(slides)
    return jsonify({'slideshow': slides})


@app.route('/api/slideshow/<int:index>', methods=['DELETE'])
@admin_required
def delete_slideshow(index):
    slides = load_slideshow()
    if 0 <= index < len(slides):
        slides.pop(index)
        save_slideshow(slides)
        return jsonify({'slideshow': slides})
    return jsonify({'error': 'Invalid index'}), 400

# API: Programm (GET/POST/DELETE)


@app.route('/api/program', methods=['GET'])
def get_program():
    return jsonify({'program': load_program()})


@app.route('/api/program', methods=['POST'])
@admin_required
def add_or_replace_program():
    data = request.json
    url = data.get('url')
    index = data.get('index')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    program = load_program()
    if index is not None and 0 <= index < len(program):
        program[index] = url
    else:
        program.append(url)
    save_program(program)
    return jsonify({'program': program})


@app.route('/api/program/<int:index>', methods=['DELETE'])
@admin_required
def delete_program(index):
    program = load_program()
    if 0 <= index < len(program):
        program.pop(index)
        save_program(program)
        return jsonify({'program': program})
    return jsonify({'error': 'Invalid index'}), 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
