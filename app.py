from flask import Flask, request, jsonify, session, redirect
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api.proxies import GenericProxyConfig
import os
import pymongo
from dotenv import load_dotenv
from openai import OpenAI
from bson.objectid import ObjectId
from flask_cors import CORS
import requests
import ssl
import bcrypt
from functools import wraps
import datetime
import sys
import logging
import certifi
from urllib.parse import urlparse, parse_qs
#pdf
import PyPDF2
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Log to stdout for Render to capture
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
# Enable CORS for all routes
CORS(app, resources={r"/*": {"origins": "*"}})

# Secret key for sessions
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key")

MONGODB_URI = os.getenv("MONGODB_URI")
# Make sure MongoDB URI is properly formatted
if MONGODB_URI and "retryWrites" not in MONGODB_URI:
    if "?" in MONGODB_URI:
        MONGODB_URI += "&retryWrites=true"
    else:
        MONGODB_URI += "?retryWrites=true"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ASSEMBLYAI_API_KEY = os.getenv("ASSEMBLYAI_API_KEY")
SUPADATA_API_KEY = os.getenv("SUPADATA_API_KEY")


# Initialize YouTube Transcript API with proxy
PROXY_HOST = "2isphj01.pr.thordata.net"
PROXY_PORT = "9999"
PROXY_USERNAME = "td-customer-GjlMS7dbw6w1"
PROXY_PASSWORD = "oJSdDwmajn1h"

# Format the proxy URL with authentication credentials
proxy_url = f"http://{PROXY_USERNAME}:{PROXY_PASSWORD}@{PROXY_HOST}:{PROXY_PORT}"

logger.info(f"Initializing YouTubeTranscriptApi with proxy: {PROXY_HOST}:{PROXY_PORT}")
youtube_transcript_api = YouTubeTranscriptApi(
    proxy_config=GenericProxyConfig(
        http_url=proxy_url,
        https_url=proxy_url
    )
)

# Get CA certificates
ca = certifi.where()

# Connect to MongoDB with proper SSL configuration
try:
    myclient = pymongo.MongoClient(
        MONGODB_URI,
        tlsCAFile=ca,
        connectTimeoutMS=30000,
        socketTimeoutMS=None,
        connect=False,
        maxPoolSize=50,
        retryWrites=True
    )
    
    # Verify connection works
    myclient.admin.command('ping')
    logger.info("Connected to MongoDB successfully")
    
except Exception as e:
    logger.critical("MongoDB connection failed: %s", str(e))
    # Don't exit in production; app should still try to start

# Log available databases
try:
    db_names = myclient.list_database_names()
    logger.info("Available databases: %s", db_names)
except Exception as e:
    logger.error("Failed to list databases: %s", str(e))

db = myclient['NoteBuddy']

# Log collections in database
try:
    collections = db.list_collection_names()
    logger.info("Collections in NoteBuddy: %s", collections)
except Exception as e:
    logger.error("Failed to list collections: %s", str(e))

collection = db['SavedNotes']
credentials_collection = db['UserCredentials']

# Create index for unique usernames
try:
    credentials_collection.create_index([('username', pymongo.ASCENDING)], unique=True)
    logger.info("Created unique index on username field")
except Exception as e:
    logger.warning("Failed to create index: %s", str(e))

# Initialize OpenAI client
try:
    openai_client = OpenAI(api_key=OPENAI_API_KEY)
    logger.info("OpenAI client initialized")
except Exception as e:
    logger.critical("Failed to initialize OpenAI client: %s", str(e))

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# Authentication decorator
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            logger.warning("Request missing Authorization header")
            return jsonify({"error": "Authorization header is required"}), 401
        
        try:
            auth_parts = auth_header.split(' ')
            if len(auth_parts) != 2 or auth_parts[0] != 'Basic':
                logger.warning("Invalid authorization format")
                return jsonify({"error": "Invalid authorization format"}), 401
                
            credentials = auth_parts[1].split(':')
            if len(credentials) != 2:
                logger.warning("Invalid credentials format")
                return jsonify({"error": "Invalid credentials format"}), 401
                
            username, password = credentials
            
            # Check if user exists
            user = credentials_collection.find_one({'username': username})
            if not user:
                logger.warning("Authentication failed: User not found - %s", username)
                return jsonify({"error": "Invalid username or password"}), 401
                
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
                logger.warning("Authentication failed: Invalid password for user - %s", username)
                return jsonify({"error": "Invalid username or password"}), 401
                
            # Attach username to request
            request.username = username
            return f(*args, **kwargs)
        except Exception as e:
            logger.error("Authentication error: %s", str(e))
            return jsonify({"error": f"Authentication error: {str(e)}"}), 401
            
    return decorated

# Registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validate input
    if not username or not password:
        logger.warning("Registration failed: Missing username or password")
        return jsonify({"error": "Username and password are required"}), 400
    
    if len(password) < 8:
        logger.warning("Registration failed: Password too short for user - %s", username)
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    try:
        # Hash the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        # Try to insert the new user
        credentials_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'created_at': datetime.datetime.utcnow()
        })
        
        logger.info("User registered successfully: %s", username)
        return jsonify({"success": True, "message": "User registered successfully"}), 201
    
    except pymongo.errors.DuplicateKeyError:
        logger.warning("Registration failed: Username already exists - %s", username)
        return jsonify({"error": "Username already exists"}), 409
    
    except Exception as e:
        logger.error("Registration failed: %s", str(e))
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        logger.warning("Login failed: Missing username or password")
        return jsonify({"error": "Username and password are required"}), 400
    
    try:
        # Find user by username
        user = credentials_collection.find_one({'username': username})
        
        if not user:
            logger.warning("Login failed: User not found - %s", username)
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Check password
        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            logger.info("User logged in successfully: %s", username)
            response = {
                'success': True,
                'message': 'Login successful',
                'username': username
            }
            return jsonify(response), 200
        else:
            logger.warning("Login failed: Invalid password for user - %s", username)
            return jsonify({"error": "Invalid username or password"}), 401
    
    except Exception as e:
        logger.error("Login failed: %s", str(e))
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

# Function to get transcript using youtube_transcript_api with proxy support
def getTranscript(video_id):
    try:
        logger.info("Fetching transcript for video ID: %s", video_id)
        transcript_list = youtube_transcript_api.fetch(video_id).to_raw_data()
        transcript = ' '.join([item['text'] for item in transcript_list])
        logger.info("Transcript fetched successfully for video ID: %s (%d characters)", video_id, len(transcript))
        return transcript
    except Exception as e:
        logger.error("Error getting transcript for video ID %s: %s", video_id, str(e))
        raise Exception(f"Error getting transcript: {str(e)}")

@app.post('/summary')
@auth_required
def summary():
    data = request.get_json() or {}
    url = data.get('URL','').strip()
    if not url:
        return jsonify(error="URL required"), 400

    # robustly extract the "v" query-param
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    video_id = qs.get('v', [None])[0]
    if not video_id:
        return jsonify(error="Could not extract video ID from URL"), 400

    try:
        transcript = getTranscript(video_id)
        summary = summarizeText(transcript)
        return jsonify({'Summary': summary}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def summarizeText(text):
    try:
        logger.info("Summarizing text (%d characters)", len(text))
        prompt = (
            "You are a helpful assistant that converts long video transcripts into concise, "
            "well-formatted notes in Markdown.\n\n"
            "Instructions:\n"
            "- Produce a title line at the top (e.g. "# MongoDB Intro").\n"
            "- Organize key points into sections using Markdown headings (##).\n"
            "- Use bullet lists (-) for sub-points.\n"
            "- Keep it under 300 words.\n"
            "- Do not include anything besides the Markdown.\n\n"
            f"Transcript:\n```\n{text}\n```"
        )

        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user",   "content": prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )
        
        summary = response.choices[0].message.content.strip()
        logger.info("Summary generated successfully (%d characters)", len(summary))
        return summary
    except Exception as e:
        logger.error("Error summarizing text: %s", str(e))
        raise Exception(f"Error summarizing text: {str(e)}")
#transcript with supadata instead
def getTranscriptSupadata(video_id):
    try:
        logger.info("Fetching transcript using Supadata API for video ID: %s", video_id)
        
        # Supadata API endpoint - using GET request with query parameters
        base_url = "https://api.supadata.ai/v1/youtube/transcript"
        
        headers = {
            "x-api-key": SUPADATA_API_KEY
        }
        
        # Query parameters - using videoId and text=true for plain text response
        params = {
            "videoId": video_id,
            "text":  "true"
        }
        
        response = requests.get(base_url, headers=headers, params=params, timeout=30)
        
        if response.status_code != 200:
            logger.error("Supadata API request failed: %s", response.text)
            raise Exception(f"Supadata API request failed: {response.text}")
        
        data = response.json()
        
        # Extract transcript from 'content' field as per API documentation
        if 'content' not in data:
            logger.error("Unexpected Supadata API response structure: %s", data)
            raise Exception("No 'content' field in API response")
        
        transcript = data['content']
        detected_lang = data.get('lang', 'unknown')
        available_langs = data.get('availableLangs', [])
        
        logger.info("Transcript fetched successfully using Supadata for video ID: %s (%d characters), lang: %s", 
                   video_id, len(transcript), detected_lang)
        logger.info("Available languages: %s", available_langs)
        
        return transcript
        
    except requests.exceptions.Timeout:
        logger.error("Supadata API request timed out for video ID: %s", video_id)
        raise Exception("Supadata API request timed out")
    except requests.exceptions.RequestException as e:
        logger.error("Network error with Supadata API for video ID %s: %s", video_id, str(e))
        raise Exception(f"Network error with Supadata API: {str(e)}")
    except Exception as e:
        logger.error("Error getting transcript from Supadata for video ID %s: %s", video_id, str(e))
        raise Exception(f"Error getting transcript from Supadata: {str(e)}")
# 6. Add helper route to test Supadata API connection
@app.route('/test-supadata', methods=['POST'])
@auth_required
def test_supadata():
    """Test route to verify Supadata API connectivity"""
    data = request.get_json() or {}
    url = data.get('URL','').strip()
    
    if not url:
        return jsonify(error="URL required"), 400

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    video_id = qs.get('v', [None])[0]
    
    if not video_id:
        return jsonify(error="Could not extract video ID from URL"), 400

    try:
        transcript = getTranscriptSupadata(video_id)
        return jsonify({
            'success': True,
            'video_id': video_id,
            'transcript_length': len(transcript),
            'full_transcript': transcript
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
#pdf routes
@app.route('/upload-pdf', methods=['POST'])
@auth_required
def upload_pdf():
    username = request.username
    logger.info("PDF upload request from user: %s", username)
    
    # Check if the request contains a file
    if 'pdf' not in request.files:
        logger.warning("No PDF file provided in request")
        return jsonify({"error": "No PDF file provided"}), 400
    
    pdf_file = request.files['pdf']
    if pdf_file.filename == '':
        logger.warning("Empty PDF filename provided")
        return jsonify({"error": "No PDF file selected"}), 400
    
    # Check file extension
    if not pdf_file.filename.lower().endswith('.pdf'):
        logger.warning("Invalid file type: %s", pdf_file.filename)
        return jsonify({"error": "File must be a PDF"}), 400
    
    # Check file size - limiting to 10MB for PDFs
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB in bytes
    pdf_file.seek(0, os.SEEK_END)
    file_size = pdf_file.tell()
    pdf_file.seek(0)  # Reset file pointer to beginning
    
    logger.info("Received PDF file: %s, size: %.2f MB", pdf_file.filename, file_size / (1024 * 1024))
    
    if file_size > MAX_FILE_SIZE:
        logger.warning("File too large: %.2f MB (max %.2f MB)", file_size / (1024 * 1024), MAX_FILE_SIZE / (1024 * 1024))
        return jsonify({"error": f"File too large. Maximum size is {MAX_FILE_SIZE / (1024 * 1024)}MB"}), 413
    
    try:
        # Extract text from PDF
        pdf_data = pdf_file.read()
        pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_data))
        
        # Extract text from all pages
        extracted_text = ""
        for page_num, page in enumerate(pdf_reader.pages):
            try:
                page_text = page.extract_text()
                extracted_text += page_text + "\n"
                logger.info("Extracted text from page %d", page_num + 1)
            except Exception as e:
                logger.warning("Error extracting text from page %d: %s", page_num + 1, str(e))
                continue
        
        if not extracted_text.strip():
            logger.warning("No text could be extracted from PDF")
            return jsonify({"error": "No text could be extracted from the PDF. The file might be image-based or corrupted."}), 400
        
        logger.info("Successfully extracted %d characters from PDF", len(extracted_text))
        
        # Check if extracted text is too long for processing
        MAX_TEXT_LENGTH = 50000  # Adjust based on your OpenAI token limits
        if len(extracted_text) > MAX_TEXT_LENGTH:
            logger.info("Text too long (%d chars), truncating to %d chars", len(extracted_text), MAX_TEXT_LENGTH)
            extracted_text = extracted_text[:MAX_TEXT_LENGTH] + "\n[Text truncated due to length...]"
        
        # Generate summary using existing function
        summary = summarizeText(extracted_text)
        
        logger.info("PDF processing successful for user %s", username)
        return jsonify({
            "summary": summary,
            "extracted_text_length": len(extracted_text),
            "filename": pdf_file.filename
        }), 200
    
    except Exception as e:
        logger.error("Error processing PDF for user %s: %s", username, str(e))
        return jsonify({"error": f"Error processing PDF: {str(e)}"}), 500


# Optional: Add a route to just extract text without summarizing
@app.route('/extract-pdf-text', methods=['POST'])
@auth_required
def extract_pdf_text():
    username = request.username
    logger.info("PDF text extraction request from user: %s", username)
    
    # Similar validation as above...
    if 'pdf' not in request.files:
        return jsonify({"error": "No PDF file provided"}), 400
    
    pdf_file = request.files['pdf']
    if pdf_file.filename == '' or not pdf_file.filename.lower().endswith('.pdf'):
        return jsonify({"error": "Invalid PDF file"}), 400
    
    try:
        pdf_data = pdf_file.read()
        pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_data))
        
        extracted_text = ""
        for page in pdf_reader.pages:
            extracted_text += page.extract_text() + "\n"
        
        if not extracted_text.strip():
            return jsonify({"error": "No text could be extracted from the PDF"}), 400
        
        return jsonify({
            "text": extracted_text,
            "length": len(extracted_text),
            "pages": len(pdf_reader.pages),
            "filename": pdf_file.filename
        }), 200
    
    except Exception as e:
        logger.error("Error extracting text from PDF: %s", str(e))
        return jsonify({"error": f"Error extracting text: {str(e)}"}), 500

#route to add note to db
@app.post('/postNote')
@auth_required
def postNote():
    data = request.get_json()
    username = request.username  # Use username from auth, not from request body
    note = data.get('note','')
    title = data.get('title','')
    
    logger.info("Saving new note for user %s: %s", username, title)
    
    try:
        result = collection.insert_one({
            'username': username,
            'title':    title,
            'note':     note
        })
        
        logger.info("Note saved successfully with ID: %s", str(result.inserted_id))
        
        return jsonify({
            'id':    str(result.inserted_id),
            'title': title,
            'note':  note
        }), 201
    except Exception as e:
        logger.error("Error saving note: %s", str(e))
        return jsonify({"error": f"Error saving note: {str(e)}"}), 500

@app.get("/notes")
@auth_required
def list_notes():
    logger.info("Listing all notes")
    try:
        docs = collection.find({}, { "_id": 1, "username": 1, "title": 1, "note": 1 })
        notes = []
        for d in docs:
            notes.append({
                'id':       str(d['_id']),
                'username': d['username'],
                'title':    d['title'],
                'note':     d['note']
            })
        
        logger.info("Retrieved %d notes", len(notes))
        return jsonify(notes), 200
    except Exception as e:
        logger.error("Error listing notes: %s", str(e))
        return jsonify({"error": f"Error listing notes: {str(e)}"}), 500

@app.get("/userNotes")
@auth_required
def userNotes():
    username = request.username  # Get username from auth
    logger.info("Fetching notes for user: %s", username)
    
    try:
        docs = collection.find(
            {'username': username},
            {'_id': 1, 'title': 1, 'note': 1}
        )
        
        notes = []
        for d in docs:
            notes.append({
            'id':    str(d['_id']),
            'title': d['title'],
            'note':  d['note']
            })
        
        logger.info("Retrieved %d notes for user %s", len(notes), username)
        return jsonify(notes), 200
    except Exception as e:
        logger.error("Error fetching notes for user %s: %s", username, str(e))
        return jsonify({"error": f"Error fetching notes: {str(e)}"}), 500

@app.route('/deleteNote/<note_id>', methods=['DELETE'])
@auth_required
def delete_note(note_id):
    try:
        # Convert string ID to ObjectId
        object_id = ObjectId(note_id)
        
        # Get username from auth
        username = request.username
        
        logger.info("Attempting to delete note %s for user %s", note_id, username)
        
        # Only allow deletion of user's own notes
        result = collection.delete_one({
            '_id': object_id,
            'username': username  # Ensure user only deletes their own notes
        })
        
        # Check if a document was deleted
        if result.deleted_count == 0:
            logger.warning("Note not found or not authorized to delete: %s by %s", note_id, username)
            return jsonify({"error": "Note not found or not authorized to delete"}), 404
        
        logger.info("Note %s successfully deleted by user %s", note_id, username)    
        return jsonify({"success": True, "message": "Note deleted successfully"}), 200
    
    except Exception as e:
        logger.error("Error deleting note %s: %s", note_id, str(e))
        return jsonify({"error": f"Error deleting note: {str(e)}"}), 500

@app.post('/llmSummaryTest')
@auth_required
def llm_summary_test():
    data = request.get_json() or {}
    transcript = data.get("transcript", "").strip()
    if not transcript:
        logger.warning("llmSummaryTest called with empty transcript")
        return jsonify(error="transcript field required"), 400

    logger.info("Processing llmSummaryTest request (%d characters)", len(transcript))

    prompt = (
        "You are a helpful assistant that converts long video transcripts into concise, "
        "well-formatted notes in Markdown.\n\n"
        "Instructions:\n"
        "- Produce a title line at the top (e.g. "# MongoDB Intro").\n"
        "- Organize key points into sections using Markdown headings (##).\n"
        "- Use bullet lists (-) for sub-points.\n"
        "- Keep it under 300 words.\n"
        "- Do not include anything besides the Markdown.\n\n"
        f"Transcript:\n```\n{transcript}\n```"
    )

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user",   "content": prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )
        
        summary = response.choices[0].message.content.strip()
        logger.info("llmSummaryTest successful (%d characters output)", len(summary))
        return jsonify(summary=summary), 200
    except Exception as e:
        logger.error("Error in llmSummaryTest: %s", str(e))
        return jsonify(error=str(e)), 502

#Routes for handling voice recordings
@app.route('/upload-audio', methods=['POST'])
@auth_required
def upload_audio():
    username = request.username
    logger.info("Audio upload request from user: %s", username)
    
    # Check if the request contains a file
    if 'audio' not in request.files:
        logger.warning("No audio file provided in request")
        return jsonify({"error": "No audio file provided"}), 400
    
    audio_file = request.files['audio']
    if audio_file.filename == '':
        logger.warning("Empty audio filename provided")
        return jsonify({"error": "No audio file selected"}), 400
    
    # Check file size - limiting to 25MB
    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25MB in bytes
    audio_file.seek(0, os.SEEK_END)
    file_size = audio_file.tell()
    audio_file.seek(0)  # Reset file pointer to beginning
    
    logger.info("Received audio file: %s, size: %.2f MB", audio_file.filename, file_size / (1024 * 1024))
    
    if file_size > MAX_FILE_SIZE:
        logger.warning("File too large: %.2f MB (max %.2f MB)", file_size / (1024 * 1024), MAX_FILE_SIZE / (1024 * 1024))
        return jsonify({"error": f"File too large. Maximum size is {MAX_FILE_SIZE / (1024 * 1024)}MB"}), 413
    
    try:
        # Step 1: Upload the audio file to AssemblyAI
        upload_endpoint = "https://api.assemblyai.com/v2/upload"
        
        headers = {
            "authorization": ASSEMBLYAI_API_KEY
        }
        
        # Read the file data
        audio_data = audio_file.read()
        
        logger.info("Uploading audio to AssemblyAI")
        
        # Upload to AssemblyAI
        upload_response = requests.post(
            upload_endpoint,
            headers=headers,
            data=audio_data
        )
        
        if upload_response.status_code != 200:
            logger.error("AssemblyAI upload failed: %s", upload_response.text)
            return jsonify({"error": f"AssemblyAI upload failed: {upload_response.text}"}), 500
        
        upload_url = upload_response.json()["upload_url"]
        logger.info("Audio uploaded successfully to AssemblyAI")
        
        # Step 2: Start the transcription process
        transcript_endpoint = "https://api.assemblyai.com/v2/transcript"
        
        transcript_request = {
            "audio_url": upload_url,
            "language_code": "en"  # You can make this configurable
        }
        
        logger.info("Requesting transcription from AssemblyAI")
        
        transcript_response = requests.post(
            transcript_endpoint,
            json=transcript_request,
            headers=headers
        )
        
        if transcript_response.status_code != 200:
            logger.error("AssemblyAI transcription request failed: %s", transcript_response.text)
            return jsonify({"error": f"AssemblyAI transcription request failed: {transcript_response.text}"}), 500
        
        transcript_id = transcript_response.json()["id"]
        logger.info("Transcription request submitted successfully, ID: %s", transcript_id)
        
        return jsonify({"transcription_id": transcript_id}), 200
    
    except Exception as e:
        logger.error("Error processing audio upload: %s", str(e))
        return jsonify({"error": f"Server error: {str(e)}"}), 500
    
@app.route('/check-transcription/<transcription_id>', methods=['GET'])
@auth_required
def check_transcription(transcription_id):
    username = request.username
    logger.info("Checking transcription %s for user %s", transcription_id, username)
    
    try:
        # Create the endpoint URL with the transcription ID
        endpoint = f"https://api.assemblyai.com/v2/transcript/{transcription_id}"
        
        headers = {
            "authorization": ASSEMBLYAI_API_KEY
        }
        
        # Get the transcription status
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code != 200:
            logger.error("AssemblyAI status check failed: %s", response.text)
            return jsonify({"error": f"AssemblyAI request failed: {response.text}"}), 500
        
        transcript_data = response.json()
        status = transcript_data["status"]
        
        # If the transcription is complete, return the transcript
        if status == "completed":
            text_length = len(transcript_data["text"]) if "text" in transcript_data else 0
            logger.info("Transcription %s completed, length: %d characters", transcription_id, text_length)
            return jsonify({
                "status": "completed",
                "transcript": transcript_data["text"]
            }), 200
        
        # If the transcription failed, return the error
        elif status == "error":
            error_msg = transcript_data.get("error", "Unknown error")
            logger.error("Transcription %s failed: %s", transcription_id, error_msg)
            return jsonify({
                "status": "error",
                "error": error_msg
            }), 500
        
        # If the transcription is still processing, return the status
        else:  # status is "queued" or "processing"
            logger.info("Transcription %s status: %s", transcription_id, status)
            return jsonify({
                "status": status
            }), 200
    
    except Exception as e:
        logger.error("Error checking transcription %s: %s", transcription_id, str(e))
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.post('/process-transcript')
@auth_required
def process_transcript():
    username = request.username
    data = request.get_json()
    transcript = data.get("transcript","")

    if not transcript:
        logger.warning("Empty transcript submitted for processing by user %s", username)
        return jsonify({"error":"transcript field required"}),400
    
    logger.info("Processing transcript for user %s (%d characters)", username, len(transcript))
    
    try:
        summary = summarizeText(transcript)
        logger.info("Transcript processing successful for user %s", username)
        return jsonify({"summary":summary}),200
    except Exception as e:
        logger.error("Error processing transcript for user %s: %s", username, str(e))
        return jsonify({"error": f"Error processing transcript: {str(e)}"}), 500

#random route testing in flask
@app.get('/incrementCount')
def incrementCount():
    count = request.args.get('Count',0)
    count = int(count) + 1  # Convert to int before incrementing
    return jsonify({'Count':count})

# Health check endpoint for monitoring
@app.route('/health', methods=['GET'])
def health_check():
    status = {
        'status': 'healthy',
        'mongodb': False,
        'openai': False,
        'assemblyai': False,
        'youtube_proxy': True  # We're now using hardcoded credentials if env vars aren't set
    }
    
    # Check MongoDB connection
    try:
        # Simple ping to check connection
        myclient.admin.command('ping')
        status['mongodb'] = True
    except Exception as e:
        logger.error("Health check - MongoDB connection failed: %s", str(e))
        status['status'] = 'degraded'
    
    # Simple check for OpenAI API key
    if OPENAI_API_KEY and len(OPENAI_API_KEY) > 10:
        status['openai'] = True
    else:
        logger.error("Health check - OpenAI API key missing or invalid")
        status['status'] = 'degraded'
    
    # Simple check for AssemblyAI API key
    if ASSEMBLYAI_API_KEY and len(ASSEMBLYAI_API_KEY) > 10:
        status['assemblyai'] = True
    else:
        logger.error("Health check - AssemblyAI API key missing or invalid")
        status['status'] = 'degraded'
    
    if status['status'] == 'healthy':
        logger.info("Health check passed")
        return jsonify(status), 200
    else:
        logger.warning("Health check returned degraded status")
        return jsonify(status), 200  # Still return 200 for uptime monitoring

if __name__ == "__main__":
    logger.info("Starting NoteBuddy API server")
    
    # For Render, we need to use the PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    logger.info("Server configured to run on port %d", port)
    app.run(host="0.0.0.0", port=port)