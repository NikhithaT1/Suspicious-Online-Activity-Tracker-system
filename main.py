import sqlite3
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import requests
import datetime
import random
import string
import bcrypt
import uuid
import platform
import json
import time
import psutil
import pyperclip
import hashlib
import socket
import geopy.distance
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
from twilio.rest import Client
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import cv2
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
import numpy as np
import ssl
import hashlib
import random


# Load environment variables
load_dotenv()

# Configuration
LOG_FILE = "login_attempts.log"
IMAGE_DIR = "captured_images"
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
RECIPIENT_EMAILS = os.getenv("RECIPIENT_EMAILS", "").split(",")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
SESSION_TIMEOUT = 30
MIN_GEOLOCATION_VELOCITY_KMH = 500  # Impossible travel threshold in km/h
SUSPICIOUS_PROCESSES = ["wireshark", "fiddler", "burp", "metasploit", "nmap", "john", "hashcat"]

# Cloudinary Configuration
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# Twilio Configuration
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
RECIPIENT_PHONE_NUMBER = os.getenv("RECIPIENT_PHONE_NUMBER")

# Create directories if they don't exist
if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)

# SQLite datetime handlers
def adapt_datetime(dt):
    return dt.isoformat()

def convert_datetime(ts):
    return datetime.datetime.fromisoformat(ts.decode())

sqlite3.register_adapter(datetime.datetime, adapt_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)

# Database Setup with new tables for enhanced security features
def init_db():
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            admin_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES admins (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            fingerprint TEXT,
            location TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            fingerprint TEXT,
            location TEXT,
            velocity FLOAT,
            suspicious_processes TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clipboard_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            content TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keystroke_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timings TEXT NOT NULL,
            model_data TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Insert a default Main Admin if not exists
    cursor.execute("SELECT * FROM admins WHERE role = 'Main Admin'")
    if not cursor.fetchone():
        hashed_password = bcrypt.hashpw("mainadmin123".encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO admins (username, password, role) VALUES (?, ?, ?)",
                      ("mainadmin", hashed_password, "Main Admin"))
    conn.commit()
    conn.close()

init_db()

# Password Hashing Functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# Enhanced Security Functions
def get_browser_fingerprint():
    """Generate a browser fingerprint based on various system attributes"""
    try:
        fingerprint_data = {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "hostname": socket.gethostname(),
            "timezone": time.tzname,
            "language": os.getenv("LANG", "en_US"),
            "user_agent": "Python"
        }
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    except Exception as e:
        print(f"Error generating fingerprint: {e}")
        return "unknown_fingerprint"

def check_geolocation_velocity(previous_location, current_location, time_diff_hours):
    """Check if the geolocation change suggests impossible travel"""
    try:
        if not previous_location or not current_location:
            return False
            
        coords_1 = (previous_location["latitude"], previous_location["longitude"])
        coords_2 = (current_location["latitude"], current_location["longitude"])
        
        distance_km = geopy.distance.distance(coords_1, coords_2).km
        velocity_kmh = distance_km / time_diff_hours
        
        return velocity_kmh > MIN_GEOLOCATION_VELOCITY_KMH
    except Exception as e:
        print(f"Error checking geolocation velocity: {e}")
        return False

def monitor_clipboard(user_id):
    """Monitor clipboard for sensitive data"""
    try:
        current_clipboard = pyperclip.paste()
        if current_clipboard and len(current_clipboard.strip()) > 0:
            conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO clipboard_logs (user_id, content) VALUES (?, ?)",
                         (user_id, current_clipboard[:500]))  # Limit to 500 chars
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Error monitoring clipboard: {e}")

def get_process_list():
    """Get a list of running processes and check for suspicious ones"""
    try:
        suspicious_found = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                proc_name = proc.info['name'].lower()
                for suspicious in SUSPICIOUS_PROCESSES:
                    if suspicious in proc_name:
                        suspicious_found.append(proc.info)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return suspicious_found
    except Exception as e:
        print(f"Error getting process list: {e}")
        return []

def get_user_keystroke_profile(user_id):
    """Retrieve the keystroke profile for a user"""
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("SELECT timings, model_data FROM keystroke_profiles WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        timings = json.loads(result[0])
        model_data = json.loads(result[1]) if result[1] else None
        return timings, model_data
    return None, None

def save_user_keystroke_profile(user_id, timings, model_data=None):
    """Save or update the keystroke profile for a user"""
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    timings_json = json.dumps(timings)
    model_data_json = json.dumps(model_data) if model_data else None
    
    cursor.execute("SELECT 1 FROM keystroke_profiles WHERE user_id = ?", (user_id,))
    if cursor.fetchone():
        cursor.execute("""
            UPDATE keystroke_profiles 
            SET timings = ?, model_data = ?, last_updated = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, (timings_json, model_data_json, user_id))
    else:
        cursor.execute("""
            INSERT INTO keystroke_profiles (user_id, timings, model_data)
            VALUES (?, ?, ?)
        """, (user_id, timings_json, model_data_json))
    
    conn.commit()
    conn.close()

def train_keystroke_model(timings):
    """Train machine learning models for keystroke dynamics"""
    if len(timings) < 10:
        return None, None
    
    X = np.array(timings).reshape(-1, 1)
    
    # Isolation Forest for anomaly detection
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    
    # K-means for clustering
    kmeans = KMeans(n_clusters=2, random_state=42)
    kmeans.fit(X)
    
    # Serialize models
    model_data = {
        'isolation_forest': {
            'offset': -model.offset_,
            'n_estimators': model.n_estimators,
            'max_samples': model.max_samples,
            'contamination': model.contamination,
            'max_features': model.max_features,
            'bootstrap': model.bootstrap,
            'n_features_in_': model.n_features_in_,
            'estimators_features': [ef.tolist() for ef in model.estimators_features_],
            'estimators_samples': [es.tolist() for es in model.estimators_samples_]
        },
        'kmeans': {
            'cluster_centers': kmeans.cluster_centers_.tolist(),
            'n_clusters': kmeans.n_clusters,
            'n_features_in': kmeans.n_features_in_
        }
    }
    
    return model, kmeans, model_data

def analyze_keystroke_pattern(user_id, current_timing):
    """Analyze keystroke timing against user's profile"""
    timings, model_data = get_user_keystroke_profile(user_id)
    if not timings or not model_data:
        return True  # No profile yet, allow access
    
    try:
        # Reconstruct models from saved data
        if model_data['isolation_forest']:
            model = IsolationForest(
                n_estimators=model_data['isolation_forest']['n_estimators'],
                max_samples=model_data['isolation_forest']['max_samples'],
                contamination=model_data['isolation_forest']['contamination'],
                max_features=model_data['isolation_forest']['max_features'],
                bootstrap=model_data['isolation_forest']['bootstrap'],
                random_state=42
            )
            # Normally we'd set the estimator attributes here, but for simplicity we'll just use the offset
            model.offset_ = -model_data['isolation_forest']['offset']
        
        if model_data['kmeans']:
            kmeans = KMeans(
                n_clusters=model_data['kmeans']['n_clusters'],
                random_state=42
            )
            kmeans.cluster_centers_ = np.array(model_data['kmeans']['cluster_centers'])
            kmeans.n_features_in_ = model_data['kmeans']['n_features_in']
        
        X = np.array([current_timing]).reshape(-1, 1)
        
        # Check with Isolation Forest
        is_inlier = model.predict(X)[0] == 1
        
        # Check with K-means (compare to largest cluster)
        cluster = kmeans.predict(X)[0]
        largest_cluster = np.argmax(np.bincount(kmeans.labels_))
        
        return is_inlier and (cluster == largest_cluster)
    except Exception as e:
        print(f"Error analyzing keystroke pattern: {e}")
        return True

# Session Management Functions with enhanced security
def create_session(user_id, username, role):
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    token = str(uuid.uuid4())
    expires_at = datetime.datetime.now() + datetime.timedelta(minutes=SESSION_TIMEOUT)
    fingerprint = get_browser_fingerprint()
    
    # Get location information
    ip_address = get_ip_address()
    location = get_location_details(ip_address)
    location_str = json.dumps(location) if location else "Unknown"
    
    cursor.execute("INSERT INTO sessions (user_id, token, role, expires_at, fingerprint, location) VALUES (?, ?, ?, ?, ?, ?)",
                  (user_id, token, role, expires_at, fingerprint, location_str))
    conn.commit()
    
    cursor.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.datetime.now(),))
    conn.commit()
    conn.close()
    
    return token

def validate_session(token):
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    cursor.execute("SELECT user_id, role, expires_at, fingerprint, location FROM sessions WHERE token = ?", (token,))
    session = cursor.fetchone()
    
    if not session:
        conn.close()
        return None
    
    user_id, role, expires_at, stored_fingerprint, location_str = session
    
    if expires_at < datetime.datetime.now():
        conn.close()
        return None
    
    # Check if browser fingerprint matches
    current_fingerprint = get_browser_fingerprint()
    if current_fingerprint != stored_fingerprint:
        conn.close()
        return None
    
    # Update expiration time
    new_expires_at = datetime.datetime.now() + datetime.timedelta(minutes=SESSION_TIMEOUT)
    cursor.execute("UPDATE sessions SET expires_at = ? WHERE token = ?", (new_expires_at, token))
    conn.commit()
    conn.close()
    
    return {"user_id": user_id, "role": role}

def logout_session(token):
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()

# Function to validate credentials
def validate_credentials(username, password):
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    # Check admins first
    cursor.execute("SELECT id, password, role FROM admins WHERE username = ?", (username,))
    admin_result = cursor.fetchone()
    
    if admin_result:
        admin_id, hashed_password, role = admin_result
        if check_password(hashed_password, password):
            conn.close()
            return {"id": admin_id, "role": role}
    
    # Check users if not found in admins
    cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    user_result = cursor.fetchone()
    
    if user_result:
        user_id, hashed_password = user_result
        if check_password(hashed_password, password):
            conn.close()
            return {"id": user_id, "role": "User"}
    
    conn.close()
    return None

# Enhanced logging functions
def get_location_details(ip_address):
    """Get detailed location information including coordinates"""
    try:
        if ip_address == "Unknown" or ip_address.startswith(("192.168.", "10.", "172.16.")):
            return None

        response = requests.get(f"https://ipinfo.io/{ip_address}?token={IPINFO_TOKEN}", timeout=5)
        data = response.json()
        
        loc = data.get("loc", "").split(",")
        if len(loc) == 2:
            latitude, longitude = map(float, loc)
        else:
            latitude, longitude = None, None
            
        return {
            "ip": ip_address,
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "latitude": latitude,
            "longitude": longitude,
            "org": data.get("org", "Unknown")
        }
    except Exception as e:
        print(f"Failed to fetch location details: {e}")
        return None

def log_attempt(username, ip_address, status):
    timestamp = datetime.datetime.now()
    location = get_location_details(ip_address)
    location_str = json.dumps(location) if location else "Unknown"
    fingerprint = get_browser_fingerprint()
    suspicious_processes = get_process_list()
    processes_str = json.dumps(suspicious_processes) if suspicious_processes else "[]"
    
    # Calculate geolocation velocity if possible
    velocity = None
    if location and "latitude" in location and "longitude" in location:
        conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = conn.cursor()
        
        # Get previous successful login for this user
        cursor.execute("""
            SELECT timestamp, location FROM login_attempts 
            WHERE username = ? AND status = 'Success' 
            ORDER BY timestamp DESC LIMIT 1
        """, (username,))
        prev_attempt = cursor.fetchone()
        conn.close()
        
        if prev_attempt:
            prev_time, prev_loc_str = prev_attempt
            try:
                prev_loc = json.loads(prev_loc_str) if prev_loc_str != "Unknown" else None
                if prev_loc and "latitude" in prev_loc and "longitude" in prev_loc:
                    time_diff_hours = (timestamp - prev_time).total_seconds() / 3600
                    if time_diff_hours > 0:  # Avoid division by zero
                        velocity = check_geolocation_velocity(prev_loc, location, time_diff_hours)
            except json.JSONDecodeError:
                pass
    
    # Log to file
    log_entry = (
        f"{timestamp} - Username: {username}, IP: {ip_address}, "
        f"Location: {location_str}, Fingerprint: {fingerprint}, "
        f"Status: {status}, Velocity: {velocity}, "
        f"Suspicious Processes: {len(suspicious_processes)}\n"
    )
    
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)
    
    # Log to database
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_attempts 
        (username, ip_address, status, fingerprint, location, velocity, suspicious_processes) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, ip_address, status, fingerprint, location_str, velocity, processes_str))
    conn.commit()
    conn.close()

# Function to get login attempt statistics
def get_login_stats():
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    # Get total attempts
    cursor.execute("SELECT COUNT(*) FROM login_attempts")
    total_attempts = cursor.fetchone()[0]
    
    # Get success/failure counts
    cursor.execute("SELECT status, COUNT(*) FROM login_attempts GROUP BY status")
    status_counts = cursor.fetchall()
    
    # Get recent attempts
    cursor.execute("""
        SELECT username, ip_address, status, timestamp 
        FROM login_attempts 
        ORDER BY timestamp DESC 
        LIMIT 10
    """)
    recent_attempts = cursor.fetchall()
    
    conn.close()
    
    stats = {
        "total_attempts": total_attempts,
        "status_counts": dict(status_counts),
        "recent_attempts": recent_attempts
    }
    
    return stats

def get_security_analytics():
    """Get security analytics data including anomaly detection results"""
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    # Get fingerprint anomalies
    cursor.execute("""
        SELECT COUNT(*) FROM login_attempts a1
        WHERE EXISTS (
            SELECT 1 FROM login_attempts a2 
            WHERE a1.username = a2.username 
            AND a1.fingerprint != a2.fingerprint
            AND a2.status = 'Success'
        )
        AND a1.status = 'Success'
    """)
    fingerprint_anomalies = cursor.fetchone()[0]
    
    # Get velocity anomalies
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE velocity = 1")
    velocity_anomalies = cursor.fetchone()[0]
    
    # Get suspicious process incidents
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE json_array_length(suspicious_processes) > 0")
    process_anomalies = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "anomalies": {
            "fingerprint": fingerprint_anomalies,
            "velocity": velocity_anomalies,
            "suspicious_processes": process_anomalies
        }
    }

def get_user_security_analytics(username):
    """Get security analytics specific to a user"""
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    # Get failed login attempts
    cursor.execute("""
        SELECT COUNT(*) FROM login_attempts 
        WHERE username = ? AND status != 'Success'
    """, (username,))
    failed_attempts = cursor.fetchone()[0]
    
    # Get fingerprint changes
    cursor.execute("""
        SELECT COUNT(DISTINCT fingerprint) - 1 FROM login_attempts 
        WHERE username = ? AND status = 'Success'
    """, (username,))
    fingerprint_changes = cursor.fetchone()[0] or 0
    
    # Get impossible travel events
    cursor.execute("""
        SELECT COUNT(*) FROM login_attempts 
        WHERE username = ? AND velocity = 1
    """, (username,))
    impossible_travel = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "failed_attempts": failed_attempts,
        "fingerprint_changes": fingerprint_changes,
        "impossible_travel": impossible_travel
    }

# Function to get public IP address
def get_ip_address():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        data = response.json()
        return data["ip"]
    except Exception as e:
        print(f"Failed to fetch public IP address: {e}")
        return "Unknown"

# Function to send email with image attachment and location
def send_email(image_path, ip_address):
    try:
        location = get_location_details(ip_address)
        sender_email = EMAIL_ADDRESS
        sender_password = EMAIL_PASSWORD
        recipient_emails = RECIPIENT_EMAILS

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = ", ".join(recipient_emails)
        msg['Subject'] = "Suspicious Login Attempt Detected"

        body = f"""
A suspicious login attempt was detected from:
- IP: {ip_address}
- Location: {location.get('city', 'Unknown')}, {location.get('region', 'Unknown')}, {location.get('country', 'Unknown')}
- Organization: {location.get('org', 'Unknown')}
- Coordinates: {location.get('latitude', 'N/A')}, {location.get('longitude', 'N/A')}

Additional Security Information:
- Browser Fingerprint: {get_browser_fingerprint()}
- Suspicious Processes Running: {len(get_process_list())}
"""
        msg.attach(MIMEText(body, 'plain'))

        with open(image_path, 'rb') as f:
            img_data = f.read()
            image = MIMEImage(img_data, name=os.path.basename(image_path))
            msg.attach(image)

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_emails, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to generate a random CAPTCHA image
def generate_captcha_image():
    width, height = 200, 80
    image = Image.new('RGB', (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)

    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except IOError:
        font = ImageFont.load_default()

    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    for i, char in enumerate(captcha_text):
        draw.text((10 + i * 30, 10), char, font=font, fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))

    for _ in range(10):
        draw.line((random.randint(0, width), random.randint(0, height), 
                 (random.randint(0, width), random.randint(0, height))), 
                 fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))

    for _ in range(100):
        draw.point((random.randint(0, width), random.randint(0, height)), 
                  fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))

    image = image.filter(ImageFilter.BLUR)
    image_path = os.path.join(IMAGE_DIR, "captcha.png")
    image.save(image_path)

    return captcha_text, image_path

# Function to capture image
def capture_image():
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    if ret:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        image_path = os.path.join(IMAGE_DIR, f"captured_{timestamp}.jpg")
        cv2.imwrite(image_path, frame)
        cap.release()
        return image_path
    cap.release()
    return None

# Function to upload image to Cloudinary
def upload_to_cloudinary(image_path):
    try:
        response = cloudinary.uploader.upload(image_path)
        return response["secure_url"]
    except Exception as e:
        print(f"Failed to upload image to Cloudinary: {e}")
        return None

# Function to send SMS with Twilio
def send_sms(message):
    try:
        if len(message) > 160:
            message = message[:157] + "..."

        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=RECIPIENT_PHONE_NUMBER
        )
        print(f"SMS sent! Message SID: {message.sid}")
    except Exception as e:
        print(f"Failed to send SMS: {e}")

# Create SSL context for secure connections
def create_ssl_context():
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context

# Demo Data Functions
def load_demo_data():
    """Load demo data with RANDOM anomaly counts for fingerprints, travel, and processes"""
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    # Clear existing demo data
    cursor.execute("DELETE FROM login_attempts WHERE username LIKE 'demo_%'")
    
    # Demo users
    demo_users = ['demo_admin', 'demo_user1', 'demo_user2']
    
    # Generate RANDOM counts for anomalies (e.g., between 5-30)
    fingerprint_count = random.randint(5, 30)
    travel_count = random.randint(5, 30)
    process_count = random.randint(5, 30)

    # Debug print (optional)
    print(f"Generating demo data: Fingerprint={fingerprint_count}, Travel={travel_count}, Process={process_count}")

    # --- 1. Generate normal logins (baseline) ---
    for i in range(30):  # 30 normal login attempts
        username = random.choice(demo_users)
        ip_address = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        status = "Success" if random.random() < 0.8 else "Failed"
        timestamp = datetime.datetime.now() - datetime.timedelta(days=random.randint(0,30))
        
        # Consistent fingerprint for normal logins
        fingerprint = hashlib.sha256(f"{username}_normal_{i}".encode()).hexdigest()
        
        # Random location
        locations = [
            {"city": "New York", "region": "NY", "country": "US", "latitude": 40.7128, "longitude": -74.0060},
            {"city": "London", "region": "England", "country": "UK", "latitude": 51.5074, "longitude": -0.1278}
        ]
        location = random.choice(locations)
        
        cursor.execute("""
            INSERT INTO login_attempts 
            (username, ip_address, status, timestamp, fingerprint, location, velocity, suspicious_processes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, ip_address, status, timestamp, fingerprint, json.dumps(location), 0, "[]"))

    # --- 2. Generate FINGERPRINT anomalies (random count) ---
    for i in range(fingerprint_count):
        username = random.choice(demo_users)
        ip_address = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        status = "Success"
        timestamp = datetime.datetime.now() - datetime.timedelta(days=random.randint(0,30))
        
        # Different fingerprint (explicit anomaly)
        fingerprint = hashlib.sha256(f"{username}_anomaly_{i}".encode()).hexdigest()
        
        # Use same location as normal logins
        cursor.execute("SELECT location FROM login_attempts WHERE username = ? LIMIT 1", (username,))
        result = cursor.fetchone()
        location = json.loads(result[0]) if result else random.choice(locations)
        
        cursor.execute("""
            INSERT INTO login_attempts 
            (username, ip_address, status, timestamp, fingerprint, location, velocity, suspicious_processes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, ip_address, status, timestamp, fingerprint, json.dumps(location), 0, "[]"))

    # --- 3. Generate IMPOSSIBLE TRAVEL anomalies (random count) ---
    for i in range(travel_count):
        username = random.choice(demo_users)
        ip_address = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        status = "Success"
        timestamp = datetime.datetime.now() - datetime.timedelta(hours=random.randint(1,5))
        
        # Same fingerprint as normal
        fingerprint = hashlib.sha256(f"{username}_normal_0".encode()).hexdigest()
        
        # Faraway location (trigger velocity check)
        far_locations = [
            {"city": "Tokyo", "region": "Kanto", "country": "JP", "latitude": 35.6762, "longitude": 139.6503},
            {"city": "Sydney", "region": "NSW", "country": "AU", "latitude": -33.8688, "longitude": 151.2093}
        ]
        location = random.choice(far_locations)
        
        cursor.execute("""
            INSERT INTO login_attempts 
            (username, ip_address, status, timestamp, fingerprint, location, velocity, suspicious_processes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, ip_address, status, timestamp, fingerprint, json.dumps(location), 1, "[]"))

    # --- 4. Generate SUSPICIOUS PROCESS anomalies (random count) ---
    for i in range(process_count):
        username = random.choice(demo_users)
        ip_address = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        status = "Success" if random.random() < 0.5 else "Failed"
        timestamp = datetime.datetime.now() - datetime.timedelta(days=random.randint(0,30))
        
        # Random fingerprint
        fingerprint = hashlib.sha256(f"{username}_process_{i}".encode()).hexdigest()
        
        # Random location
        location = random.choice([
            {"city": "New York", "region": "NY", "country": "US", "latitude": 40.7128, "longitude": -74.0060},
            {"city": "London", "region": "England", "country": "UK", "latitude": 51.5074, "longitude": -0.1278}
        ])
        
        # Random suspicious process
        processes = [{"name": random.choice(SUSPICIOUS_PROCESSES)}]
        
        cursor.execute("""
            INSERT INTO login_attempts 
            (username, ip_address, status, timestamp, fingerprint, location, velocity, suspicious_processes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, ip_address, status, timestamp, fingerprint, json.dumps(location), 0, json.dumps(processes)))

    conn.commit()
    conn.close()
    return True

def reset_demo_data():
    """Reset demo data by removing all demo records"""
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_attempts WHERE username LIKE 'demo_%'")
    conn.commit()
    conn.close()
    return True

def clear_all_data():
    """Clear all data (except admin accounts)"""
    conn = sqlite3.connect("user_management.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    
    # Clear all data except admin accounts
    cursor.execute("DELETE FROM login_attempts")
    cursor.execute("DELETE FROM sessions")
    cursor.execute("DELETE FROM clipboard_logs")
    cursor.execute("DELETE FROM keystroke_profiles")
    cursor.execute("DELETE FROM users")
    
    # Keep only the main admin
    cursor.execute("DELETE FROM admins WHERE username != 'mainadmin'")
    
    conn.commit()
    conn.close()
    return True