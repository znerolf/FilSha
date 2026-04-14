from imports import *
from dotenv import load_dotenv
from datetime import timedelta

app = Flask(__name__, static_folder='static')
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['UPLOAD_FOLDER'] = 'uploads'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True

session_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
os.makedirs(session_dir, exist_ok=True)
app.config['SESSION_FILE_DIR'] = session_dir

Session(app)

# Initialize Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*")
upload_progress = {}

#admin credentials
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

#Flask-Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Database connector
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mail = Mail(app)

# Ensure database schema is up to date
def ensure_db_schema():
    conn = mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )
    cursor = conn.cursor()
    
    try:
        # Check if is_read column exists in user_inquiries table
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = %s 
            AND TABLE_NAME = 'user_inquiries' 
            AND COLUMN_NAME = 'is_read'
        """, (app.config['MYSQL_DB'],))
        
        if cursor.fetchone()[0] == 0:
            # Add is_read column if it doesn't exist
            cursor.execute("ALTER TABLE user_inquiries ADD COLUMN is_read TINYINT(1) DEFAULT 0 AFTER status")
            conn.commit()
            print("Added is_read column to user_inquiries table")
            
        # Check if receiver_id column exists in threats table
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = %s 
            AND TABLE_NAME = 'threats' 
            AND COLUMN_NAME = 'receiver_id'
        """, (app.config['MYSQL_DB'],))
        
        if cursor.fetchone()[0] == 0:
            # Add receiver_id column if it doesn't exist
            cursor.execute("ALTER TABLE threats ADD COLUMN receiver_id INT NULL AFTER owner_id")
            conn.commit()
            print("Added receiver_id column to threats table")
    except Exception as e:
        print(f"Error ensuring database schema: {e}")
    finally:
        cursor.close()
        conn.close()

# Initialize database schema
ensure_db_schema()

# Function to check if a file has an allowed extension
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Request interceptor to detect SQL injection and XSS attacks
@app.before_request
def detect_threats():
    # Skip for static files
    if request.path.startswith('/static'):
        return
    
    # Get user ID if logged in
    user_id = session.get('user_id', 0)
    
    # Get client IP address
    if request.headers.getlist("X-Forwarded-For"):
        ip_address = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip_address = request.remote_addr
    
    # Check for suspicious IP
    if is_suspicious_ip(ip_address):
        log_threat(
            owner_id=user_id,
            threat_type='SUSPICIOUS_IP',
            ip_address=ip_address,
            request_path=request.path
        )
    
    # Check form data for SQL injection and XSS
    if request.form:
        for key, value in request.form.items():
            # Check for SQL injection
            if detect_sql_injection(value):
                log_threat(
                    owner_id=user_id,
                    threat_type='SQL_INJECTION',
                    payload=value,
                    ip_address=ip_address,
                    request_path=request.path
                )
            
            # Check for XSS
            if detect_xss(value):
                log_threat(
                    owner_id=user_id,
                    threat_type='XSS',
                    payload=value,
                    ip_address=ip_address,
                    request_path=request.path
                )
    
    # Check URL parameters for SQL injection and XSS
    if request.args:
        for key, value in request.args.items():
            # Check for SQL injection
            if detect_sql_injection(value):
                log_threat(
                    owner_id=user_id,
                    threat_type='SQL_INJECTION',
                    payload=value,
                    ip_address=ip_address,
                    request_path=request.path
                )
            
            # Check for XSS
            if detect_xss(value):
                log_threat(
                    owner_id=user_id,
                    threat_type='XSS',
                    payload=value,
                    ip_address=ip_address,
                    request_path=request.path
                )


@app.template_filter('time_ago')
def time_ago_filter(timestamp):
    now = datetime.now()
    delta = now - timestamp
    if delta.days > 0:
        return f"{delta.days} days ago"
    elif delta.seconds > 3600:
        return f"{delta.seconds // 3600} hours ago"
    elif delta.seconds > 60:
        return f"{delta.seconds // 60} minutes ago"
    else:
        return "Just now"

@app.context_processor
#user ratings
def inject_notifications():
    if 'user_id' in session:
        notifications = get_user_notifications(session['user_id'], 5)
        unread_count = get_unread_notification_count(session['user_id'])
        return {
            'user_notifications': notifications,
            'unread_notification_count': unread_count,
            'get_notification_icon': get_notification_icon,
            'has_user_rated': lambda user_id: has_user_rated(user_id)
        }
    return {
        'user_notifications': [],
        'unread_notification_count': 0,
        'get_notification_icon': get_notification_icon,
        'has_user_rated': lambda user_id: False
    }
###############################################################################

# Initialize the monitor with Socket.IO
system_monitor = SystemMonitor(socketio=socketio)

def get_db_connection():
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )

#for total gb file uploaded by user 
def calculate_total_uploaded_size(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename FROM files WHERE owner_id = %s", (user_id,))
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    total_size = 0
    for file in files:
        file_path = os.path.join('uploads', file[0])
        if os.path.exists(file_path):
            total_size += os.path.getsize(file_path)
    return total_size / (1024 * 1024 * 1024)  # Convert bytes to GB

def get_expiration_time(expiration_duration):
    if expiration_duration == '1h':
        return datetime.now() + timedelta(hours=1)
    elif expiration_duration == '1d':
        return datetime.now() + timedelta(days=1)
    elif expiration_duration == '1w':
        return datetime.now() + timedelta(weeks=1)
    else:
        return None
############################# FOR total virus detected ######################################
#for user
# SQL Injection patterns to detect
SQL_INJECTION_PATTERNS = [
    r"'\s*OR\s*'\s*'\s*=\s*'", # 'OR''='
    r"'\s*OR\s*[0-9]\s*=\s*[0-9]", # 'OR 1=1
    r"'\s*OR\s*'[^']*'\s*=\s*'[^']*'", # 'OR 'a'='a'
    r"--", # SQL comment
    r";\s*DROP\s+TABLE", # DROP TABLE
    r";\s*DELETE\s+FROM", # DELETE FROM
    r"UNION\s+SELECT", # UNION SELECT
    r"UNION\s+ALL\s+SELECT", # UNION ALL SELECT
    r"INSERT\s+INTO", # INSERT INTO
    r"UPDATE\s+.+\s+SET", # UPDATE SET
    r"SELECT\s+.+\s+FROM", # SELECT FROM
    r"SLEEP\s*\(\s*[0-9]+\s*\)", # SLEEP()
    r"BENCHMARK\s*\(", # BENCHMARK()
    r"WAITFOR\s+DELAY", # WAITFOR DELAY
    r"INFORMATION_SCHEMA", # INFORMATION_SCHEMA
    r"LOAD_FILE\s*\(", # LOAD_FILE()
    r"INTO\s+OUTFILE", # INTO OUTFILE
    r"INTO\s+DUMPFILE" # INTO DUMPFILE
]

# XSS patterns to detect
XSS_PATTERNS = [
    r"<script[^>]*>[^<]*</script>", # <script>...</script>
    r"javascript:\s*", # javascript:
    r"<img[^>]*src\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*onerror\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*>", # <img src=x onerror=...>
    r"<iframe[^>]*src\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*>", # <iframe src=...>
    r"<svg[^>]*onload\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*>", # <svg onload=...>
    r"alert\s*\(", # alert()
    r"eval\s*\(", # eval()
    r"document\.cookie", # document.cookie
    r"document\.location", # document.location
    r"document\.write", # document.write
    r"onmouseover\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*>", # onmouseover=...
    r"onclick\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*>", # onclick=...
    r"onload\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*>", # onload=...
    r"onerror\s*=\s*['\"]?[^'\"\s>]*['\"]?[^>]*>" # onerror=...
]

# Function to detect SQL injection
def detect_sql_injection(input_string):
    if not input_string or not isinstance(input_string, str):
        return False
    
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False

# Function to detect XSS attacks
def detect_xss(input_string):
    if not input_string or not isinstance(input_string, str):
        return False
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False

# Function to check if an IP is suspicious
def is_suspicious_ip(ip_address):
    # Check if the IP is in the suspicious IP list
    try:
        with open('hashes/sus_ip.txt', 'r') as f:
            suspicious_ips = [line.strip() for line in f.readlines()]
        
        return ip_address in suspicious_ips
    except Exception as e:
        print(f"Error checking suspicious IP: {e}")
        return False
    
    # Example of a simple check (uncomment and customize as needed):
    # suspicious_ips = ['192.168.1.100', '10.0.0.1']
    # return ip_address in suspicious_ips
    
    return False

def log_threat(file_id=None, file_name=None, md5_hash=None, sha1_hash=None, sha256_hash=None, owner_id=None, threat_type=None, payload=None, ip_address=None, request_path=None, receiver_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Log file hash threats
        if threat_type == 'HASH' or (md5_hash or sha1_hash or sha256_hash):
            # Check MD5 hash
            if md5_hash in SUSPICIOUS_HASHES['md5']:
                cursor.execute("""
                    INSERT INTO threats (file_id, file_name, threat_type, hash_type, file_hash, owner_id, receiver_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (file_id, file_name, 'HASH', 'MD5', md5_hash, owner_id, receiver_id))
            
            # Check SHA1 hash
            if sha1_hash in SUSPICIOUS_HASHES['sha1']:
                cursor.execute("""
                    INSERT INTO threats (file_id, file_name, threat_type, hash_type, file_hash, owner_id, receiver_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (file_id, file_name, 'HASH', 'SHA1', sha1_hash, owner_id, receiver_id))
            
            # Check SHA256 hash
            if sha256_hash in SUSPICIOUS_HASHES['sha256']:
                cursor.execute("""
                    INSERT INTO threats (file_id, file_name, threat_type, hash_type, file_hash, owner_id, receiver_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (file_id, file_name, 'HASH', 'SHA256', sha256_hash, owner_id, receiver_id))
            
            # Notify receiver if a threat was detected and receiver_id is provided
            if receiver_id:
                from utils.notification_utils import create_notification
                title = "Threat Detected"
                message = f"A file '{file_name}' shared with you contained a potential threat and was blocked."
                create_notification(receiver_id, 'threat_detected', title, message, file_id)
        
        # Log SQL injection threats
        elif threat_type == 'SQL_INJECTION':
            cursor.execute("""
                INSERT INTO threats (threat_type, payload, ip_address, request_path, owner_id, receiver_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ('SQL_INJECTION', payload, ip_address, request_path, owner_id, receiver_id))
        
        # Log XSS threats
        elif threat_type == 'XSS':
            cursor.execute("""
                INSERT INTO threats (threat_type, payload, ip_address, request_path, owner_id, receiver_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ('XSS', payload, ip_address, request_path, owner_id, receiver_id))
        
        # Log suspicious IP threats
        elif threat_type == 'SUSPICIOUS_IP':
            cursor.execute("""
                INSERT INTO threats (threat_type, ip_address, request_path, owner_id, receiver_id)
                VALUES (%s, %s, %s, %s, %s)
            """, ('SUSPICIOUS_IP', ip_address, request_path, owner_id, receiver_id))
            
        conn.commit()
    except Exception as e:
        print(f"Error logging threat: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def get_user_threats(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.*, 
               u1.username as owner_username,
               u2.username as receiver_username 
        FROM threats t
        LEFT JOIN users u1 ON t.owner_id = u1.id
        LEFT JOIN users u2 ON t.receiver_id = u2.id
        WHERE t.owner_id = %s OR t.receiver_id = %s
        ORDER BY t.detected_at DESC
    """, (user_id, user_id))
    threats = cursor.fetchall()
    cursor.close()
    conn.close()
    return threats

def get_all_threats():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.*, 
               u1.username as owner_username,
               u2.username as receiver_username 
        FROM threats t
        LEFT JOIN users u1 ON t.owner_id = u1.id
        LEFT JOIN users u2 ON t.receiver_id = u2.id
        ORDER BY t.detected_at DESC
    """)
    threats = cursor.fetchall()
    cursor.close()
    conn.close()
    return threats

def get_threat_statistics():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get counts by threat type
    cursor.execute("""
        SELECT threat_type, COUNT(*) as count
        FROM threats
        GROUP BY threat_type
    """)
    threat_counts = {row['threat_type']: row['count'] for row in cursor.fetchall()}
    
    # Get recent threats (last 24 hours)
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM threats
        WHERE detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    """)
    recent_threats = cursor.fetchone()['count']
    
    # Get unique IPs with threats
    cursor.execute("""
        SELECT COUNT(DISTINCT ip_address) as count
        FROM threats
        WHERE ip_address IS NOT NULL
    """)
    unique_ips = cursor.fetchone()['count']
    
    cursor.close()
    conn.close()
    
    return {
        'hash_threats': threat_counts.get('HASH', 0),
        'sql_injection_threats': threat_counts.get('SQL_INJECTION', 0),
        'xss_threats': threat_counts.get('XSS', 0),
        'suspicious_ip_threats': threat_counts.get('SUSPICIOUS_IP', 0),
        'total_threats': sum(threat_counts.values()) if threat_counts else 0,
        'recent_threats': recent_threats,
        'unique_ips': unique_ips
    }


def calculate_total_viruses_detected(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM threats WHERE owner_id = %s", (user_id,))
    total_viruses = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return total_viruses

def calculate_total_viruses_detected_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM threats")
    total_viruses = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return total_viruses

############################## file quota and limit size upload ###############################
def calculate_file_size_breakdown(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT size, filename FROM files WHERE owner_id = %s", (user_id,))
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    # Initialize sizes in GB and counts
    small_gb = 0.0  # Files < 100MB
    medium_gb = 0.0  # 100MB ≤ Files < 1GB
    small_count = 0
    medium_count = 0
    total_count = len(files)
    
    # Extension statistics
    extension_counts = {}
    extension_sizes = {}
    
    for file in files:
        size_bytes = file['size']
        filename = file['filename']
        size_gb = size_bytes / (1024 ** 3)  # Convert bytes to GB
        
        # Get file extension
        extension = os.path.splitext(filename)[1].lower() if '.' in filename else 'unknown'
        
        # Update extension statistics
        if extension not in extension_counts:
            extension_counts[extension] = 0
            extension_sizes[extension] = 0
        extension_counts[extension] += 1
        extension_sizes[extension] += size_bytes
        
        # Update size categories
        if size_gb < 0.1:  # 100MB = 0.1GB
            small_gb += size_gb
            small_count += 1
        else:  # 100MB ≤ Files
            medium_gb += size_gb
            medium_count += 1
    
    # Get top 5 extensions by count
    top_extensions = sorted(extension_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_extensions_data = [
        {
            'extension': ext if ext else 'unknown',
            'count': count,
            'size_mb': round(extension_sizes[ext] / (1024 * 1024), 2)
        } for ext, count in top_extensions
    ]
    
    return {
        'small_gb': round(small_gb, 2),
        'medium_gb': round(medium_gb, 2),
        'small_count': small_count,
        'medium_count': medium_count,
        'total_count': total_count,
        'top_extensions': top_extensions_data
    }
    
#function for the user ratings 
# Add this function to app.py to check if user has already rated
def has_user_rated(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM user_ratings WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result is not None

# Add this function to save user rating
def save_user_rating(user_id, rating, comment=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_ratings (user_id, rating, comment) 
            VALUES (%s, %s, %s)
        """, (user_id, rating, comment))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving rating: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

############################## ADMIN FUNCTIONALITY ###########################################
@app.route('/api/user_ip_info/<int:user_id>')
def get_user_ip_info(user_id):
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get the last login IP for the user
    cursor.execute("SELECT last_login_ip FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not user or not user.get('last_login_ip'):
        return jsonify({'error': 'No IP information available'}), 404
    
    ip_address = user['last_login_ip']
    
    try:
        # Use IPQuery API to get detailed IP information
        response = requests.get(f"https://api.ipquery.io/{ip_address}")
        if response.status_code == 200:
            ip_data = response.json()
            
            # Get user agent information from request headers
            user_agent = request.headers.get('User-Agent', 'Unknown')
            
            # Parse user agent to get browser and OS info
            browser = "Unknown"
            os = "Unknown"
            device_type = "Unknown"
            
            if 'Chrome' in user_agent:
                browser = "Chrome"
            elif 'Firefox' in user_agent:
                browser = "Firefox"
            elif 'Safari' in user_agent:
                browser = "Safari"
            elif 'Edge' in user_agent:
                browser = "Edge"
            elif 'Opera' in user_agent:
                browser = "Opera"
            elif 'MSIE' in user_agent or 'Trident' in user_agent:
                browser = "Internet Explorer"
            
            if 'Windows' in user_agent:
                os = "Windows"
            elif 'Macintosh' in user_agent:
                os = "Mac OS"
            elif 'Linux' in user_agent:
                os = "Linux"
            elif 'Android' in user_agent:
                os = "Android"
                device_type = "Mobile"
            elif 'iPhone' in user_agent or 'iPad' in user_agent:
                os = "iOS"
                device_type = "Mobile"
            
            if not device_type == "Mobile":
                if 'Mobile' in user_agent:
                    device_type = "Mobile"
                elif 'Tablet' in user_agent:
                    device_type = "Tablet"
                else:
                    device_type = "Desktop"
            
            # Format the response with additional device info
            return jsonify({
                'ip': ip_data.get('ip'),
                'isp': {
                    'asn': ip_data.get('isp', {}).get('asn', ''),
                    'org': ip_data.get('isp', {}).get('org', ''),
                    'isp': ip_data.get('isp', {}).get('isp', '')
                },
                'location': {
                    'country': ip_data.get('location', {}).get('country', ''),
                    'city': ip_data.get('location', {}).get('city', ''),
                    'state': ip_data.get('location', {}).get('state', ''),
                    'zipcode': ip_data.get('location', {}).get('zipcode', ''),
                    'latitude': ip_data.get('location', {}).get('latitude', ''),
                    'longitude': ip_data.get('location', {}).get('longitude', ''),
                    'timezone': ip_data.get('location', {}).get('timezone', ''),
                    'localtime': ip_data.get('location', {}).get('localtime', '')
                },
                'risk': {
                    'is_mobile': ip_data.get('risk', {}).get('is_mobile', False),
                    'is_vpn': ip_data.get('risk', {}).get('is_vpn', False),
                    'is_tor': ip_data.get('risk', {}).get('is_tor', False),
                    'is_proxy': ip_data.get('risk', {}).get('is_proxy', False),
                    'is_datacenter': ip_data.get('risk', {}).get('is_datacenter', False),
                    'risk_score': ip_data.get('risk', {}).get('risk_score', 0)
                },
                'device': {
                    'user_agent': user_agent,
                    'browser': browser,
                    'os': os,
                    'type': device_type
                }
            })
        else:
            return jsonify({'error': 'Failed to fetch IP info from IPQuery'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
def get_public_ip_info():
    try:
        # Get the IP from request headers (works behind proxies)
        if request.headers.getlist("X-Forwarded-For"):
            ip_address = request.headers.getlist("X-Forwarded-For")[0]
        else:
            ip_address = request.remote_addr
        
        # Check if the IP is suspicious and user is logged in
        if current_user.is_authenticated and is_suspicious_ip(ip_address):
            # Store user ID before logout for logging
            user_id = current_user.id
            # Force logout
            logout_user()
            flash('Your session has been terminated due to suspicious IP activity.', 'danger')
            # Log the suspicious activity
            log_activity(user_id, 'forced_logout', f'Forced logout due to suspicious IP: {ip_address}')
            # Return a special response that indicates redirection is needed
            return {"redirect": True, "url": url_for('login')}
        
        # If we got an IP, fetch additional info from IPQuery
        if ip_address and ip_address != '127.0.0.1':
            response = requests.get(f"https://api.ipquery.io/{ip_address}")
            if response.status_code == 200:
                return response.json()
        
        return {"ip": ip_address if ip_address else "Unknown"}
    except Exception as e:
        print(f"Error getting public IP: {e}")
        return {"error": str(e)}



#total of file size
def generate_username(first_name, last_name):
    # Replace spaces in the first name with underscores
    first_name_cleaned = first_name.replace(" ", "_").lower()
    last_name_cleaned = last_name.lower()
    
    # Generate the base username
    base_username = f"{first_name_cleaned}.{last_name_cleaned}"
    username = base_username
    counter = 1

    conn = get_db_connection()
    cursor = conn.cursor()
    while True:
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if not cursor.fetchone():
            break
        username = f"{base_username}{counter}"
        counter += 1
    cursor.close()
    conn.close()

    return username

def generate_password():
    # Generate a random password with 8 characters
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(8))

def calculate_total_uploaded_size_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT owner_id, filename FROM files")
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    total_size = 0
    for file in files:
        file_path = os.path.join('uploads', file[1])
        if os.path.exists(file_path):
            total_size += os.path.getsize(file_path)
    return total_size / (1024 * 1024 * 1024)  # Convert bytes to GB


# total of users
def get_user_statistics():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch total number of users
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    # Fetch total number of barangay captains
    cursor.execute("SELECT COUNT(*) FROM brgycaptain")
    total_brgycaptain = cursor.fetchone()[0]

    # Fetch total number of government positions
    cursor.execute("SELECT COUNT(*) FROM government_position")
    total_government_position = cursor.fetchone()[0]

    # Fetch total number of municipal employees
    cursor.execute("SELECT COUNT(*) FROM employee")
    total_employee = cursor.fetchone()[0]
    
    # Get active users count (users active in the last 5 minutes)
    active_users = 0
    current_time = datetime.now()
    for user_id, last_active in user_last_activity.items():
        time_diff = (current_time - last_active).total_seconds()
        if time_diff < 300:  # 5 minutes = 300 seconds
            active_users += 1

    cursor.close()
    conn.close()

    return {
        'total_users': total_users,
        'total_brgycaptain': total_brgycaptain,
        'total_government_position': total_government_position,
        'total_employee': total_employee,
        'active_users': active_users
    }

# Count file uploads from activity log
def count_file_uploads():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM activity_log WHERE action = 'file_upload'")
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count

# Count file downloads from activity log
def count_file_downloads():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM activity_log WHERE action = 'file_download'")
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count
    
#activity log
def log_activity(user_id, action, description=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO activity_log (user_id, action, description)
        VALUES (%s, %s, %s)
    """, (user_id, action, description))
    conn.commit()
    cursor.close()
    conn.close()

def get_users_with_details():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT 
                u.id, 
                u.username, 
                u.role, 
                u.profile_picture,
                CONCAT(
                    COALESCE(b.first_name, g.first_name, e.first_name, ''), ' ',
                    COALESCE(b.last_name, g.last_name, e.last_name, '')
                ) AS full_name,
                COALESCE(b.email, g.email, e.email) AS email,
                COALESCE(b.contact_number, g.contact_number, e.contact_number) AS contact_number,
                COALESCE(b.gender, g.gender, e.gender) AS gender,
                COALESCE(b.age, g.age, e.age) AS age,
                COALESCE(b.position, g.government_position, e.position) AS position,
                COALESCE(b.barangay, 'N/A') AS barangay,
                COALESCE(SUM(f.size) / (1024 * 1024 * 1024), 0) AS total_uploaded_size
            FROM users u
            LEFT JOIN brgycaptain b ON u.id = b.user_id
            LEFT JOIN government_position g ON u.id = g.user_id
            LEFT JOIN employee e ON u.id = e.user_id
            LEFT JOIN files f ON u.id = f.owner_id
            GROUP BY u.id
        """)
        users = cursor.fetchall()
        return users
    except Exception as e:
        print(f"Error fetching user details: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

###############################################################################
def delete_expired_files():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch expired files
    cursor.execute("SELECT id, filename FROM files WHERE expiration_time IS NOT NULL AND expiration_time <= NOW()")
    expired_files = cursor.fetchall()

    for file_id, filename in expired_files:
        # Delete the file from the filesystem
        file_path = os.path.join('uploads', filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete the file record from the database
        cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
        conn.commit()

    cursor.close()
    conn.close()

# Run this function periodically (e.g., using a cron job or a scheduler)
delete_expired_files()

###############################################################################

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Generate and save an encryption key (run this once)
if not os.path.exists('key.key'):
    with open('key.key', 'wb') as key_file:
        key_file.write(Fernet.generate_key())

with open('key.key', 'rb') as key_file:
    encryption_key = key_file.read()

cipher = Fernet(encryption_key)

#THIS IS FOR AES ENCRYPTION
def generate_aes_key():
    return os.urandom(32)  # 256-bit key

# Encrypt data with AES
def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

# Decrypt data with AES
def decrypt_aes(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

#directory for file scan
# Function to load suspicious hashes from files
def load_suspicious_hashes(md5_file_path, sha1_file_path, sha256_file_path):
    hashes = {
        'md5': set(),
        'sha1': set(),
        'sha256': set()
    }
    
    # Load MD5 hashes
    try:
        with open(md5_file_path, 'r') as file:
            hashes['md5'] = set(line.strip() for line in file)
    except Exception as e:
        print(f"Error loading MD5 hashes: {e}")
    
    # Load SHA1 hashes
    try:
        with open(sha1_file_path, 'r') as file:
            hashes['sha1'] = set(line.strip() for line in file)
    except Exception as e:
        print(f"Error loading SHA1 hashes: {e}")
    
    # Load SHA256 hashes
    try:
        with open(sha256_file_path, 'r') as file:
            hashes['sha256'] = set(line.strip() for line in file)
    except Exception as e:
        print(f"Error loading SHA256 hashes: {e}")
    
    return hashes

# Load suspicious hashes from the files in the hashes directory
SUSPICIOUS_HASHES = load_suspicious_hashes(
    os.path.join('hashes', 'MD5_Hashes.txt'), 
    os.path.join('hashes', 'SHA1_Hashes.txt'), 
    os.path.join('hashes', 'SHA256_Hashes.txt')
)

# Disable caching to force auto-logout
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# User Loader
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, password_changed, profile_picture, block_incoming_files, otp_expires_at FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[3], user[4], user[5], user[6])
    return None

# User class
class User(UserMixin):
    def __init__(self, id, username, password, password_changed=False, profile_picture=None, block_incoming_files=False, otp_expires_at=None):
        self.id = id
        self.username = username
        self.password = password
        self.password_changed = password_changed
        self.profile_picture = profile_picture
        self.block_incoming_files = block_incoming_files
        self.otp_expires_at = otp_expires_at
        
# clean up expired otp
def cleanup_expired_otp_sessions():
    """Clean up expired OTP sessions from the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET otp_expires_at = NULL WHERE otp_expires_at < NOW()")
    conn.commit()
    cursor.close()
    conn.close()

# User online status tracking
user_last_activity = {}

@app.route('/api/user_status', methods=['POST'])
def user_status():
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    user_ids = data.get('user_ids', [])
    
    # Current time for comparison
    current_time = datetime.now()
    
    # Prepare response with status for each user
    status_response = {}
    for user_id in user_ids:
        # Convert to string for dictionary key comparison
        user_id_str = str(user_id)
        
        # Check if user has activity recorded and if it's recent (within last 5 minutes)
        if user_id_str in user_last_activity:
            last_active = user_last_activity[user_id_str]
            time_diff = (current_time - last_active).total_seconds()
            
            # Consider user online if active in the last 5 minutes
            if time_diff < 300:  # 5 minutes = 300 seconds
                status_response[user_id] = 'online'
            else:
                status_response[user_id] = 'offline'
        else:
            status_response[user_id] = 'offline'
    
    return jsonify(status_response)

# Update user's last activity timestamp
def update_user_activity(user_id):
    if user_id:
        user_last_activity[str(user_id)] = datetime.now()

# Add before_request handler to track user activity
@app.before_request
def track_user_activity():
    if current_user.is_authenticated and session.get('otp_verified'):
        update_user_activity(current_user.id)

@app.route('/')
def index():
    return redirect(url_for('login'))

#WORK IN PROGRESS
@app.route('/api/system_stats')
def system_stats():
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        range_seconds = int(request.args.get('range', 30))
    except ValueError:
        range_seconds = 30
    
    stats = system_monitor.get_all_stats()
    
    # Return only the requested range
    requested_points = min(range_seconds + 1, len(stats['history']['timestamps']))
    
    response = {
        'current': {
            'cpu': stats['cpu'],
            'memory': stats['memory'],
            'disk': stats['disk'],
            'network': stats['network']
        },
        'history': {
            'timestamps': stats['history']['timestamps'][-requested_points:],
            'cpu': stats['history']['cpu'][-requested_points:],
            'memory': stats['history']['memory'][-requested_points:],
            'disk': stats['history']['disk'][-requested_points:],
            'network_kb': stats['history']['network_kb'][-requested_points:],
            'network_packets': stats['history']['network_packets'][-requested_points:]
        }
    }
    
    return jsonify(response)

# Socket.IO event handlers for system monitoring
@socketio.on('connect', namespace='/admin')
def admin_connect():
    if 'admin' not in session:
        return False
    system_monitor.start_monitoring(interval=2)
    
@socketio.on('disconnect', namespace='/admin')
def admin_disconnect():

    pass

@socketio.on('stop_monitoring', namespace='/admin')
def stop_monitoring():
    if 'admin' not in session:
        return False
    system_monitor.stop_monitoring()
    return True

########################################### - ADMIN ROUTES - ###################################################
# Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            session['admin_username'] = username  # Store admin username in session
            log_activity(None, 'admin_login', f'Admin {username} logged in.')
            flash('Admin logged in successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template('admin/admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    total_uploaded_gb = calculate_total_uploaded_size_all_users()
    user_statistics = get_user_statistics()
    total_viruses_detected = calculate_total_viruses_detected_all_users()
    
    # Get user upload statistics
    user_upload_stats = get_user_upload_stats(app.config)
    
    # Get file upload and download counts
    file_uploads_count = count_file_uploads()
    file_downloads_count = count_file_downloads()

    # Get unread inquiry count for admin notifications
    from utils.notification_utils import get_unread_admin_inquiry_count
    unread_inquiry_count = get_unread_admin_inquiry_count()
    
    return render_template('admin/admin_dashboard.html', 
                           admin_username=session.get('admin_username'), 
                           total_uploaded_gb=total_uploaded_gb,
                           total_users=user_statistics['total_users'],
                           total_brgycaptain=user_statistics['total_brgycaptain'],
                           total_government_position=user_statistics['total_government_position'],
                           total_employee=user_statistics['total_employee'],
                           active_users=user_statistics['active_users'],
                           get_all_threats=get_all_threats,
                           get_threat_statistics=get_threat_statistics,
                           total_viruses_detected=total_viruses_detected,
                           user_upload_stats=user_upload_stats,
                           file_uploads_count=file_uploads_count,
                           file_downloads_count=file_downloads_count,
                           unread_inquiry_count=unread_inquiry_count)

@app.route('/admin/user_list')
def admin_user_list():
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))
    
    try:
        users = get_users_with_details()
        return render_template('admin/admin_user_list.html',
                               admin_username=session.get('admin_username'),
                               users=users)
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/user_file_stats/<int:user_id>')
def admin_user_file_stats(user_id):
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        stats = get_user_file_stats(app.config, user_id)
        if stats:
            return jsonify(stats)
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Routes
@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        # Fetch form data
        first_name = request.form['firstName']
        middle_name = request.form.get('middleName', '')
        last_name = request.form['lastName']
        gender = request.form['gender']
        age = request.form['age']
        contact_number = request.form['contactNumber']
        role = request.form['role']
        government_position = request.form.get('governmentPosition', '')
        barangay = request.form.get('barangay', '')
        department = request.form.get('department', '')
        position = request.form.get('employeePosition', '')  # Updated to use employeePosition
        email = request.form['email']

        # Generate username and password
        username = generate_username(first_name, last_name)
        password = generate_password()

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert into users table
            cursor.execute("""
                INSERT INTO users (username, password, role, password_changed)
                VALUES (%s, %s, %s, %s)
            """, (username, hashed_password, role, False))  # Set password_changed to False
            user_id = cursor.lastrowid

            # Insert into role-specific table
            if role == 'barangay-captain':
                cursor.execute("""
                    INSERT INTO brgycaptain 
                    (user_id, first_name, middle_name, last_name, gender, age, contact_number, position, email, barangay)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, first_name, middle_name, last_name, gender, age, contact_number, "Barangay Captain", email, barangay))

            elif role == 'government-position':
                cursor.execute("""
                    INSERT INTO government_position 
                    (user_id, first_name, middle_name, last_name, gender, age, contact_number, government_position, email)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, first_name, middle_name, last_name, gender, age, contact_number, government_position, email))

            elif role == 'municipal-employee':
                cursor.execute("""
                    INSERT INTO employee 
                    (user_id, first_name, middle_name, last_name, gender, age, contact_number, department, position, email)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, first_name, middle_name, last_name, gender, age, contact_number, department, position, email))

            conn.commit()

            message = f"""
            Your account has been created successfully.
            Username: {username}
            Password: {password}
            
            You will be required to change your password on your first login.
            """


            # Send email with username and password
            msg = Message('Your Account Information', recipients=[email])
            msg.body = message
            mail.send(msg)

            # Send SMS with the same account information
            sms_status = send_sms(contact_number, message)

            if sms_status == 200:
                flash('User added successfully, email and SMS sent.', 'success')
            else:
                flash('User added successfully, email sent but SMS failed.', 'warning')

        except Exception as e:
            flash(f"Error: {e}", "danger")
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('admin_dashboard'))

    return render_template('admin/admin_add_user.html', admin_username=session.get('admin_username'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        # Fetch form data
        first_name = request.form['firstName']
        middle_name = request.form.get('middleName', '')
        last_name = request.form['lastName']
        gender = request.form['gender']
        age = request.form['age']
        contact_number = request.form['contactNumber']
        email = request.form['email']
        username = request.form['username']
        password = request.form.get('password')  # New password field

        # Fetch the user's current role
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        role = cursor.fetchone()[0]

        try:
            # Update users table
            if password:
                # Hash the new password
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute("""
                    UPDATE users 
                    SET username = %s, password = %s
                    WHERE id = %s
                """, (username, hashed_password, user_id))
            else:
                # Update username only if password is not provided
                cursor.execute("""
                    UPDATE users 
                    SET username = %s
                    WHERE id = %s
                """, (username, user_id))

            # Update role-specific table
            if role == 'barangay-captain':
                barangay = request.form.get('barangay', '')
                position = "Barangay Captain"  # Default position for barangay captain
                cursor.execute("""
                    UPDATE brgycaptain 
                    SET first_name = %s, middle_name = %s, last_name = %s, gender = %s, age = %s, 
                        contact_number = %s, position = %s, email = %s, barangay = %s
                    WHERE user_id = %s
                """, (first_name, middle_name, last_name, gender, age, contact_number, position, email, barangay, user_id))

            elif role == 'government-position':
                government_position = request.form.get('governmentPosition', '')
                cursor.execute("""
                    UPDATE government_position 
                    SET first_name = %s, middle_name = %s, last_name = %s, gender = %s, age = %s, 
                        contact_number = %s, government_position = %s, email = %s
                    WHERE user_id = %s
                """, (first_name, middle_name, last_name, gender, age, contact_number, government_position, email, user_id))

            elif role == 'municipal-employee':
                department = request.form.get('department', '')
                position = request.form.get('position', '')
                cursor.execute("""
                    UPDATE employee 
                    SET first_name = %s, middle_name = %s, last_name = %s, gender = %s, age = %s, 
                        contact_number = %s, department = %s, position = %s, email = %s
                    WHERE user_id = %s
                """, (first_name, middle_name, last_name, gender, age, contact_number, department, position, email, user_id))

            conn.commit()
            flash('User updated successfully.', 'success')
        except Exception as e:
            flash(f"Error: {e}", "danger")
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('admin_user_list'))

    # Fetch user details for pre-filling the form
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_user_list'))

    # Fetch role-specific details
    role = user[3]  # role is at index 3 in the users table
    role_details = None

    if role == 'barangay-captain':
        cursor.execute("SELECT * FROM brgycaptain WHERE user_id = %s", (user_id,))
        role_details = cursor.fetchone()
    elif role == 'government-position':
        cursor.execute("SELECT * FROM government_position WHERE user_id = %s", (user_id,))
        role_details = cursor.fetchone()
    elif role == 'municipal-employee':
        cursor.execute("SELECT * FROM employee WHERE user_id = %s", (user_id,))
        role_details = cursor.fetchone()

    cursor.close()
    conn.close()

    if not role_details:
        flash('Role-specific details not found.', 'danger')
        return redirect(url_for('admin_user_list'))

    # Combine user and role-specific details into a dictionary
    user_details = {
        'id': user[0],
        'username': user[1],
        'role': user[3],
        'first_name': role_details[2] if len(role_details) > 2 else '',
        'middle_name': role_details[3] if len(role_details) > 3 else '',
        'last_name': role_details[4] if len(role_details) > 4 else '',
        'gender': role_details[5] if len(role_details) > 5 else '',
        'age': role_details[6] if len(role_details) > 6 else '',
        'contact_number': role_details[7] if len(role_details) > 7 else '',
        'position': role_details[8] if len(role_details) > 8 else '',
        'email': role_details[9] if len(role_details) > 9 else '',
        'government_position': role_details[10] if len(role_details) > 10 and role == 'government-position' else '',
        'barangay': role_details[10] if len(role_details) > 10 and role == 'barangay-captain' else '',
        'department': role_details[10] if len(role_details) > 10 and role == 'municipal-employee' else ''
    }

    return render_template('admin/admin_edit_user.html', user=user_details)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch the user's role to determine which role-specific table to delete from
        cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        role = cursor.fetchone()[0]

        # First, delete records from tables with foreign key constraints
        # Delete from messages table where user is sender or receiver
        cursor.execute("DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s", (user_id, user_id))
        
        # Delete from user_inquiries table
        cursor.execute("DELETE FROM user_inquiries WHERE user_id = %s", (user_id,))
        
        # Delete from activity_log table if it has a foreign key constraint
        cursor.execute("DELETE FROM activity_log WHERE user_id = %s", (user_id,))
        
        # Delete from threats table if it exists and has a foreign key constraint
        cursor.execute("DELETE FROM threats WHERE owner_id = %s", (user_id,))
        
        # Delete from files table if it has a foreign key constraint
        cursor.execute("DELETE FROM files WHERE owner_id = %s", (user_id,))

        # Delete from role-specific tables based on the user's role
        if role == 'barangay-captain':
            cursor.execute("DELETE FROM brgycaptain WHERE user_id = %s", (user_id,))
        elif role == 'government-position':
            cursor.execute("DELETE FROM government_position WHERE user_id = %s", (user_id,))
        elif role == 'municipal-employee':
            cursor.execute("DELETE FROM employee WHERE user_id = %s", (user_id,))

        # Finally, delete the user from the users table
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        conn.commit()
        flash('User and related data deleted successfully.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting user: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_user_list'))


# THIS IS FOR ADMIN ACTIVITY LOGS FOR USERS
@app.route('/admin/activity_log')
def admin_activity_log():
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Use dictionary cursor
    cursor.execute("""
        SELECT 
            activity_log.id,
            activity_log.user_id,
            activity_log.action,
            activity_log.description,
            activity_log.timestamp,
            users.username,
            files.filename,
            files.size
        FROM activity_log 
        LEFT JOIN users ON activity_log.user_id = users.id
        LEFT JOIN files ON activity_log.description LIKE CONCAT('%', files.filename, '%')
        ORDER BY activity_log.timestamp DESC
    """)
    logs = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('admin/admin_activity_log.html', admin_username=session.get('admin_username'), logs=logs)


#admin inquiries
@app.route('/admin/inquiries')
def admin_inquiries():
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    # Fetch all inquiries with user details
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT 
            user_inquiries.id, 
            user_inquiries.subject, 
            user_inquiries.description, 
            user_inquiries.status, 
            user_inquiries.created_at, 
            user_inquiries.is_read,
            user_inquiries.screenshot,
            users.username 
        FROM user_inquiries 
        LEFT JOIN users ON user_inquiries.user_id = users.id 
        ORDER BY user_inquiries.created_at DESC
    """)
    inquiries = cursor.fetchall()
    cursor.close()
    conn.close()
    
    # Get unread inquiry count
    unread_count = get_unread_admin_inquiry_count()

    return render_template('admin/admin_inquiries.html', 
                          inquiries=inquiries, 
                          admin_username=session.get('admin_username'),
                          unread_inquiry_count=unread_count)

@app.route('/admin/resolve_inquiry/<int:inquiry_id>', methods=['POST'])
def resolve_inquiry(inquiry_id):
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # First get the inquiry details to use for notification
    cursor.execute("""
        SELECT user_id, subject 
        FROM user_inquiries 
        WHERE id = %s
    """, (inquiry_id,))
    inquiry = cursor.fetchone()
    
    if inquiry:
        # Update the inquiry status
        cursor.execute("""
            UPDATE user_inquiries 
            SET status = 'Resolved', is_read = 1 
            WHERE id = %s
        """, (inquiry_id,))
        conn.commit()
        
        # Send notification to the user
        from utils.notification_utils import notify_inquiry_resolved
        notify_inquiry_resolved(inquiry['user_id'], inquiry['subject'])
    
    cursor.close()
    conn.close()
    
    # If this is an AJAX request, return JSON response
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True})
    
    flash('Inquiry has been resolved and user notified.', 'success')
    return redirect(url_for('admin_inquiries'))

@app.route('/admin/delete_inquiry/<int:inquiry_id>', methods=['POST'])
def delete_inquiry(inquiry_id):
    if 'admin' not in session:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_inquiries WHERE id = %s", (inquiry_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Inquiry deleted successfully.', 'success')
    return redirect(url_for('admin_inquiries'))

@app.route('/admin/get_inquiry_notifications')
def get_inquiry_notifications():
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.notification_utils import get_admin_inquiry_notifications, get_unread_admin_inquiry_count
    
    inquiries = get_admin_inquiry_notifications()
    unread_count = get_unread_admin_inquiry_count()
    
    return jsonify({
        'inquiries': inquiries,
        'unread_count': unread_count
    })

@app.route('/admin/mark_inquiry_as_read/<int:inquiry_id>', methods=['POST'])
def mark_inquiry_as_read(inquiry_id):
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.notification_utils import mark_inquiry_as_read
    
    success = mark_inquiry_as_read(inquiry_id)
    
    return jsonify({'success': success})

@app.route('/admin/mark_all_inquiries_as_read', methods=['POST'])
def mark_all_inquiries_as_read():
    if 'admin' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.notification_utils import mark_all_inquiries_as_read
    
    success = mark_all_inquiries_as_read()
    
    return jsonify({'success': success})

@app.route('/admin/logout')
def admin_logout():
    # Admin doesn't use the same tracking mechanism as regular users
    session.pop('admin', None)
    session.pop('admin_username', None)  # Clear admin username from session
    flash('Admin logged out.', 'info')
    return redirect(url_for('admin_login'))

########################################## - USER ROUTES - #############################################################

# LOGIN USER FUNCTION
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if input is email or username
        is_email = '@' in username_or_email
        
        if is_email:
            # Search for user by email in role-specific tables
            cursor.execute("""
                SELECT u.id, u.username, u.password, u.password_changed, u.role, u.otp_expires_at
                FROM users u 
                LEFT JOIN brgycaptain b ON u.id = b.user_id 
                LEFT JOIN government_position g ON u.id = g.user_id 
                LEFT JOIN employee e ON u.id = e.user_id 
                WHERE b.email = %s OR g.email = %s OR e.email = %s
            """, (username_or_email, username_or_email, username_or_email))
            
            user = cursor.fetchone()
            
            if not user:
                cursor.execute("SELECT id, username, password, password_changed, role, otp_expires_at FROM users WHERE username = %s", (username_or_email,))
                user = cursor.fetchone()
        else:
            # Fetch user details by username
            cursor.execute("SELECT id, username, password, password_changed, role, otp_expires_at FROM users WHERE username = %s", (username_or_email,))
            user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            role = user[4]  
            contact_number = None
            otp_expires_at = user[5]  # Get OTP expiration time
            
            ip_info = get_public_ip_info()
            
            if isinstance(ip_info, dict) and ip_info.get('redirect'):
                cursor.close()
                conn.close()
                return redirect(ip_info.get('url'))
            
            ip_address = ip_info.get('ip') if isinstance(ip_info, dict) else request.remote_addr
            
            if is_suspicious_ip(ip_address):
                flash('Access denied from suspicious IP address.', 'danger')
                log_activity(user[0], 'login_attempt', f'Login attempt from suspicious IP: {ip_address}')
                cursor.close()
                conn.close()
                return redirect(url_for('login'))

            cursor.execute("UPDATE users SET last_login_ip = %s WHERE id = %s", (ip_address, user[0]))
            conn.commit()

            if role == 'barangay-captain':
                cursor.execute("SELECT contact_number FROM brgycaptain WHERE user_id = %s", (user[0],))
                result = cursor.fetchone()
                if result:
                    contact_number = result[0]
            elif role == 'government-position':
                cursor.execute("SELECT contact_number FROM government_position WHERE user_id = %s", (user[0],))
                result = cursor.fetchone()
                if result:
                    contact_number = result[0]
            elif role == 'municipal-employee':
                cursor.execute("SELECT contact_number FROM employee WHERE user_id = %s", (user[0],))
                result = cursor.fetchone()
                if result:
                    contact_number = result[0]

            cursor.close()
            conn.close()

            if not contact_number:
                flash('Contact number not found for the user.', 'danger')
                return redirect(url_for('login'))

            session.permanent = True
            login_user(User(user[0], user[1], user[2], user[3]))

            # Check if user needs to change password
            if not user[3]:  # password_changed is False
                otp = generate_otp()
                session['otp'] = otp
                session['user_id'] = user[0]
                print(f"Generated OTP: {otp}")
                print(f"Sending OTP to: {contact_number}")
                if send_otp_via_sms(contact_number, otp):
                    flash('An OTP has been sent to your registered phone number.', 'info')
                else:
                    flash('Failed to send OTP. Please try again.', 'danger')
                flash('You must change your password before proceeding.', 'info')
                return redirect(url_for('change_password'))

            # Check if OTP is still valid (within 1 day)
            current_time = datetime.now()
            if otp_expires_at and otp_expires_at > current_time:
                # OTP is still valid, skip OTP verification
                session['otp_verified'] = True
                update_user_activity(current_user.id)
                flash('Login successful.', 'success')
                return redirect(url_for('userdashboard'))
            else:
                # OTP expired or doesn't exist, require new OTP
                otp = generate_otp()
                session['otp'] = otp
                session['user_id'] = user[0]
                print(f"Generated OTP: {otp}")
                print(f"Sending OTP to: {contact_number}")
                if send_otp_via_sms(contact_number, otp):
                    flash('An OTP has been sent to your registered phone number.', 'info')
                else:
                    flash('Failed to send OTP. Please try again.', 'danger')
                return redirect(url_for('verify_otp'))

        else:
            flash('Invalid credentials.', 'danger')

    return render_template('login.html')


# THIS IS FOR USER DASHBOARD
STORAGE_QUOTA = 30  # in GB
@app.route('/userdashboard')
@login_required
def userdashboard():
    # Check for suspicious IP
    ip_info = get_public_ip_info()
    if isinstance(ip_info, dict) and ip_info.get('redirect'):
        return redirect(ip_info.get('url'))
    # Fetch user details
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (current_user.id,))
    user = cursor.fetchone()
    
    # Get user's full name from role-specific tables
    cursor.execute("""
        SELECT 
            CONCAT(
                COALESCE(b.first_name, g.first_name, e.first_name, ''), ' ',
                COALESCE(b.last_name, g.last_name, e.last_name, '')
            ) AS full_name
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id = %s
    """, (current_user.id,))
    user_full_name_result = cursor.fetchone()
    # Fix: Check if user_full_name_result is not None and has a value at index 0
    user_full_name = user_full_name_result[0] if user_full_name_result and user_full_name_result[0] is not None else ""

    # Fetch the latest message per sender for the current user
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, m.sender_id, u.username AS sender_username,
               COALESCE(b.first_name, g.first_name, e.first_name) AS sender_first_name,
               COALESCE(b.last_name, g.last_name, e.last_name) AS sender_last_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN brgycaptain b ON m.sender_id = b.user_id
        LEFT JOIN government_position g ON m.sender_id = g.user_id
        LEFT JOIN employee e ON m.sender_id = e.user_id
        JOIN (
            SELECT sender_id, MAX(created_at) AS latest_timestamp
            FROM messages
            WHERE receiver_id = %s
            GROUP BY sender_id
        ) latest ON m.sender_id = latest.sender_id AND m.created_at = latest.latest_timestamp
        WHERE m.receiver_id = %s
        ORDER BY m.created_at DESC
        LIMIT 2
    """, (current_user.id, current_user.id))
    latest_messages = cursor.fetchall()

    # Decrypt the messages
    for message in latest_messages:
        try:
            # Decrypt the message
            decrypted_message = cipher.decrypt(message['message'].encode('utf-8')).decode('utf-8')
            message['message'] = decrypted_message
        except Exception as e:
            print(f"Error decrypting message: {e}")
            message['message'] = "[Unable to decrypt message]"

    # Count unread messages (or total messages if no is_read column exists)
    cursor.execute("""
        SELECT COUNT(*) AS unread_count 
        FROM messages 
        WHERE receiver_id = %s
    """, (current_user.id,))
    unread_message_count = cursor.fetchone()['unread_count']

    # Calculate total uploaded size in GB
    total_uploaded_gb = calculate_total_uploaded_size(current_user.id)

    # Calculate storage usage percentage
    storage_usage_percentage = (total_uploaded_gb / STORAGE_QUOTA) * 100 # testing

    # Calculate file size breakdown
    file_size_breakdown = calculate_file_size_breakdown(current_user.id)

    # Fetch user's role-specific details
    role = user[4]  # role is at index 4 in the users table
    role_details = None

    if role == 'barangay-captain':
        cursor.execute("SELECT * FROM brgycaptain WHERE user_id = %s", (current_user.id,))
        role_details = cursor.fetchone()
    elif role == 'government-position':
        cursor.execute("SELECT * FROM government_position WHERE user_id = %s", (current_user.id,))
        role_details = cursor.fetchone()
    elif role == 'municipal-employee':
        cursor.execute("SELECT * FROM employee WHERE user_id = %s", (current_user.id,))
        role_details = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template(
        'userdashboard.html',
        user=user,
        role_details=role_details,
        user_full_name=user_full_name,
        total_uploaded_gb=total_uploaded_gb,
        storage_quota=STORAGE_QUOTA,
        storage_usage_percentage=storage_usage_percentage,
        latest_messages=latest_messages,
        unread_message_count=unread_message_count,
        file_size_breakdown=file_size_breakdown,
        get_user_threats=get_user_threats,
        has_user_rated=has_user_rated,
        total_viruses_detected=calculate_total_viruses_detected(current_user.id)
    )
# THIS IS FOR THE FILESHARE 
@app.route('/fileshare', methods=['GET', 'POST'])
@login_required
def fileshare():
    # Check for suspicious IP
    ip_info = get_public_ip_info()
    if isinstance(ip_info, dict) and ip_info.get('redirect'):
        return redirect(ip_info.get('url'))
    if 'otp_verified' not in session:
        flash('Please verify your OTP to access the fileshare.', 'info')
        return redirect(url_for('verify_otp'))

    # Function to check for viruses and log threats
    def check_and_log_threat(file_data, filename, owner_id, receiver_id=None):
        # Calculate all hashes
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha1_hash = hashlib.sha1(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        # Check against all hash types
        is_malicious = (
            md5_hash in SUSPICIOUS_HASHES['md5'] or
            sha1_hash in SUSPICIOUS_HASHES['sha1'] or
            sha256_hash in SUSPICIOUS_HASHES['sha256']
        )
        
        # Check each hash type separately
        if md5_hash in SUSPICIOUS_HASHES['md5']:
            log_threat(file_id=None, file_name=filename, md5_hash=md5_hash, sha1_hash=sha1_hash, sha256_hash=sha256_hash, owner_id=owner_id, threat_type='HASH', receiver_id=receiver_id)
            return True
        elif sha1_hash in SUSPICIOUS_HASHES['sha1']:
            log_threat(file_id=None, file_name=filename, md5_hash=md5_hash, sha1_hash=sha1_hash, sha256_hash=sha256_hash, owner_id=owner_id, threat_type='HASH', receiver_id=receiver_id)
            return True
        elif sha256_hash in SUSPICIOUS_HASHES['sha256']:
            log_threat(file_id=None, file_name=filename, md5_hash=md5_hash, sha1_hash=sha1_hash, sha256_hash=sha256_hash, owner_id=owner_id, threat_type='HASH', receiver_id=receiver_id)
            return True 
        return False

    if request.method == 'POST':
        files = request.files.getlist('file')
        shared_with = request.form.getlist('shared_with')
        expiration_duration = request.form.get('expiration_duration')
        user_queries = request.form.get('user_queries', '')
        delete_after_download = 'delete_after_download' in request.form

        if not files or all(f.filename == '' for f in files):
            flash('No files selected.', 'danger')
            return redirect(url_for('fileshare'))

        # Validate shared_with usernames
        shared_usernames = [username.strip() for username in shared_with if username.strip()]
        valid_usernames = []
        conn = get_db_connection()
        cursor = conn.cursor()
        
        for username in shared_usernames:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                valid_usernames.append(username)
            else:
                flash(f"Username '{username}' does not exist and will be ignored.", 'warning')

        if not valid_usernames:
            flash('No valid usernames provided for sharing.', 'danger')
            return redirect(url_for('fileshare'))

        # Check if recipient has blocked incoming files
        cursor.execute("SELECT username, block_incoming_files FROM users WHERE username IN (%s)" % 
            ','.join(['%s']*len(valid_usernames)), tuple(valid_usernames))
        recipient_info = cursor.fetchall()
        blocked_recipients = [user[0] for user in recipient_info if user[1]]

        if blocked_recipients:
            flash(f"The following users have blocked incoming files: {', '.join(blocked_recipients)}", 'danger')
            return redirect(url_for('fileshare'))

        # Remove blocked users from valid_usernames
        valid_usernames = [user for user in valid_usernames if user not in blocked_recipients]

        if not valid_usernames:
            flash('All selected recipients have blocked incoming files.', 'danger')
            return redirect(url_for('fileshare'))

        try:
            # Process files based on count
            if len(files) > 1:
                # Process multiple files as ZIP
                virus_found = False
                zip_buffer = BytesIO()
                
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file in files:
                        if file.filename == '':
                            continue
                            
                        # Check file size
                        file.seek(0, os.SEEK_END)
                        file_size = file.tell()
                        file.seek(0)
                        if file_size > 1024 * 1024 * 1024:  # 1GB limit
                            flash(f'File {file.filename} exceeds 1GB limit.', 'danger')
                            continue
                            
                        # Read and check file content
                        file_data = file.read()
                        
                        # Get user IDs for all recipients to notify them if a threat is detected
                        for shared_user in valid_usernames:
                            cursor.execute("SELECT id FROM users WHERE username = %s", (shared_user,))
                            user_result = cursor.fetchone()
                            if user_result and check_and_log_threat(file_data, file.filename, current_user.id, user_result[0]):
                                flash(f'Virus detected in {file.filename}. Upload aborted.', 'danger')
                                virus_found = True
                                break
                        
                        if virus_found:
                            break
                            
                        zipf.writestr(file.filename, file_data)
                        
                if virus_found:
                    return redirect(url_for('fileshare'))
                    
                # Create ZIP filename with timestamp
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                zip_filename = f"files_{timestamp}.zip"
                zip_data = zip_buffer.getvalue()
                
                # Encrypt with Fernet
                encrypted_zip = cipher.encrypt(zip_data)
                
                # Encrypt with AES
                aes_key = generate_aes_key()
                double_encrypted_zip = encrypt_aes(encrypted_zip, aes_key)
                
                # Save the double-encrypted ZIP
                zip_path = os.path.join('uploads', zip_filename)
                with open(zip_path, 'wb') as f:
                    f.write(double_encrypted_zip)
                    
                # Get password if provided
                file_password = request.form.get('file_password')
                hashed_password = None
                if file_password and file_password.strip():
                    hashed_password = bcrypt.generate_password_hash(file_password).decode('utf-8')
                
                # Store ZIP file details
                cursor.execute(
                    """INSERT INTO files 
                    (filename, owner_id, shared_with, created_at, expiration_time, 
                     size, user_queries, delete_after_download, aes_key, password)
                    VALUES (%s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s)""",
                    (zip_filename, current_user.id, ','.join(valid_usernames),
                    get_expiration_time(expiration_duration), len(zip_data),
                    user_queries, delete_after_download, aes_key, hashed_password)
                )
                
                # Log the file upload activity
                log_activity(current_user.id, 'file_upload', f'File {zip_filename} uploaded and shared with {shared_with}.')
                
                flash(f'{len(files)} files zipped and uploaded successfully.', 'success')
                
            else:
                # Process single file
                file = files[0]
                if file.filename == '':
                    flash('No file selected.', 'danger')
                    return redirect(url_for('fileshare'))
                
                # Check file size
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > 1024 * 1024 * 1024:  # 1GB limit
                    flash('File size exceeds 1GB limit.', 'danger')
                    return redirect(url_for('fileshare'))
                    
                # Read and check file content
                file_data = file.read()
                
                # Check for threats for each recipient
                virus_found = False
                for shared_user in valid_usernames:
                    cursor.execute("SELECT id FROM users WHERE username = %s", (shared_user,))
                    user_result = cursor.fetchone()
                    if user_result and check_and_log_threat(file_data, file.filename, current_user.id, user_result[0]):
                        flash('File contains virus. Upload aborted.', 'danger')
                        virus_found = True
                        break
                
                if virus_found:
                    return redirect(url_for('fileshare'))
                    
                # Encrypt with Fernet
                encrypted_data = cipher.encrypt(file_data)
                
                # Encrypt with AES
                aes_key = generate_aes_key()
                double_encrypted_data = encrypt_aes(encrypted_data, aes_key)
                
                # Save the double-encrypted file
                file_path = os.path.join('uploads', file.filename)
                with open(file_path, 'wb') as f:
                    f.write(double_encrypted_data)
                    
                # Get password if provided
                file_password = request.form.get('file_password')
                hashed_password = None
                if file_password and file_password.strip():
                    hashed_password = bcrypt.generate_password_hash(file_password).decode('utf-8')
                
                # Store file details
                cursor.execute(
                    """INSERT INTO files 
                    (filename, owner_id, shared_with, created_at, expiration_time, 
                     size, user_queries, delete_after_download, aes_key, password)
                    VALUES (%s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s)""",
                    (file.filename, current_user.id, ','.join(valid_usernames),
                    get_expiration_time(expiration_duration), len(file_data),
                    user_queries, delete_after_download, aes_key, hashed_password)
                )
                
                # Log the file upload activity
                log_activity(current_user.id, 'file_upload', f'File {file.filename} uploaded and shared with {shared_with}.')
                
                flash('File uploaded successfully.', 'success')
                
            conn.commit()
            
            # Notify users who received files
            if valid_usernames:
                for shared_user in valid_usernames:
                    # Get user ID from username
                    cursor.execute("SELECT id FROM users WHERE username = %s", (shared_user,))
                    user_result = cursor.fetchone()
                    if user_result:
                        if len(files) > 1:
                            notify_file_received(
                                user_result[0], 
                                current_user.username, 
                                zip_filename, 
                                cursor.lastrowid
                            )
                        else:
                            notify_file_received(
                                user_result[0], 
                                current_user.username, 
                                file.filename, 
                                cursor.lastrowid
                            )
            
        except Exception as e:
            conn.rollback()
            flash(f'Error during file processing: {str(e)}', 'danger')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('fileshare'))

    # Fetch user's own files with owner's username and shared files
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Fetch all users for recipient selection
    cursor.execute("""
        SELECT u.id, u.username, u.role,
               COALESCE(b.first_name, g.first_name, e.first_name) AS first_name,
               COALESCE(b.last_name, g.last_name, e.last_name) AS last_name
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id != %s
    """, (current_user.id,))
    all_users = cursor.fetchall()
    
    # Fetch user's own files along with the owner's username
    cursor.execute("""
        SELECT files.*, users.username as owner_username 
        FROM files 
        JOIN users ON files.owner_id = users.id 
        WHERE files.owner_id = %s
    """, (current_user.id,))
    user_files = cursor.fetchall()

    # Fetch files shared with the current user, including owner's username
    cursor.execute("""
        SELECT files.*, users.username as owner_username 
        FROM files 
        JOIN users ON files.owner_id = users.id 
        WHERE FIND_IN_SET(%s, files.shared_with)
    """, (current_user.username,))
    shared_files = cursor.fetchall()

    # Fetch threats for the current user
    cursor.execute("""
        SELECT * FROM threats 
        WHERE owner_id = %s
        ORDER BY detected_at DESC
        LIMIT 5
    """, (current_user.id,))
    recent_threats = cursor.fetchall()
      
    # Message Nav
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, m.sender_id, u.username AS sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        JOIN (
            SELECT sender_id, MAX(created_at) AS latest_timestamp
            FROM messages
            WHERE receiver_id = %s
            GROUP BY sender_id
        ) latest ON m.sender_id = latest.sender_id AND m.created_at = latest.latest_timestamp
        WHERE m.receiver_id = %s
        ORDER BY m.created_at DESC
        LIMIT 2
    """, (current_user.id, current_user.id))
    latest_messages = cursor.fetchall()

    # Decrypt the messages
    for message in latest_messages:
        try:
            # Decrypt the message
            decrypted_message = cipher.decrypt(message['message'].encode('utf-8')).decode('utf-8')
            message['message'] = decrypted_message
        except Exception as e:
            print(f"Error decrypting message: {e}")
            message['message'] = "[Unable to decrypt message]"

    # Count unread messages (or total messages if no is_read column exists)
    cursor.execute("""
        SELECT COUNT(*) AS unread_count 
        FROM messages 
        WHERE receiver_id = %s
    """, (current_user.id,))
    unread_message_count = cursor.fetchone()['unread_count']

    cursor.close()
    conn.close()

    # Calculate storage usage
    total_uploaded_gb = calculate_total_uploaded_size(current_user.id)
    storage_usage_percentage = (total_uploaded_gb / STORAGE_QUOTA) * 100
    
    for file in shared_files + user_files:
             if file['size']:
                file['size'] = round(file['size'] / (1024 * 1024), 2)
                

    # Get user's full name from role-specific tables
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            CONCAT(
                COALESCE(b.first_name, g.first_name, e.first_name, ''), ' ',
                COALESCE(b.last_name, g.last_name, e.last_name, '')
            ) AS full_name
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id = %s
    """, (current_user.id,))
    user_full_name_result = cursor.fetchone()
    # Fix: Check if user_full_name_result is not None and has a value at index 0
    user_full_name = user_full_name_result[0] if user_full_name_result and user_full_name_result[0] is not None else ""
    cursor.close()
    conn.close()
    
    return render_template(
        'fileshare.html',
        total_uploaded_gb=total_uploaded_gb,
        latest_messages=latest_messages,
        unread_message_count=unread_message_count,
        storage_quota=STORAGE_QUOTA,
        storage_usage_percentage=storage_usage_percentage,
        user_files=user_files,
        shared_files=shared_files,
        recent_threats=recent_threats,
        total_viruses_detected=calculate_total_viruses_detected(current_user.id),
        user_full_name=user_full_name,
        has_user_rated=has_user_rated,
        all_users=all_users
    )

#THIS IS FOR USER PROFILE    
@app.route('/userprofile')
@login_required
def userprofile():
    # Check for suspicious IP
    ip_info = get_public_ip_info()
    if isinstance(ip_info, dict) and ip_info.get('redirect'):
        return redirect(ip_info.get('url'))
    if 'otp_verified' not in session:
        flash('Please verify your OTP to access the profile page.', 'info')
        return redirect(url_for('verify_otp'))

    # Fetch user details
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Use dictionary cursor to access columns by name
    cursor.execute("SELECT * FROM users WHERE id = %s", (current_user.id,))
    user = cursor.fetchone()

    role = user['role']  
    role_details = None

    if role == 'barangay-captain':
        cursor.execute("SELECT * FROM brgycaptain WHERE user_id = %s", (current_user.id,))
        role_details = cursor.fetchone()
    elif role == 'government-position':
        cursor.execute("SELECT * FROM government_position WHERE user_id = %s", (current_user.id,))
        role_details = cursor.fetchone()
    elif role == 'municipal-employee':
        cursor.execute("SELECT * FROM employee WHERE user_id = %s", (current_user.id,))
        role_details = cursor.fetchone()

    cursor.execute("""
        SELECT 
            CONCAT(
                COALESCE(b.first_name, g.first_name, e.first_name, ''), ' ',
                COALESCE(b.last_name, g.last_name, e.last_name, '')
            ) AS full_name
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id = %s
    """, (current_user.id,))
    user_full_name_result = cursor.fetchone()
    user_full_name = user_full_name_result['full_name'] if user_full_name_result else ""
    
    # Fetch the latest message per sender for the current user
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, m.sender_id, u.username AS sender_username,
               COALESCE(b.first_name, g.first_name, e.first_name) AS sender_first_name,
               COALESCE(b.last_name, g.last_name, e.last_name) AS sender_last_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN brgycaptain b ON m.sender_id = b.user_id
        LEFT JOIN government_position g ON m.sender_id = g.user_id
        LEFT JOIN employee e ON m.sender_id = e.user_id
        JOIN (
            SELECT sender_id, MAX(created_at) AS latest_timestamp
            FROM messages
            WHERE receiver_id = %s
            GROUP BY sender_id
        ) latest ON m.sender_id = latest.sender_id AND m.created_at = latest.latest_timestamp
        WHERE m.receiver_id = %s
        ORDER BY m.created_at DESC
        LIMIT 2
    """, (current_user.id, current_user.id))
    latest_messages = cursor.fetchall()

    # Decrypt the messages
    for message in latest_messages:
        try:
            # Decrypt the message
            decrypted_message = cipher.decrypt(message['message'].encode('utf-8')).decode('utf-8')
            message['message'] = decrypted_message
        except Exception as e:
            print(f"Error decrypting message: {e}")
            message['message'] = "[Unable to decrypt message]"

    # Count unread messages (or total messages if no is_read column exists)
    cursor.execute("""
        SELECT COUNT(*) AS unread_count 
        FROM messages 
        WHERE receiver_id = %s
    """, (current_user.id,))
    unread_message_count = cursor.fetchone()['unread_count']
    
    cursor.close()
    conn.close()

    return render_template('userprofile.html', user=user, role_details=role_details, role=role, user_full_name=user_full_name, unread_message_count=unread_message_count, latest_messages=latest_messages, has_user_rated=has_user_rated)

# THIS IS FOR USER HISTORY
@app.route('/userhistory')
@login_required
def userhistory():
    if 'otp_verified' not in session:
        flash('Please verify your OTP to access the history page.', 'info')
        return redirect(url_for('verify_otp'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, filename, shared_with, created_at, size, user_queries 
        FROM files 
        WHERE owner_id = %s
    """, (current_user.id,))
    uploaded_files = cursor.fetchall()

    cursor.execute("""
        SELECT id, filename, shared_with, created_at, size, user_queries 
        FROM files 
        WHERE owner_id = %s AND shared_with IS NOT NULL
    """, (current_user.id,))
    sent_files = cursor.fetchall()

    # Fetch user inquiries
    cursor.execute("""
        SELECT id, subject, description, status, created_at 
        FROM user_inquiries 
        WHERE user_id = %s  -- Filter by the logged-in user's ID
        ORDER BY created_at DESC
    """, (current_user.id,))
    inquiries = cursor.fetchall()

    cursor.execute("""
        SELECT 
            CONCAT(
                COALESCE(b.first_name, g.first_name, e.first_name, ''),
                ' ',
                COALESCE(b.last_name, g.last_name, e.last_name, '')
            ) AS full_name
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id = %s
    """, (current_user.id,))
    user_full_name_result = cursor.fetchone()
    
    user_full_name = ""
    if user_full_name_result and 'full_name' in user_full_name_result:
        user_full_name = user_full_name_result['full_name'] or ""
        
    
    # Fetch the latest message per sender for the current user
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, m.sender_id, u.username AS sender_username,
               COALESCE(b.first_name, g.first_name, e.first_name) AS sender_first_name,
               COALESCE(b.last_name, g.last_name, e.last_name) AS sender_last_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN brgycaptain b ON m.sender_id = b.user_id
        LEFT JOIN government_position g ON m.sender_id = g.user_id
        LEFT JOIN employee e ON m.sender_id = e.user_id
        JOIN (
            SELECT sender_id, MAX(created_at) AS latest_timestamp
            FROM messages
            WHERE receiver_id = %s
            GROUP BY sender_id
        ) latest ON m.sender_id = latest.sender_id AND m.created_at = latest.latest_timestamp
        WHERE m.receiver_id = %s
        ORDER BY m.created_at DESC
        LIMIT 2
    """, (current_user.id, current_user.id))
    latest_messages = cursor.fetchall()

    # Decrypt the messages
    for message in latest_messages:
        try:
            # Decrypt the message
            decrypted_message = cipher.decrypt(message['message'].encode('utf-8')).decode('utf-8')
            message['message'] = decrypted_message
        except Exception as e:
            print(f"Error decrypting message: {e}")
            message['message'] = "[Unable to decrypt message]"

    # Count unread messages (or total messages if no is_read column exists)
    cursor.execute("""
        SELECT COUNT(*) AS unread_count 
        FROM messages 
        WHERE receiver_id = %s
    """, (current_user.id,))
    unread_message_count = cursor.fetchone()['unread_count']
    
    cursor.close()
    conn.close()

    for file in uploaded_files + sent_files:
        if file['size']:
            file['size'] = round(file['size'] / (1024 * 1024), 2)

    return render_template(
        'userhistory.html',
        uploaded_files=uploaded_files,
        inquiries=inquiries,
        sent_files=sent_files,
        user_full_name=user_full_name,
        unread_message_count=unread_message_count,
        latest_messages=latest_messages
    )
    
    
#user help desk routes
@app.route('/userhelp', methods=['GET', 'POST'])
@login_required
def userhelp():
    if 'otp_verified' not in session:
        flash('Please verify your OTP to access the help desk.', 'info')
        return redirect(url_for('verify_otp'))

    if request.method == 'POST':
        subject = request.form['subject']
        description = request.form['description']
        
        # Handle screenshot upload
        screenshot_filename = None
        if 'screenshot' in request.files and request.files['screenshot'].filename != '':
            screenshot = request.files['screenshot']
            if screenshot and allowed_file(screenshot.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                # Generate a secure filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                secure_filename_base = secure_filename(screenshot.filename)
                screenshot_filename = f"inquiry_{current_user.id}_{timestamp}_{secure_filename_base}"
                
                # Ensure the user_inquiries directory exists
                os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'user_inquiries'), exist_ok=True)
                
                # Save the file
                screenshot_path = os.path.join(app.config['UPLOAD_FOLDER'], 'user_inquiries', screenshot_filename)
                screenshot.save(screenshot_path)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_inquiries (user_id, subject, description, screenshot)
            VALUES (%s, %s, %s, %s)
        """, (current_user.id, subject, description, screenshot_filename))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Your inquiry has been submitted successfully.', 'success')
        return redirect(url_for('userhelp'))

    # Fetch user's inquiries
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, subject, description, screenshot, status, created_at 
        FROM user_inquiries 
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (current_user.id,))
    inquiries = cursor.fetchall()
    
    # Get user's full name from role-specific tables
    cursor.execute("""
        SELECT 
            CONCAT(
                COALESCE(b.first_name, g.first_name, e.first_name, ''), ' ',
                COALESCE(b.last_name, g.last_name, e.last_name, '')
            ) AS full_name
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id = %s
    """, (current_user.id,))
    user_full_name_result = cursor.fetchone()
    user_full_name = user_full_name_result['full_name'] if user_full_name_result else ""
    
    # Fetch the latest message per sender for the current user
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, m.sender_id, u.username AS sender_username,
               COALESCE(b.first_name, g.first_name, e.first_name) AS sender_first_name,
               COALESCE(b.last_name, g.last_name, e.last_name) AS sender_last_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN brgycaptain b ON m.sender_id = b.user_id
        LEFT JOIN government_position g ON m.sender_id = g.user_id
        LEFT JOIN employee e ON m.sender_id = e.user_id
        JOIN (
            SELECT sender_id, MAX(created_at) AS latest_timestamp
            FROM messages
            WHERE receiver_id = %s
            GROUP BY sender_id
        ) latest ON m.sender_id = latest.sender_id AND m.created_at = latest.latest_timestamp
        WHERE m.receiver_id = %s
        ORDER BY m.created_at DESC
        LIMIT 2
    """, (current_user.id, current_user.id))
    latest_messages = cursor.fetchall()

    # Decrypt the messages
    for message in latest_messages:
        try:
            # Decrypt the message
            decrypted_message = cipher.decrypt(message['message'].encode('utf-8')).decode('utf-8')
            message['message'] = decrypted_message
        except Exception as e:
            print(f"Error decrypting message: {e}")
            message['message'] = "[Unable to decrypt message]"

    # Count unread messages (or total messages if no is_read column exists)
    cursor.execute("""
        SELECT COUNT(*) AS unread_count 
        FROM messages 
        WHERE receiver_id = %s
    """, (current_user.id,))
    unread_message_count = cursor.fetchone()['unread_count']
    
    cursor.close()
    conn.close()

    return render_template('userhelp.html', inquiries=inquiries, user_full_name=user_full_name, unread_message_count=unread_message_count, latest_messages=latest_messages)


#RENAME FILE FUNCTIONALITY
@app.route('/rename_file/<int:file_id>', methods=['POST'])
@login_required
def rename_file(file_id):
    # Fetch the file from the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE id = %s", (file_id,))
    file = cursor.fetchone()

    if not file:
        flash('File not found.', 'danger')
        return redirect(url_for('fileshare'))

    # Check if the current user is the owner of the file
    if file['owner_id'] != current_user.id:
        flash('You do not have permission to rename this file.', 'danger')
        return redirect(url_for('fileshare'))

    # Get the new filename from the request
    new_filename = request.form.get('new_filename')
    if not new_filename:
        flash('New filename is required.', 'danger')
        return redirect(url_for('fileshare'))

    # Preserve the file extension
    old_filename = file['filename']
    old_extension = os.path.splitext(old_filename)[1]  # Get the file extension
    new_filename_with_extension = new_filename + old_extension

    # Check if the new filename already exists
    cursor.execute("SELECT id FROM files WHERE filename = %s AND owner_id = %s", (new_filename_with_extension, current_user.id))
    if cursor.fetchone():
        flash('A file with this name already exists.', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('fileshare'))

    try:
        # Rename the file in the filesystem
        old_file_path = os.path.join('uploads', old_filename)
        new_file_path = os.path.join('uploads', new_filename_with_extension)
        if os.path.exists(old_file_path):
            os.rename(old_file_path, new_file_path)
        else:
            flash('File not found on server.', 'danger')
            return redirect(url_for('fileshare'))

        # Update the filename in the database
        cursor.execute("UPDATE files SET filename = %s WHERE id = %s", (new_filename_with_extension, file_id))
        conn.commit()
        
        # Log the activity
        log_activity(current_user.id, 'file_rename', f'Renamed file from {old_filename} to {new_filename_with_extension}')
        
        flash('File renamed successfully.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error renaming file: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('fileshare'))

#DOWNLOAD FILE FUNCTIONALITY
@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download(file_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM files WHERE id = %s", (file_id,))
        file = cursor.fetchone()
        if not file:
            flash('File not found.', 'danger')
            return redirect(url_for('fileshare'))
        
        # Validate permissions
        is_owner = file['owner_id'] == current_user.id
        is_shared = current_user.username in file['shared_with'].split(',') if file['shared_with'] else False
        if not (is_owner or is_shared):
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('fileshare'))
        
        # Check if file is password protected
        if file.get('password') and request.method == 'GET':
            # Show password prompt
            return render_template('fileshare.html', password_prompt=True, file_id=file_id)
       
        # Verify password if file is password protected
        if file.get('password') and request.method == 'POST':
            entered_password = request.form.get('file_password')
            if not entered_password or not bcrypt.check_password_hash(file['password'], entered_password):
                flash('Incorrect password.', 'danger')
                return render_template('fileshare.html', password_prompt=True, file_id=file_id)
        
        # Get the server-side file path
        file_path = os.path.join('uploads', file['filename'])
        if not os.path.exists(file_path):
            flash('File not found on server.', 'danger')
            return redirect(url_for('fileshare'))
            
        with open(file_path, 'rb') as f:
            double_encrypted_data = f.read()
        
        # Decrypt with AES
        aes_key = file['aes_key']
        decrypted_aes_data = decrypt_aes(double_encrypted_data, aes_key)
        
        # Decrypt with Fernet
        decrypted_data = cipher.decrypt(decrypted_aes_data)
       
        original_filename = file['filename']
        
        # Create response with proper filename
        response = send_file(
            BytesIO(decrypted_data),
            download_name=original_filename,
            as_attachment=True
        )
        
        response.headers["Content-Disposition"] = f"attachment; filename=\"{original_filename}\""
        
        # Log the file download activity
        log_activity(current_user.id, 'file_download', f'File {original_filename} downloaded.')
        
        # Check if the file should be deleted after download
        if file['delete_after_download']:
            try:
                os.remove(file_path)
                cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
                conn.commit()
                flash('File deleted after download.', 'info')
            except Exception as e:
                flash(f'Error deleting file after download: {str(e)}', 'danger')
        
        return response
    except Exception as e:
        flash(f'Download error: {str(e)}', 'danger')
        return redirect(url_for('fileshare'))
    finally:
        cursor.close()
        conn.close()

# DELETE FILE FUNCTIONALITY
@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    # Verify the file belongs to the current user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE id = %s AND owner_id = %s", (file_id, current_user.id))
    file = cursor.fetchone()
    
    if not file:
        cursor.close()
        conn.close()
        flash('File not found or unauthorized access.', 'danger')
        return redirect(url_for('fileshare'))
    
    # Log the file deletion activity
    log_activity(current_user.id, 'file_deletion', f'File {file[1]} deleted.')

    # Delete the file from the database and filesystem
    file_path = os.path.join('uploads', file[1])  # file[1] is the filename
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
        conn.commit()
        flash('File deleted successfully.', 'success')
    except Exception as e:
        flash('Error deleting file.', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('fileshare'))


#SCAN FOR SUSPICIOUS FILE USING MD5 UNIQUE
@app.route('/scan_file', methods=['POST'])
def scan_file():
    data = request.json
    filename = data.get('filename')
    md5_hash = data.get('md5')
    sha1_hash = data.get('sha1')
    sha256_hash = data.get('sha256')

    # Check all hash types
    results = {
        'md5': md5_hash in SUSPICIOUS_HASHES['md5'] if md5_hash else False,
        'sha1': sha1_hash in SUSPICIOUS_HASHES['sha1'] if sha1_hash else False,
        'sha256': sha256_hash in SUSPICIOUS_HASHES['sha256'] if sha256_hash else False
    }

    # If any hash matches, return suspicious
    if any(results.values()):
        return jsonify({
            "status": "suspicious",
            "details": results
        })
    else:
        return jsonify({"status": "clean"})


#LOG-OUT FUNCTION FOR USER
@app.route('/logout')
@login_required
def logout():
    # Remove user from activity tracking when they log out
    if current_user.is_authenticated:
        user_id_str = str(current_user.id)
        if user_id_str in user_last_activity:
            user_last_activity.pop(user_id_str)
    
    # Check if user is being logged out after password change
    password_changed = session.pop('password_change_success', False)
    
    session.pop('otp_verified', None)
    logout_user()
    
    if password_changed:
        flash('Password changed successfully. Please log in with your new password.', 'success')
    else:
        flash('Logged out.', 'info')
        
    return redirect(url_for('login'))

#CHANGE PASS FOR FIRST TIME LOG-IN
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Fetch the current user's details
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = %s", (current_user.id,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[0], current_password):
            if new_password == confirm_password:
                # Hash the new password
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

                # Update the password and set password_changed to True
                cursor.execute("""
                    UPDATE users 
                    SET password = %s, password_changed = TRUE 
                    WHERE id = %s
                """, (hashed_password, current_user.id))
                conn.commit()
                cursor.close()
                conn.close()

                flash('Password changed successfully.', 'success')
                return redirect(url_for('verify_otp'))  # Redirect to OTP verification after password change
            else:
                flash('New password and confirm password do not match.', 'danger')
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('change_password.html')

#toggle for block incoming files settings 
@app.route('/toggle_block_incoming_files', methods=['POST'])
@login_required
def toggle_block_incoming_files():
    data = request.get_json()
    block = data.get('block', False)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET block_incoming_files = %s WHERE id = %s", 
                      (block, current_user.id))
        conn.commit()
        
        # Update the current_user object to reflect the change immediately
        current_user.block_incoming_files = block
        
        # Log the activity
        action = 'enabled' if block else 'disabled'
        log_activity(current_user.id, 'security_setting', f'User {action} block incoming files')
        
        return jsonify({'success': True, 'blocked': block})
    except Exception as e:
        print(f"Error updating block incoming files setting: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Change password from profile page with OTP verification
@app.route('/profile_change_password', methods=['POST'])
@login_required
def profile_change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Fetch the current user's details
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password, role FROM users WHERE id = %s", (current_user.id,))
    user_data = cursor.fetchone()
    
    if not user_data:
        flash('User not found.', 'danger')
        return redirect(url_for('userprofile'))
    
    user_password = user_data[0]
    user_role = user_data[1]
    
    # Verify current password
    if not bcrypt.check_password_hash(user_password, current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('userprofile'))
    
    # Verify new password and confirmation match
    if new_password != confirm_password:
        flash('New password and confirm password do not match.', 'danger')
        return redirect(url_for('userprofile'))
    
    # Get user's contact number for OTP
    if user_role == 'barangay-captain':
        cursor.execute("SELECT contact_number FROM brgycaptain WHERE user_id = %s", (current_user.id,))
    elif user_role == 'government-position':
        cursor.execute("SELECT contact_number FROM government_position WHERE user_id = %s", (current_user.id,))
    elif user_role == 'municipal-employee':
        cursor.execute("SELECT contact_number FROM employee WHERE user_id = %s", (current_user.id,))
    
    contact_number = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    
    if not contact_number:
        flash('Contact number not found. Please contact administrator.', 'danger')
        return redirect(url_for('userprofile'))
    
    # Generate and send OTP
    otp = generate_otp()
    session['otp'] = otp
    session['password_change_data'] = {
        'new_password': new_password,
        'user_id': current_user.id
    }
    
    # Send OTP via SMS
    if send_otp_via_sms(contact_number, otp):
        flash('An OTP has been sent to your registered phone number for verification.', 'info')
    else:
        flash('Failed to send OTP. Please try again.', 'danger')
        return redirect(url_for('userprofile'))
    
    return redirect(url_for('verify_password_change_otp'))

# Verify OTP for password change
@app.route('/verify_password_change_otp', methods=['GET', 'POST'])
@login_required
def verify_password_change_otp():
    if 'password_change_data' not in session:
        flash('Invalid session. Please try changing your password again.', 'danger')
        return redirect(url_for('userprofile'))
    
    if request.method == 'POST':
        user_otp = request.form['otp']
        if 'otp' in session and user_otp == session['otp']:
            # OTP verified, proceed with password change
            new_password = session['password_change_data']['new_password']
            user_id = session['password_change_data']['user_id']
            
            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            # Update password and set OTP expiration to 1 day from now
            otp_expires_at = datetime.now() + timedelta(days=1)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET password = %s, otp_expires_at = %s
                WHERE id = %s
            """, (hashed_password, otp_expires_at, user_id))
            conn.commit()
            cursor.close()
            conn.close()
            
            # Log the activity
            log_activity(user_id, 'Password Changed', 'User changed their password')
            
            # Clear session data
            session.pop('otp', None)
            session.pop('password_change_data', None)
            
            # Set flash message for after logout
            session['password_change_success'] = True
            
            # Redirect to logout instead of profile
            return redirect(url_for('logout'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    
    # Fetch the user's phone number for display
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = %s", (current_user.id,))
    role = cursor.fetchone()[0]
    
    if role == 'barangay-captain':
        cursor.execute("SELECT contact_number FROM brgycaptain WHERE user_id = %s", (current_user.id,))
    elif role == 'government-position':
        cursor.execute("SELECT contact_number FROM government_position WHERE user_id = %s", (current_user.id,))
    elif role == 'municipal-employee':
        cursor.execute("SELECT contact_number FROM employee WHERE user_id = %s", (current_user.id,))
    
    phone_number = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    
    # Mask the phone number except for the last 4 digits
    masked_phone_number = '*******' + phone_number[-4:]
    
    return render_template('verify_otp.html', masked_phone_number=masked_phone_number)


#FOR VERIFY OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    if 'otp_verified' not in session and current_user.is_authenticated:
        user_id_str = str(current_user.id)
        if user_id_str in user_last_activity:
            user_last_activity.pop(user_id_str)
    
    if request.method == 'POST':
        user_otp = request.form['otp']
        if 'otp' in session and user_otp == session['otp']:
            session.pop('otp', None)
            session['otp_verified'] = True
            
            # Set OTP expiration to 1 day from now
            otp_expires_at = datetime.now() + timedelta(days=1)
            
            # Update the database with the new expiration time
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET otp_expires_at = %s WHERE id = %s", 
                          (otp_expires_at, current_user.id))
            conn.commit()
            cursor.close()
            conn.close()
            
            update_user_activity(current_user.id)
            flash('Login successful.', 'success')
            return redirect(url_for('userdashboard'))
        else:
            flash('Invalid OTP.', 'danger')
    
    # Fetch the user's phone number
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT role FROM users WHERE id = %s", (current_user.id,))
    role = cursor.fetchone()[0]
    
    if role == 'barangay-captain':
        cursor.execute("SELECT contact_number FROM brgycaptain WHERE user_id = %s", (current_user.id,))
    elif role == 'government-position':
        cursor.execute("SELECT contact_number FROM government_position WHERE user_id = %s", (current_user.id,))
    elif role == 'municipal-employee':
        cursor.execute("SELECT contact_number FROM employee WHERE user_id = %s", (current_user.id,))
    
    phone_number = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    
    masked_phone_number = '*******' + phone_number[-4:]
    
    return render_template('verify_otp.html', masked_phone_number=masked_phone_number)

# FOR RESEND OTP
@app.route('/resend_otp', methods=['POST'])
@login_required
def resend_otp():
    # Check if 60 seconds have passed since last OTP request
    last_otp_time = session.get('otp_timestamp')
    if last_otp_time and (datetime.now().timestamp() - last_otp_time) < 60:
        return jsonify({'success': False, 'message': 'Please wait 60 seconds before requesting a new OTP'})

    # Fetch user's phone number again
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch the user's role
    cursor.execute("SELECT role FROM users WHERE id = %s", (current_user.id,))
    role = cursor.fetchone()[0]
    
    # Fetch the phone number based on the role
    if role == 'barangay-captain':
        cursor.execute("SELECT contact_number FROM brgycaptain WHERE user_id = %s", (current_user.id,))
    elif role == 'government-position':
        cursor.execute("SELECT contact_number FROM government_position WHERE user_id = %s", (current_user.id,))
    elif role == 'municipal-employee':
        cursor.execute("SELECT contact_number FROM employee WHERE user_id = %s", (current_user.id,))
    
    phone_number = cursor.fetchone()[0]
    cursor.close()
    conn.close()

    # Generate and send new OTP
    new_otp = generate_otp()
    session['otp'] = new_otp
    session['otp_timestamp'] = datetime.now().timestamp()  # Store timestamp
    
    if send_otp_via_sms(phone_number, new_otp):
        return jsonify({'success': True, 'message': 'New OTP has been sent'})
    else:
        return jsonify({'success': False, 'message': 'Failed to send OTP. Please try again.'})

@app.route('/some_protected_route')
@login_required
def some_protected_route():
    if 'otp_verified' not in session:
        flash('Please verify your OTP to access this page.', 'info')
        return redirect(url_for('verify_otp'))
    
#profile picture 
@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('userprofile'))
    
    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('userprofile'))
    
    if file:
        try:
            if not os.path.exists('uploads/profile_pictures'):
                os.makedirs('uploads/profile_pictures')
            
            # Read the image using PIL
            image_data = file.read()
            img = Image.open(io.BytesIO(image_data))
            
            # Apply EXIF orientation correction
            img = ImageOps.exif_transpose(img)
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            MAX_SIZE = (500, 500)
            img.thumbnail(MAX_SIZE, Image.LANCZOS)
            
            # Compress the image
            output = io.BytesIO()
            img.save(output, format='JPEG', quality=85) 
            compressed_data = output.getvalue()
            
            # Encrypt the compressed data
            encrypted_file = cipher.encrypt(compressed_data)
            
            filename = f"profile_{current_user.id}.jpg"
            file_path = os.path.join('uploads/profile_pictures', filename)
            with open(file_path, 'wb') as f:
                f.write(encrypted_file)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET profile_picture = %s WHERE id = %s", (filename, current_user.id))
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Profile picture uploaded successfully', 'success')
            return redirect(url_for('userprofile'))
        
        except Exception as e:
            flash(f'Failed to upload profile picture: {str(e)}', 'danger')
            return redirect(url_for('userprofile'))
    
    flash('Failed to upload profile picture', 'danger')
    return redirect(url_for('userprofile'))


@app.route('/profile_picture/<int:user_id>')
def profile_picture(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_picture FROM users WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if result and result[0]:  # Check if profile_picture exists
        file_path = os.path.join('uploads/profile_pictures', result[0])
        if os.path.exists(file_path):
            try:
                with open(file_path, 'rb') as f:
                    encrypted_file = f.read()
                    decrypted_file = cipher.decrypt(encrypted_file)
                    return send_file(BytesIO(decrypted_file), mimetype='image/jpeg')
            except Exception as e:
                print(f"Error decrypting image: {e}")

    # Return default image if nothing found or error
    return send_file('static/img/pic.png', mimetype='image/png')


@app.route('/remove_profile_picture', methods=['POST'])
@login_required
def remove_profile_picture():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_picture FROM users WHERE id = %s", (current_user.id,))
    result = cursor.fetchone()
    profile_picture = result[0] if result else None

    if profile_picture:
        file_path = os.path.join('uploads/profile_pictures', profile_picture)
        if os.path.exists(file_path):
            os.remove(file_path)

    cursor.execute("UPDATE users SET profile_picture = NULL WHERE id = %s", (current_user.id,))


@app.route('/view_inquiry_screenshot/<int:inquiry_id>')
def view_inquiry_screenshot(inquiry_id):
    # Check if user is logged in or admin is in session
    if 'user_id' not in session and 'admin' not in session:
        flash('Please log in to view this content.', 'warning')
        return redirect(url_for('login'))
    # Get the inquiry details to verify ownership and get the screenshot filename
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # First check if the inquiry belongs to the current user or if user is admin
    if 'admin' in session:
        cursor.execute("SELECT screenshot FROM user_inquiries WHERE id = %s", (inquiry_id,))
    else:
        cursor.execute("SELECT screenshot FROM user_inquiries WHERE id = %s AND user_id = %s", 
                      (inquiry_id, session.get('user_id')))
    
    inquiry = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not inquiry or not inquiry['screenshot']:
        flash('Screenshot not found or you do not have permission to view it.', 'danger')
        if 'admin' in session:
            return redirect(url_for('admin_inquiries'))
        else:
            return redirect(url_for('userhelp'))
    
    # Construct the path to the screenshot file
    screenshot_path = os.path.join(app.config['UPLOAD_FOLDER'], 'user_inquiries', inquiry['screenshot'])
    
    # Check if the file exists
    if not os.path.exists(screenshot_path):
        flash('Screenshot file not found.', 'danger')
        if 'admin' in session:
            return redirect(url_for('admin_inquiries'))
        else:
            return redirect(url_for('userhelp'))
    
    # Return the file
    return send_file(screenshot_path)
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'success': True})
    
    # Route to display the messaging interface
@app.route('/messages', methods=['GET'])
@login_required
def messages():
    if 'otp_verified' not in session:
        flash('Please verify your OTP to access the messaging system.', 'info')
        return redirect(url_for('verify_otp'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all users except the current user for the recipient list
    cursor.execute("""
        SELECT u.id, u.username, u.profile_picture,
               COALESCE(b.first_name, g.first_name, e.first_name) AS first_name,
               COALESCE(b.last_name, g.last_name, e.last_name) AS last_name
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id != %s
    """, (current_user.id,))
    users = cursor.fetchall()

    # Fetch messages for the current user
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, 
               u1.username as sender_username, 
               COALESCE(b1.first_name, g1.first_name, e1.first_name) AS sender_first_name,
               COALESCE(b1.last_name, g1.last_name, e1.last_name) AS sender_last_name,
               u1.profile_picture as sender_profile_picture,
               u2.username as receiver_username, 
               COALESCE(b2.first_name, g2.first_name, e2.first_name) AS receiver_first_name,
               COALESCE(b2.last_name, g2.last_name, e2.last_name) AS receiver_last_name,
               u2.profile_picture as receiver_profile_picture
        FROM messages m
        JOIN users u1 ON m.sender_id = u1.id
        JOIN users u2 ON m.receiver_id = u2.id
        LEFT JOIN brgycaptain b1 ON u1.id = b1.user_id
        LEFT JOIN government_position g1 ON u1.id = g1.user_id
        LEFT JOIN employee e1 ON u1.id = e1.user_id
        LEFT JOIN brgycaptain b2 ON u2.id = b2.user_id
        LEFT JOIN government_position g2 ON u2.id = g2.user_id
        LEFT JOIN employee e2 ON u2.id = e2.user_id
        WHERE m.sender_id = %s OR m.receiver_id = %s
        ORDER BY m.created_at DESC
    """, (current_user.id, current_user.id))
    messages = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('messages.html', users=users, messages=messages)

@app.route('/mark_as_read/<int:message_id>', methods=['POST'])
@login_required
def mark_as_read(message_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE messages 
        SET is_read = TRUE 
        WHERE id = %s AND receiver_id = %s
    """, (message_id, current_user.id))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'success': True})

# Route to send a message
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    if 'otp_verified' not in session:
        return jsonify({'success': False, 'message': 'Please verify your OTP to send messages.'})

    data = request.json
    receiver_id = data.get('receiver_id')  # Single receiver ID
    message = data.get('message')

    if not receiver_id or not message:
        return jsonify({'success': False, 'message': 'Receiver ID and message are required.'})

    # Encrypt the message using Fernet
    encrypted_message = cipher.encrypt(message.encode('utf-8'))

    # Save the encrypted message to the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, message)
        VALUES (%s, %s, %s)
    """, (current_user.id, receiver_id, encrypted_message))
    
    # Get the ID of the newly inserted message
    message_id = cursor.lastrowid
    conn.commit()
    
    # Fetch sender details for the response
    cursor.execute("""
        SELECT 
            COALESCE(b.first_name, g.first_name, e.first_name) AS first_name,
            COALESCE(b.last_name, g.last_name, e.last_name) AS last_name,
            u.profile_picture
        FROM users u
        LEFT JOIN brgycaptain b ON u.id = b.user_id
        LEFT JOIN government_position g ON u.id = g.user_id
        LEFT JOIN employee e ON u.id = e.user_id
        WHERE u.id = %s
    """, (current_user.id,))
    sender_details = cursor.fetchone()
    cursor.close()
    conn.close()
    
    # Emit a Socket.IO event to the receiver's room
    socketio.emit('new_message', {
        'message_id': message_id,
        'sender_id': current_user.id,
        'message': message,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'sender_first_name': sender_details[0] if sender_details else None,
        'sender_last_name': sender_details[1] if sender_details else None,
        'sender_profile_picture': sender_details[2] if sender_details else None
    }, room=str(receiver_id))

    return jsonify({'success': True, 'message': 'Message sent successfully.'})

# Route to fetch messages between the current user and a specific user
@app.route('/get_messages/<int:receiver_id>', methods=['GET'])
@login_required
def get_messages(receiver_id):
    if 'otp_verified' not in session:
        return jsonify({'success': False, 'message': 'Please verify your OTP to view messages.'})

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, m.sender_id,
               COALESCE(b1.first_name, g1.first_name, e1.first_name) AS sender_first_name,
               COALESCE(b1.last_name, g1.last_name, e1.last_name) AS sender_last_name,
               u1.profile_picture as sender_profile_picture
        FROM messages m
        LEFT JOIN brgycaptain b1 ON m.sender_id = b1.user_id
        LEFT JOIN government_position g1 ON m.sender_id = g1.user_id
        LEFT JOIN employee e1 ON m.sender_id = e1.user_id
        LEFT JOIN users u1 ON m.sender_id = u1.id
        WHERE (m.sender_id = %s AND m.receiver_id = %s) OR (m.sender_id = %s AND m.receiver_id = %s)
        ORDER BY m.created_at ASC
    """, (current_user.id, receiver_id, receiver_id, current_user.id))
    messages = cursor.fetchall()

    # Decrypt the messages
    for message in messages:
        try:
            decrypted_message = cipher.decrypt(message['message'].encode('utf-8')).decode('utf-8')
            message['message'] = decrypted_message
        except Exception as e:
            print(f"Error decrypting message: {e}")
            message['message'] = "[Unable to decrypt message]"

    cursor.close()
    conn.close()

    return jsonify({'success': True, 'messages': messages})

# Route to check for new messages from all users
@app.route('/check_all_new_messages', methods=['GET'])
@login_required
def check_all_new_messages():
    if 'otp_verified' not in session:
        return jsonify({'success': False, 'message': 'Please verify your OTP to view messages.'})

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get the last message time for each conversation
    cursor.execute("""
        SELECT 
            CASE 
                WHEN m.sender_id = %s THEN m.receiver_id 
                ELSE m.sender_id 
            END AS other_user_id,
            MAX(m.created_at) as last_message_time,
            COUNT(CASE WHEN m.is_read = FALSE AND m.receiver_id = %s THEN 1 END) as unread_count
        FROM messages m
        WHERE m.sender_id = %s OR m.receiver_id = %s
        GROUP BY other_user_id
    """, (current_user.id, current_user.id, current_user.id, current_user.id))
    
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return jsonify({'success': True, 'results': results})

@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    notifications = get_user_notifications(session['user_id'], 20)
    return render_template('notifications.html', notifications=notifications)

@app.route('/mark_notification_read/<int:notification_id>')
def mark_notification_read_route(notification_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    mark_notification_as_read(notification_id)
    return redirect(request.referrer or url_for('userdashboard'))

@app.route('/mark_all_notifications_read')
def mark_all_notifications_read_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    mark_all_notifications_as_read(session['user_id'])
    return redirect(request.referrer or url_for('userdashboard'))

@app.route('/check_expiring_files')
def check_expiring_files_route():
    # This should be called by a cron job or scheduler
    count = check_expiring_files()
    return f"Checked {count} expiring files"

# Add this route to handle rating submission
@app.route('/submit_rating', methods=['POST'])
@login_required
def submit_rating():
    if 'otp_verified' not in session:
        return jsonify({'success': False, 'message': 'Please verify your OTP first.'})
    
    data = request.get_json()
    rating = data.get('rating')
    comment = data.get('comment', '')
    
    if not rating or int(rating) < 1 or int(rating) > 5:
        return jsonify({'success': False, 'message': 'Please provide a valid rating (1-5).'})
    
    success = save_user_rating(current_user.id, int(rating), comment)
    
    if success:
        # Log the activity
        log_activity(current_user.id, 'system_rating', f'User rated the system {rating} stars')
        return jsonify({'success': True, 'message': 'Thank you for your feedback!'})
    else:
        return jsonify({'success': False, 'message': 'Failed to save rating. Please try again.'})

# Socket.IO event handlers
#@socketio.on('connect')
#def handle_connect():
#    print(f'Client connected: {request.sid}')

#@socketio.on('disconnect')
#def handle_disconnect():
#    print(f'Client disconnected: {request.sid}')

@socketio.on('join')
def handle_join(data):
    user_id = data.get('user_id')
    if user_id:
        # Join a room named after the user's ID to receive private messages
        join_room(str(user_id))
        #print(f'User {user_id} joined their room')

@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session or 'otp_verified' not in session:
        emit('error', {'message': 'Authentication required'})
        return
    
    sender_id = session['user_id']
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
    if not receiver_id or not message:
        emit('error', {'message': 'Receiver ID and message are required'})
        return
    
    try:
        # Encrypt the message using Fernet
        encrypted_message = cipher.encrypt(message.encode('utf-8'))
        
        # Save the encrypted message to the database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, message)
            VALUES (%s, %s, %s)
        """, (sender_id, receiver_id, encrypted_message))
        
        # Get the ID of the newly inserted message
        message_id = cursor.lastrowid
        
        # Fetch sender details for the response
        cursor.execute("""
            SELECT 
                COALESCE(b.first_name, g.first_name, e.first_name) AS first_name,
                COALESCE(b.last_name, g.last_name, e.last_name) AS last_name,
                u.profile_picture
            FROM users u
            LEFT JOIN brgycaptain b ON u.id = b.user_id
            LEFT JOIN government_position g ON u.id = g.user_id
            LEFT JOIN employee e ON u.id = e.user_id
            WHERE u.id = %s
        """, (sender_id,))
        sender_details = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        # Prepare message data for both sender and receiver
        message_data = {
            'message_id': message_id,
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': message,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'sender_first_name': sender_details['first_name'] if sender_details else None,
            'sender_last_name': sender_details['last_name'] if sender_details else None,
            'sender_profile_picture': sender_details['profile_picture'] if sender_details else None
        }
        
        # Emit to receiver's room
        emit('new_message', message_data, room=str(receiver_id))
        # Also emit back to sender for confirmation
        emit('message_sent', message_data)
        
    except Exception as e:
        print(f"Error sending message via Socket.IO: {e}")
        emit('error', {'message': f'Failed to send message: {str(e)}'})

# File upload Socket.IO event handlers
@socketio.on('upload_start')
def handle_upload_start(data):
    """Initialize upload progress tracking when a file upload starts"""
    user_id = data.get('user_id')
    file_id = data.get('file_id')  # A unique identifier for this upload
    filename = data.get('filename')
    total_size = data.get('total_size')
    file_index = data.get('file_index', 0)  # Position in the upload queue
    total_files = data.get('total_files', 1)  # Total number of files being uploaded
    
    if user_id and file_id:
        # Initialize progress tracking for this upload
        upload_progress[file_id] = {
            'user_id': user_id,
            'filename': filename,
            'total_size': total_size,
            'uploaded_size': 0,
            'start_time': time.time(),
            'status': 'in_progress',
            'file_index': file_index,
            'total_files': total_files
        }
        
        # Emit initial progress
        socketio.emit('upload_progress', {
            'file_id': file_id,
            'filename': filename,
            'progress': 0,
            'uploaded_size': 0,
            'total_size': total_size,
            'speed': 0,
            'status': 'started',
            'file_index': file_index,
            'total_files': total_files
        }, room=str(user_id))

@socketio.on('upload_progress_update')
def handle_upload_progress(data):
    """Update upload progress during file upload"""
    user_id = data.get('user_id')
    file_id = data.get('file_id')
    uploaded_size = data.get('uploaded_size')
    
    if file_id in upload_progress:
        progress_data = upload_progress[file_id]
        progress_data['uploaded_size'] = uploaded_size
        
        # Calculate progress percentage
        total_size = progress_data['total_size']
        progress = (uploaded_size / total_size) * 100 if total_size > 0 else 0
        
        # Calculate upload speed
        elapsed_time = time.time() - progress_data['start_time']
        speed = uploaded_size / elapsed_time if elapsed_time > 0 else 0  # bytes per second
        
        # Emit progress update
        socketio.emit('upload_progress', {
            'file_id': file_id,
            'filename': progress_data['filename'],
            'progress': progress,
            'uploaded_size': uploaded_size,
            'total_size': total_size,
            'speed': speed,
            'status': 'in_progress',
            'file_index': progress_data.get('file_index', 0),
            'total_files': progress_data.get('total_files', 1)
        }, room=str(user_id))

@socketio.on('upload_complete')
def handle_upload_complete(data):
    """Mark upload as complete and clean up tracking data"""
    user_id = data.get('user_id')
    file_id = data.get('file_id')
    
    if file_id in upload_progress:
        progress_data = upload_progress[file_id]
        
        # Calculate final statistics
        total_time = time.time() - progress_data['start_time']
        avg_speed = progress_data['total_size'] / total_time if total_time > 0 else 0
        
        # Emit completion event
        socketio.emit('upload_progress', {
            'file_id': file_id,
            'filename': progress_data['filename'],
            'progress': 100,
            'uploaded_size': progress_data['total_size'],
            'total_size': progress_data['total_size'],
            'speed': avg_speed,
            'total_time': total_time,
            'status': 'completed',
            'file_index': progress_data.get('file_index', 0),
            'total_files': progress_data.get('total_files', 1)
        }, room=str(user_id))
        
        # Clean up
        del upload_progress[file_id]

# Main
if __name__ == '__main__':
    socketio.run(app, debug=True)
