# api-gateway/main.py - Complete CyberNova AI Backend
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
import httpx, os, asyncio, json, random, hashlib, jwt, smtplib, ssl, time
try:
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
except ImportError:
    # Fallback for email functionality
    MimeText = None
    MimeMultipart = None
from starlette.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
import sqlite3
import pymysql
from contextlib import contextmanager
import bcrypt
from agent import (
    perform_real_threat_scan,        # Main function to perform the full scan
    scan_real_processes,             # To scan processes
    scan_real_network_connections,   # To scan network connections
    scan_real_open_ports,             # To scan for risky ports
    get_real_system_info,             # To read system info
    send_scan_results                # To send results to backend (optional)
)
import pytz


app = FastAPI(
    title="CyberNova AI - Advanced Cybersecurity Platform", 
    version="3.0",
    description="Next-generation AI-powered cybersecurity platform with real-time threat detection"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
)

# Configuration
DETECTION_SERVICE_URL = os.getenv("DETECTION_SERVICE_URL", "http://detection-service:8081")
ANALYTICS_SERVICE_URL = os.getenv("ANALYTICS_SERVICE_URL", "http://analytics-service:8083")
JWT_SECRET = os.getenv("JWT_SECRET", "plus-one")
JWT_ALGORITHM = "HS256"
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "cybernova073@gmail.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "hsrz fymn gplp enbp")
SIMULATION_MODE = os.getenv("SIMULATION_MODE", "false").lower() == "true"


# Security
security = HTTPBearer()

# Database Configuration
DATABASE_PATH = "cybernova.db"

# MySQL Configuration (for production deployment)
MYSQL_HOST = os.getenv("MYSQLHOST")
MYSQL_PORT = int(os.getenv("MYSQLPORT", "3306"))
MYSQL_USER = os.getenv("MYSQLUSER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_ROOT_PASSWORD")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "railway")
USE_MYSQL = bool(MYSQL_HOST and MYSQL_PASSWORD)

# Pydantic Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    company: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class WaitlistEntry(BaseModel):
    email: EmailStr

class ThreatAlert(BaseModel):
    threat_type: str
    severity: str
    source_ip: str
    description: str
    risk_score: int

class User(BaseModel):
    id: int
    email: str
    full_name: str
    company: Optional[str]
    is_active: bool
    created_at: datetime

# WebSocket Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

# Database Functions
def init_database():
    """Initialize database with all required tables (MySQL or SQLite)"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
    
        # Users table
        if USE_MYSQL:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255) NOT NULL,
                    company VARCHAR(255),
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        else:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    company TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
    
    # Waitlist table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS waitlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # System scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            system_info TEXT,
            threats_detected INTEGER DEFAULT 0,
            scan_status TEXT DEFAULT 'completed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Network connections table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            hostname TEXT,
            service_info TEXT,
            activity_description TEXT,
            status TEXT,
            pid INTEGER,
            process_name TEXT,
            process_exe TEXT,
            process_cmdline TEXT,
            threat_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
        )
    ''')
    
    # Suspicious processes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            pid INTEGER,
            name TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            threat_level TEXT,
            threat_reasons TEXT,
            exe_path TEXT,
            cmdline TEXT,
            username TEXT,
            network_activity TEXT,
            behavior_analysis TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
        )
    ''')
    
    # Risky ports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risky_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            port INTEGER,
            service TEXT,
            threat_level TEXT,
            reason TEXT,
            recommendation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
        )
    ''')
    
    # Threat history table (permanent storage)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            description TEXT,
            risk_score INTEGER,
            is_resolved BOOLEAN DEFAULT FALSE,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Security recommendations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            type TEXT,
            priority TEXT,
            title TEXT,
            description TEXT,
            action TEXT,
            details TEXT,
            is_sent BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES system_scans (scan_id)
        )
    ''')
    
    # Analytics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_type TEXT NOT NULL,
            metric_value REAL NOT NULL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

@contextmanager
def get_db_connection():
    """Get database connection (MySQL or SQLite)"""
    if USE_MYSQL:
        # Use MySQL for production
        connection = None
        try:
            connection = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DATABASE,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=False
            )
            yield connection
        except Exception as e:
            if connection:
                connection.rollback()
            raise e
        finally:
            if connection:
                connection.close()
    else:
        # Use SQLite for local development
        conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrent access
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=1000")
        conn.execute("PRAGMA temp_store=memory")
        try:
            yield conn
        finally:
            conn.close()

# Utility Functions
async def _get(url, default=None):
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.json()
    except Exception:
        return default

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

ist = pytz.timezone('Asia/Kolkata')
def create_jwt_token(user_id: int, email: str) -> str:
    """Create JWT token"""
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(ist) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    payload = verify_jwt_token(credentials.credentials)
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ? AND is_active = TRUE", 
        (payload["user_id"],)
    ).fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return dict(user)

def send_email(to_email: str, subject: str, body: str):
    """Send a real email via SMTP (TLS)."""
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS]):
        print("[WARN] Email not configured")
        return

    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls(context=context)
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
        print(f"[INFO] Email sent to {to_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.post("/api/auth/register")
async def register_user(user_data: UserRegister, background_tasks: BackgroundTasks):
    """Register new user"""
    conn = get_db_connection()
    
    # Check if user already exists
    existing_user = conn.execute(
        "SELECT id FROM users WHERE email = ?", (user_data.email,)
    ).fetchone()
    
    if existing_user:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password and create user
    password_hash = hash_password(user_data.password)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, full_name, company) VALUES (?, ?, ?, ?)",
        (user_data.email, password_hash, user_data.full_name, user_data.company)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Create JWT token
    token = create_jwt_token(user_id, user_data.email)
    
    # Send welcome email
    welcome_email = f"""
🛡️ Welcome to CyberNova AI!

Hi {user_data.full_name},

Your account has been successfully created! You now have access to our advanced cybersecurity platform.

🚀 What's Next:
✅ Complete your security profile
✅ Set up threat monitoring
✅ Configure alert preferences
✅ Explore AI-powered analytics

🔗 Login to your dashboard: http://localhost:3000/dashboard

Best regards,
The CyberNova AI Team
cybernova073@gmail.com
    """
    
    background_tasks.add_task(
        send_email, 
        user_data.email, 
        "🛡️ Welcome to CyberNova AI - Account Created!", 
        welcome_email
    )
    
    return {
        "message": "User registered successfully",
        "token": token,
        "user": {
            "id": user_id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "company": user_data.company
        }
    }

@app.post("/api/auth/login")
async def login_user(login_data: UserLogin):
    """Login user"""
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ? AND is_active = TRUE", 
        (login_data.email,)
    ).fetchone()
    conn.close()
    
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_jwt_token(user["id"], user["email"])
    
    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "company": user["company"]
        }
    }

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "company": current_user["company"],
        "created_at": current_user["created_at"]
    }

# ============================================================================
# WAITLIST ENDPOINTS
# ============================================================================

@app.post("/api/waitlist")
async def join_waitlist(waitlist_entry: WaitlistEntry, background_tasks: BackgroundTasks):
    """Add email to waitlist"""
    conn = get_db_connection()
    
    # Check if email already exists
    existing = conn.execute(
        "SELECT id FROM waitlist WHERE email = ?", (waitlist_entry.email,)
    ).fetchone()
    
    if existing:
        conn.close()
        return {"message": "Email already on waitlist", "status": "existing"}
    
    # Add to waitlist
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO waitlist (email) VALUES (?)", (waitlist_entry.email,)
    )
    conn.commit()
    conn.close()
    
    # Send waitlist email
    waitlist_email = f"""
🛡️ CyberNova AI - Next-Generation Cybersecurity Platform

Thank you for joining our exclusive waitlist!

🗓️ LAUNCH DATE: September 15, 2025

What you'll get:
✅ Early access to CyberNova AI platform
✅ Special launch pricing (up to 50% off)
✅ Priority customer support
✅ Beta testing opportunities

We're building the most advanced AI-powered cybersecurity
platform ever created. You'll be among the first to experience:

🔹 Real-time threat detection (<100ms response)
🔹 AI-powered risk assessment
🔹 Automated incident response
🔹 Intelligent security analytics
🔹 24/7 monitoring and alerts

Stay tuned for more updates as we approach launch!

Best regards,
The CyberNova AI Team
cybernova073@gmail.com
    """
    
    background_tasks.add_task(
        send_email,
        waitlist_entry.email,
        "🚀 Welcome to CyberNova AI Waitlist!",
        waitlist_email
    )
    
    return {"message": "Successfully joined waitlist", "status": "success"}

# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================

@app.get("/api/dashboard/stats")
async def dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get real dashboard statistics from actual scans (no duplicates)"""
    conn = get_db_connection()
    
    # Get latest scan data
    latest_scan = conn.execute("""
        SELECT * FROM system_scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    """, (current_user["id"],)).fetchone()
    
    # Get current active threats from LATEST scan only (prevents duplication)
    if latest_scan:
        scan_id = latest_scan["scan_id"]
        
        # Count threats from the latest scan only
        process_threats = conn.execute("""
            SELECT COUNT(*) as count FROM suspicious_processes 
            WHERE scan_id = ? AND threat_level IN ('high', 'critical')
        """, (scan_id,)).fetchone()["count"]
        
        port_threats = conn.execute("""
            SELECT COUNT(*) as count FROM risky_ports 
            WHERE scan_id = ? AND threat_level IN ('high', 'critical')
        """, (scan_id,)).fetchone()["count"]
        
        network_threats = conn.execute("""
            SELECT COUNT(*) as count FROM network_connections 
            WHERE scan_id = ? AND threat_level IN ('high', 'critical')
        """, (scan_id,)).fetchone()["count"]
        
        total_threats = process_threats + port_threats + network_threats
        
        # Use the scan's recorded threat count as authoritative
        recorded_threats = latest_scan["threats_detected"] or 0
        total_threats = max(total_threats, recorded_threats)
        
    else:
        total_threats = 0
    
    # Calculate system health based on current threats
    risk_score = min(100, max(0, total_threats * 15))
    system_health = max(0, 100 - (total_threats * 10))
    
    conn.close()
    
    return {
        "totalThreats": int(total_threats),
        "activeAlerts": int(total_threats),  # Same as total for current session
        "riskScore": round(float(risk_score), 2),
        "systemHealth": round(float(system_health), 2),
        "lastScanTime": latest_scan["created_at"] if latest_scan else None,
        "scanStatus": latest_scan["scan_status"] if latest_scan else "No scans yet"
    }

def get_threat_resolution(threat_type, severity, description):
    """Get resolution recommendations for different threat types"""
    resolutions = {
        "Suspicious Process": {
            "critical": {
                "action": "Immediate Action Required",
                "steps": [
                    "1. Terminate the suspicious process immediately",
                    "2. Run a full system antivirus scan",
                    "3. Check for unauthorized system changes",
                    "4. Update all security software",
                    "5. Consider system restore if needed"
                ],
                "prevention": "Keep antivirus updated, avoid suspicious downloads"
            },
            "high": {
                "action": "Action Recommended",
                "steps": [
                    "1. Investigate the process in Task Manager",
                    "2. Check process location and digital signature",
                    "3. Run antivirus scan if suspicious",
                    "4. Monitor system performance"
                ],
                "prevention": "Regular system scans, software updates"
            }
        },
        "Risky Port": {
            "critical": {
                "action": "Secure Network Immediately",
                "steps": [
                    "1. Close unnecessary open ports",
                    "2. Configure firewall rules",
                    "3. Check for unauthorized services",
                    "4. Update network security settings",
                    "5. Monitor network traffic"
                ],
                "prevention": "Regular firewall audits, disable unused services"
            },
            "high": {
                "action": "Review Network Security",
                "steps": [
                    "1. Verify if the service is needed",
                    "2. Configure proper access controls",
                    "3. Update service if outdated",
                    "4. Monitor port activity"
                ],
                "prevention": "Regular security audits, principle of least privilege"
            }
        },
        "Suspicious Network Activity": {
            "critical": {
                "action": "Block Suspicious Traffic",
                "steps": [
                    "1. Block suspicious IP addresses",
                    "2. Check for malware infections",
                    "3. Review network logs",
                    "4. Update firewall rules",
                    "5. Consider network isolation if needed"
                ],
                "prevention": "Use reputable DNS, avoid suspicious websites"
            },
            "high": {
                "action": "Monitor Network Activity",
                "steps": [
                    "1. Review connection details",
                    "2. Check if connection is legitimate",
                    "3. Monitor for unusual data transfer",
                    "4. Update security software"
                ],
                "prevention": "Regular network monitoring, secure browsing habits"
            }
        }
    }
    
    # Default resolution for unknown threats
    default_resolution = {
        "action": "General Security Review",
        "steps": [
            "1. Run a full system security scan",
            "2. Update all software and security patches",
            "3. Review recent system changes",
            "4. Monitor system behavior"
        ],
        "prevention": "Keep systems updated, use reputable security software"
    }
    
    threat_category = "Suspicious Process"
    if "port" in description.lower() or "service" in description.lower():
        threat_category = "Risky Port"
    elif "network" in description.lower() or "connection" in description.lower():
        threat_category = "Suspicious Network Activity"
    
    return resolutions.get(threat_category, {}).get(severity.lower(), default_resolution)

@app.get("/api/dashboard/alerts")
async def dashboard_alerts(current_user: dict = Depends(get_current_user)):
    """Get recent real threat alerts from latest scan only (no duplicates)"""
    conn = get_db_connection()
    
    # Get the latest scan for this user
    latest_scan = conn.execute("""
        SELECT scan_id FROM system_scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    """, (current_user["id"],)).fetchone()
    
    if not latest_scan:
        conn.close()
        return []
    
    scan_id = latest_scan["scan_id"]
    
    # Get threats from LATEST scan only to prevent duplicates
    alerts_query = """
    SELECT 
        'process_' || sp.name || '_' || sp.pid as id,
        'Suspicious Process: ' || sp.name as title,
        'Real threat detected: ' || sp.name || ' (PID: ' || sp.pid || ')' as description,
        sp.threat_level as severity,
        s.created_at as timestamp,
        'Local System' as sourceIp,
        CASE sp.threat_level 
            WHEN 'critical' THEN 90
            WHEN 'high' THEN 70
            ELSE 50
        END as riskScore,
        0 as isBlocked,
        'process' as type,
        sp.threat_reasons as details
    FROM suspicious_processes sp
    JOIN system_scans s ON sp.scan_id = s.scan_id
    WHERE sp.scan_id = ? AND sp.threat_level IN ('high', 'critical')
    
    UNION ALL
    
    SELECT 
        'port_' || rp.port as id,
        'Risky Port: ' || rp.port || ' (' || COALESCE(rp.service, 'Unknown') || ')' as title,
        'Real vulnerability: ' || COALESCE(rp.reason, 'Port ' || rp.port || ' is exposed') as description,
        rp.threat_level as severity,
        s.created_at as timestamp,
        'Local System' as sourceIp,
        CASE rp.threat_level 
            WHEN 'critical' THEN 80
            WHEN 'high' THEN 60
            ELSE 40
        END as riskScore,
        0 as isBlocked,
        'port' as type,
        rp.reason as details
    FROM risky_ports rp
    JOIN system_scans s ON rp.scan_id = s.scan_id
    WHERE rp.scan_id = ? AND rp.threat_level IN ('high', 'critical')
    
    UNION ALL
    
    SELECT 
        'network_' || nc.remote_ip || '_' || nc.remote_port as id,
        'Suspicious Network Activity' as title,
        'Real network threat: ' || COALESCE(nc.activity_description, 'Suspicious connection detected') as description,
        nc.threat_level as severity,
        s.created_at as timestamp,
        nc.remote_ip as sourceIp,
        CASE nc.threat_level 
            WHEN 'critical' THEN 85
            WHEN 'high' THEN 65
            ELSE 45
        END as riskScore,
        0 as isBlocked,
        'network' as type,
        nc.activity_description as details
    FROM network_connections nc
    JOIN system_scans s ON nc.scan_id = s.scan_id
    WHERE nc.scan_id = ? AND nc.threat_level IN ('high', 'critical')
    
    ORDER BY timestamp DESC
    """
    
    threats = conn.execute(alerts_query, (scan_id, scan_id, scan_id)).fetchall()
    conn.close()
    
    alerts = []
    seen_ids = set()  # Additional deduplication
    
    for threat in threats:
        # Skip if we've already seen this threat ID
        if threat["id"] in seen_ids:
            continue
        seen_ids.add(threat["id"])
        
        # Get resolution recommendations
        resolution = get_threat_resolution(threat["title"], threat["severity"], threat["description"])
        
        alerts.append({
            "id": threat["id"],
            "title": threat["title"],
            "description": threat["description"],
            "severity": threat["severity"],
            "timestamp": threat["timestamp"],
            "sourceIp": threat["sourceIp"],
            "riskScore": threat["riskScore"],
            "isBlocked": bool(threat["isBlocked"]),
            "type": threat["type"],
            "resolution": resolution,
            "isReal": True  # Mark as real threat
        })
    
    return alerts

@app.get("/api/threat/{threat_id}/details")
async def get_threat_details(threat_id: str, current_user: dict = Depends(get_current_user)):
    """Get detailed information about a specific threat"""
    conn = get_db_connection()
    
    # Parse threat ID to determine type
    if threat_id.startswith("process_"):
        process_name = threat_id.replace("process_", "")
        threat_data = conn.execute("""
            SELECT sp.*, s.created_at, s.scan_id
            FROM suspicious_processes sp
            JOIN system_scans s ON sp.scan_id = s.scan_id
            WHERE s.user_id = ? AND sp.name = ?
            ORDER BY s.created_at DESC
            LIMIT 1
        """, (current_user["id"], process_name)).fetchone()
        
        if not threat_data:
            raise HTTPException(status_code=404, detail="Threat not found")
            
        resolution = get_threat_resolution("Suspicious Process", threat_data["threat_level"], f"Process: {process_name}")
        
        return {
            "id": threat_id,
            "type": "Suspicious Process",
            "name": process_name,
            "severity": threat_data["threat_level"],
            "riskScore": 90 if threat_data["threat_level"] == "critical" else 70,
            "detectedAt": threat_data["created_at"],
            "details": {
                "processName": process_name,
                "threatLevel": threat_data["threat_level"],
                "scanId": threat_data["scan_id"]
            },
            "resolution": resolution,
            "isActive": True
        }
    
    elif threat_id.startswith("port_"):
        port_num = threat_id.replace("port_", "")
        threat_data = conn.execute("""
            SELECT rp.*, s.created_at, s.scan_id
            FROM risky_ports rp
            JOIN system_scans s ON rp.scan_id = s.scan_id
            WHERE s.user_id = ? AND rp.port = ?
            ORDER BY s.created_at DESC
            LIMIT 1
        """, (current_user["id"], port_num)).fetchone()
        
        if not threat_data:
            raise HTTPException(status_code=404, detail="Threat not found")
            
        resolution = get_threat_resolution("Risky Port", threat_data["threat_level"], f"Port: {port_num}")
        threat_dict = dict(threat_data)


        return {
            "id": threat_id,
            "type": "Risky Port",
            "name": f"Port {port_num}",
            "severity": threat_data["threat_level"],
            "riskScore": 80 if threat_data["threat_level"] == "critical" else 60,
            "detectedAt": threat_data["created_at"],
            "details": {
                "port": port_num,
                "service": threat_dict.get("service", "Unknown"),
                "threatLevel": threat_data["threat_level"],
                "scanId": threat_data["scan_id"]
            },
            "resolution": resolution,
            "isActive": True
        }
    
    elif threat_id.startswith("network_"):
        # For network threats, we need to find by description pattern
        threat_data = conn.execute("""
            SELECT nc.*, s.created_at, s.scan_id
            FROM network_connections nc
            JOIN system_scans s ON nc.scan_id = s.scan_id
            WHERE s.user_id = ? AND nc.threat_level IN ('high', 'critical')
            ORDER BY s.created_at DESC
            LIMIT 1
        """, (current_user["id"],)).fetchone()
        
        if not threat_data:
            raise HTTPException(status_code=404, detail="Threat not found")
            
        resolution = get_threat_resolution("Suspicious Network Activity", threat_data["threat_level"], threat_data["activity_description"])
        
        return {
            "id": threat_id,
            "type": "Suspicious Network Activity",
            "name": "Network Connection",
            "severity": threat_data["threat_level"],
            "riskScore": 85 if threat_data["threat_level"] == "critical" else 65,
            "detectedAt": threat_data["created_at"],
            "details": {
                "description": threat_data["activity_description"],
                "threatLevel": threat_data["threat_level"],
                "scanId": threat_data["scan_id"]
            },
            "resolution": resolution,
            "isActive": True
        }
    
    conn.close()
    raise HTTPException(status_code=404, detail="Threat not found")

@app.post("/api/threat/{threat_id}/resolve")
async def resolve_threat(threat_id: str, current_user: dict = Depends(get_current_user)):
    """Mark a threat as resolved"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Update resolved status and timestamp for the threat
    cursor.execute("""
        UPDATE threats
        SET is_resolved = 1,
            resolved_at = ?
        WHERE id = ?
    """, (datetime.now(ist).isoformat(), threat_id))

    conn.commit()

    # Check if any row was updated
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")

    conn.close()

    return {
        "success": True,
        "message": "Threat marked as resolved",
        "threatId": threat_id,
        "resolvedAt": datetime.now(ist).isoformat()
    }


@app.post("/api/dashboard/reset")
async def reset_dashboard_data(current_user: dict = Depends(get_current_user)):
    """Reset/clear all scan data for the current user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Clear all scan-related data for this user
        cursor.execute("""
            DELETE FROM network_connections WHERE scan_id IN (
                SELECT scan_id FROM system_scans WHERE user_id = ?
            )
        """, (current_user["id"],))
        
        cursor.execute("""
            DELETE FROM suspicious_processes WHERE scan_id IN (
                SELECT scan_id FROM system_scans WHERE user_id = ?
            )
        """, (current_user["id"],))
        
        cursor.execute("""
            DELETE FROM risky_ports WHERE scan_id IN (
                SELECT scan_id FROM system_scans WHERE user_id = ?
            )
        """, (current_user["id"],))
        
        cursor.execute("""
            DELETE FROM security_recommendations WHERE scan_id IN (
                SELECT scan_id FROM system_scans WHERE user_id = ?
            )
        """, (current_user["id"],))
        
        cursor.execute("DELETE FROM system_scans WHERE user_id = ?", (current_user["id"],))
        cursor.execute("DELETE FROM threat_history WHERE user_id = ?", (current_user["id"],))
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "message": "Dashboard data reset successfully",
            "timestamp": datetime.now(ist).isoformat()
        }
        
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=f"Reset failed: {str(e)}")

@app.get("/api/dashboard/trends")
async def dashboard_trends(current_user: dict = Depends(get_current_user)):
    """Get threat trends data"""
    # Generate realistic hourly trends
    trends = []
    for hour in range(24):
        threats = random.randint(10, 50)
        blocked = random.randint(5, threats)
        trends.append({
            "time": f"{hour:02d}:00",
            "threats": threats,
            "blocked": blocked
        })
    
    return trends

# ============================================================================
# REAL SYSTEM SCANNING ENDPOINTS
# ============================================================================

@app.get("/api/test")
async def test_endpoint():
    """Test endpoint to verify backend is working"""
    return {"status": "Backend is working!", "timestamp": datetime.now(ist).isoformat()}

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "CyberNova AI Backend",
        "version": "1.0.0",
        "timestamp": datetime.now(ist).isoformat()
    }

def build_threat_summary_email(name: str, scan_id: str, processes: list, networks: list, ports: list) -> tuple[str, str]:
    total = len(processes) + len(networks) + len(ports)
    subject = f"🚨 CyberNova AI: {total} Threat(s) Detected | Scan {scan_id}"
    lines = [f"Hi {name},", ""]
    if processes:
        lines.append("🔍 High/Critical Processes:")
        for p in processes:
            lines.append(f"• {p.get('name', 'Unknown')} (PID {p.get('pid')}) — Level: {p.get('threat_level')}")
        lines.append("")
    if networks:
        lines.append("🌐 High/Critical Network Activity:")
        for n in networks:
            desc = n.get("activity_description") or f"{n.get('remote_ip', '?')}:{n.get('remote_port', '?')}"
            lines.append(f"• {desc} — Level: {n.get('threat_level')}")
        lines.append("")
    if ports:
        lines.append("🔓 High/Critical Risky Ports:")
        for r in ports:
            lines.append(f"• Port {r.get('port', '?')} ({r.get('service', 'Unknown')}) — Level: {r.get('threat_level')}")
        lines.append("")
    lines.append("Recommended actions:")
    lines.append("1. Review and terminate suspicious processes")
    lines.append("2. Close or restrict risky ports")
    lines.append("3. Monitor or block suspicious connections")
    lines.append("")
    lines.append("Open Dashboard: http://localhost:3000/dashboard")
    body = "\n".join(lines)
    return subject, body

def send_batched_threat_email(to_email: str, name: str, scan_id: str, processes: list, networks: list, ports: list):
    if not (processes or networks or ports):
        return
    subject, body = build_threat_summary_email(name, scan_id, processes, networks, ports)
    send_email(to_email, subject, body)



@app.post("/api/scan/start")
async def start_scan(background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    """Start a manual system scan and store results."""
    try:
        # Perform the actual scan (replace with your real scanner if needed)
        scan_data = {
            "scan_id": f"scan_{int(time.time())}_{random.randint(1000, 9999)}",
            "system_info": {
                "hostname": socket.gethostname(),
                "platform": platform.system(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "architecture": platform.architecture()[0],
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            },
            "suspicious_processes": [],    # Populate with your real scan results
            "network_threats": [],         # Populate with your real scan results
            "risky_ports": [],             # Populate with your real scan results
            "total_threats": 0,            # Sum of all threats
        }

        # Replace this section with your actual scan logic,
        # e.g., populate scan_data["suspicious_processes"], etc.

        # Prepare for DB insertion
        scan_id = scan_data["scan_id"]
        user_id = current_user["id"]
        system_info = json.dumps(scan_data["system_info"])
        threats_detected = scan_data["total_threats"]

        # Insert scan record
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO system_scans (scan_id, user_id, system_info, threats_detected, scan_status, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_id, user_id, system_info, threats_detected, "completed", (datetime.now(ist) + timedelta(hours=2)).isoformat())
        )

        # Gather all threats that should trigger an email
        high_crit_processes = []
        high_crit_networks = []
        high_crit_ports = []

        # Insert suspicious processes and gather if high/critical
        for proc in scan_data.get("suspicious_processes", []):
            threat_level = proc.get("threat_level", "").lower()
            if threat_level in ["high", "critical"]:
                high_crit_processes.append(proc)
            cursor.execute(
                """
                INSERT INTO suspicious_processes (scan_id, pid, name, cpu_percent, memory_percent, threat_level, threat_reasons, exe_path, cmdline, username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    proc.get("pid"),
                    proc.get("name"),
                    proc.get("cpu_percent"),
                    proc.get("memory_percent"),
                    proc.get("threat_level"),
                    json.dumps(proc.get("threat_reasons", [])),
                    proc.get("exe_path"),
                    proc.get("cmdline"),
                    proc.get("username"),
                )
            )

        # Insert network threats and gather if high/critical
        for nt in scan_data.get("network_threats", []):
            threat_level = nt.get("threat_level", "").lower()
            if threat_level in ["high", "critical"]:
                high_crit_networks.append(nt)
            cursor.execute(
                """
                INSERT INTO network_connections (scan_id, local_ip, local_port, remote_ip, remote_port, status, pid, process_name, threat_level, activity_description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    nt.get("local_ip"),
                    nt.get("local_port"),
                    nt.get("remote_ip"),
                    nt.get("remote_port"),
                    nt.get("status"),
                    nt.get("pid"),
                    nt.get("process_name"),
                    nt.get("threat_level"),
                    nt.get("activity_description"),
                )
            )

        # Insert risky ports and gather if high/critical
        for rp in scan_data.get("risky_ports", []):
            threat_level = rp.get("threat_level", "").lower()
            if threat_level in ["high", "critical"]:
                high_crit_ports.append(rp)
            cursor.execute(
                """
                INSERT INTO risky_ports (scan_id, port, service, threat_level, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    rp.get("port"),
                    rp.get("service"),
                    rp.get("threat_level"),
                    rp.get("reason"),
                )
            )

        # Commit to DB
        conn.commit()
        conn.close()

        # Only send one batched email per scan
        if background_tasks and (high_crit_processes or high_crit_networks or high_crit_ports):
            background_tasks.add_task(
                send_batched_threat_email,
                current_user["email"],
                current_user.get("full_name", "User"),
                scan_id,
                high_crit_processes,
                high_crit_networks,
                high_crit_ports,
            )

        # Broadcast over websocket if needed
        await manager.broadcast(json.dumps({
            "type": "scan_completed", "data": {
                "scan_id": scan_id, "threats_detected": threats_detected,
                "timestamp": datetime.now(ist).isoformat(),
                "user_id": current_user["id"],
            }
        }))

        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_detected": threats_detected,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
        


@app.get("/api/scan/latest")
async def get_latest_scan(current_user: dict = Depends(get_current_user)):
    """Get latest scan results"""
    conn = get_db_connection()
    
    # Get latest scan
    scan = conn.execute("""
        SELECT * FROM system_scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    """, (current_user["id"],)).fetchone()
    
    if not scan:
        conn.close()
        return {"message": "No scans found"}
    
    # Get scan details
    connections = conn.execute("""
        SELECT * FROM network_connections 
        WHERE scan_id = ?
    """, (scan["scan_id"],)).fetchall()
    
    processes = conn.execute("""
        SELECT * FROM suspicious_processes 
        WHERE scan_id = ?
    """, (scan["scan_id"],)).fetchall()
    
    ports = conn.execute("""
        SELECT * FROM risky_ports 
        WHERE scan_id = ?
    """, (scan["scan_id"],)).fetchall()
    
    recommendations = conn.execute("""
        SELECT * FROM security_recommendations 
        WHERE scan_id = ?
    """, (scan["scan_id"],)).fetchall()
    
    conn.close()
    
    # Transform data to match frontend expectations
    transformed_connections = []
    for conn in connections:
        conn_dict = dict(conn)
        # Add missing fields that frontend expects
        conn_dict["activity_name"] = conn_dict.get("activity_description", "Network Activity")
        conn_dict["website"] = conn_dict.get("hostname", "Unknown")
        conn_dict["description"] = f"Network connection to {conn_dict.get('hostname', 'unknown host')}"
        conn_dict["how_occurred"] = "Established during normal system operation"
        conn_dict["why_dangerous"] = "Potentially suspicious network activity detected"
        conn_dict["immediate_impact"] = "May indicate security compromise"
        transformed_connections.append(conn_dict)
    
    transformed_processes = []
    for proc in processes:
        proc_dict = dict(proc)
        # Parse JSON fields if they exist
        if proc_dict.get("threat_reasons"):
            try:
                proc_dict["threat_indicators"] = json.loads(proc_dict["threat_reasons"])
            except:
                proc_dict["threat_indicators"] = [proc_dict.get("threat_reasons", "")]
        
        if proc_dict.get("behavior_analysis"):
            try:
                proc_dict["behavior_analysis"] = json.loads(proc_dict["behavior_analysis"])
            except:
                proc_dict["behavior_analysis"] = [proc_dict.get("behavior_analysis", "")]
        
        # Add missing fields
        proc_dict["description"] = f"Suspicious process: {proc_dict.get('name', 'Unknown')}"
        proc_dict["how_occurred"] = "Process started by malicious software or user action"
        proc_dict["why_dangerous"] = "This process may be performing malicious activities"
        proc_dict["immediate_impact"] = "System security may be compromised"
        proc_dict["first_seen"] = proc_dict.get("created_at", "Unknown")
        transformed_processes.append(proc_dict)

    return {
        "scan_info": dict(scan),
        "system_info": json.loads(scan["system_info"]) if scan["system_info"] else {},
        "network_connections": transformed_connections,
        "suspicious_processes": transformed_processes,
        "risky_ports": [dict(row) for row in ports],
        "recommendations": [dict(row) for row in recommendations]
    }

@app.get("/api/threats/analytics")
async def threat_analytics(current_user: dict = Depends(get_current_user)):
    """Get threat analytics and AI insights"""
    conn = get_db_connection()
    
    # Get threat distribution by type
    threat_types = conn.execute("""
        SELECT threat_type, COUNT(*) as count
        FROM threat_events 
        WHERE user_id = ? OR user_id IS NULL
        GROUP BY threat_type
        ORDER BY count DESC
    """, (current_user["id"],)).fetchall()
    
    # Get severity distribution
    severity_dist = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM threat_events 
        WHERE user_id = ? OR user_id IS NULL
        GROUP BY severity
    """, (current_user["id"],)).fetchall()
    
    # Get risk assessment
    risk_stats = conn.execute("""
        SELECT 
            AVG(risk_score) as avg_risk,
            MAX(risk_score) as max_risk,
            COUNT(CASE WHEN risk_score > 70 THEN 1 END) as high_risk_count
        FROM threat_events 
        WHERE user_id = ? OR user_id IS NULL
    """, (current_user["id"],)).fetchone()
    
    conn.close()
    
    # AI-powered recommendations
    recommendations = generate_ai_recommendations(risk_stats, threat_types)
    
    return {
        "threat_types": [dict(row) for row in threat_types],
        "severity_distribution": [dict(row) for row in severity_dist],
        "risk_assessment": {
            "overall_risk_score": risk_stats["avg_risk"] or 0,
            "max_risk_score": risk_stats["max_risk"] or 0,
            "high_risk_count": risk_stats["high_risk_count"] or 0,
            "risk_level": "high" if (risk_stats["avg_risk"] or 0) > 70 else "medium" if (risk_stats["avg_risk"] or 0) > 40 else "low",
            "recommendations": recommendations
        },
        "predictions": generate_threat_predictions()
    }

# ============================================================================
# WEBSOCKET ENDPOINTS
# ============================================================================

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Send periodic updates
            await asyncio.sleep(5)
            
            # Generate random threat update
            if random.random() < 0.3:  # 30% chance of new threat
                threat_update = {
                    "type": "threat_update",
                    "data": {
                        "threat_type": random.choice(["Malware", "Phishing", "DDoS", "Brute Force"]),
                        "severity": random.choice(["low", "medium", "high", "critical"]),
                        "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                        "risk_score": random.randint(20, 95),
                        "timestamp": datetime.now(ist).isoformat()
                    }
                }
                await manager.send_personal_message(json.dumps(threat_update), websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ============================================================================
# REAL SYSTEM SCANNER FUNCTIONS
# ============================================================================

import psutil
import socket
import subprocess
import platform
import threading
import time
from pathlib import Path

def get_system_info():
    """Get real system information"""
    try:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
    except Exception as e:
        print(f"Error getting system info: {e}")
        return {}

def get_process_details(pid):
    """Get detailed process information"""
    try:
        proc = psutil.Process(pid)
        return {
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": " ".join(proc.cmdline()),
            "cwd": proc.cwd(),
            "username": proc.username(),
            "create_time": datetime.fromtimestamp(proc.create_time()).isoformat()
        }
    except:
        return {"name": "Unknown", "exe": "", "cmdline": "", "cwd": "", "username": "", "create_time": ""}

def resolve_hostname(ip):
    """Resolve IP to hostname/domain"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ip

def get_service_info(port):
    """Get service information for port"""
    common_services = {
        80: "HTTP Web Traffic", 443: "HTTPS Secure Web", 21: "FTP File Transfer",
        22: "SSH Secure Shell", 23: "Telnet", 25: "SMTP Email", 53: "DNS",
        110: "POP3 Email", 143: "IMAP Email", 993: "IMAPS Secure Email",
        995: "POP3S Secure Email", 3389: "Remote Desktop", 5900: "VNC Remote Access",
        1433: "SQL Server Database", 3306: "MySQL Database", 5432: "PostgreSQL Database",
        6379: "Redis Database", 27017: "MongoDB Database", 8080: "HTTP Alternate",
        9200: "Elasticsearch", 5601: "Kibana", 3000: "Development Server"
    }
    return common_services.get(port, f"Unknown Service on Port {port}")

# def generate_user_friendly_network_activity():
#     """Generate user-friendly network activity that people can understand"""
    
#     # Normal, safe activities that users do every day
#     normal_activities = [
#         {
#             "activity": "Browsing Google",
#             "website": "www.google.com",
#             "what_youre_doing": "Searching for information on Google",
#             "is_safe": True,
#             "explanation": "This is completely normal - you're just using Google to search for things."
#         },
#         {
#             "activity": "Watching YouTube",
#             "website": "www.youtube.com", 
#             "what_youre_doing": "Streaming videos on YouTube",
#             "is_safe": True,
#             "explanation": "This is normal - you're watching videos on YouTube."
#         },
#         {
#             "activity": "Using Facebook",
#             "website": "www.facebook.com",
#             "what_youre_doing": "Checking social media on Facebook",
#             "is_safe": True,
#             "explanation": "This is normal social media activity - nothing to worry about."
#         },
#         {
#             "activity": "Checking Email",
#             "website": "mail.google.com",
#             "what_youre_doing": "Reading and sending emails",
#             "is_safe": True,
#             "explanation": "This is normal email activity - you're just checking your messages."
#         }
#     ]
    
#     # Suspicious activities (only show if there are actual threats)
#     suspicious_activities = [
#         {
#             "activity": "Sending Your Passwords to Criminals",
#             "website": "suspicious-data-collector.com",
#             "what_youre_doing": "A virus is stealing your personal information",
#             "is_safe": False,
#             "explanation": "This is DANGEROUS - malware on your computer is sending your passwords and personal data to criminals.",
#             "what_to_do": "Disconnect from internet immediately and run a virus scan",
#             "why_bad": "Criminals can use your stolen information to break into your accounts and steal your money"
#         },
#         {
#             "activity": "Your Computer Being Used for Attacks",
#             "website": "criminal-botnet-server.net",
#             "what_youre_doing": "Hackers are using your computer to attack other people",
#             "is_safe": False,
#             "explanation": "This is VERY DANGEROUS - your computer has been hijacked and is being used to commit cybercrimes.",
#             "what_to_do": "Turn off your computer immediately and get professional help",
#             "why_bad": "You could get in legal trouble for crimes committed using your computer"
#         }
#     ]
    
#     # Always show some normal activities
#     activities = random.sample(normal_activities, random.randint(2, 4))
    
#     # Sometimes add suspicious activities (simulate real threats)
#     if random.random() < 0.3:  # 30% chance of threats
#         activities.extend(random.sample(suspicious_activities, random.randint(1, 2)))
    
#     return activities

# def scan_network_connections():
#     """Scan network connections and show user-friendly activity"""
#     # Get user-friendly network activities
#     activities = generate_user_friendly_network_activity()
    
#     connections = []
    
#     for activity in activities:
#         connections.append({
#             "activity_name": activity["activity"],
#             "website": activity["website"],
#             "what_youre_doing": activity["what_youre_doing"],
#             "is_safe": activity["is_safe"],
#             "explanation": activity["explanation"],
#             "threat_level": "safe" if activity["is_safe"] else "critical",
#             "what_to_do": activity.get("what_to_do", "Continue normally - this is safe"),
#             "why_bad": activity.get("why_bad", ""),
#             "timestamp": datetime.utcnow().isoformat(),
#             "status": "Active right now"
#         })
    
#     return connections

def generate_network_remediation_steps(threat_level):
    """Generate remediation steps for network threats"""
    if threat_level == "critical":
        return [
            "1. IMMEDIATE: Disconnect from internet (unplug ethernet/disable WiFi)",
            "2. End all suspicious network processes via Task Manager",
            "3. Run offline antivirus scan from bootable rescue disk",
            "4. Change ALL passwords from a different, clean device",
            "5. Contact your bank and credit card companies immediately",
            "6. Monitor all accounts for unauthorized activity",
            "7. Consider professional malware removal service",
            "8. Reinstall operating system if heavily compromised"
        ]
    else:
        return [
            "1. Monitor the connection and identify the source process",
            "2. Run full antivirus and anti-malware scans",
            "3. Update all software and operating system",
            "4. Review and strengthen firewall rules"
        ]

def generate_network_prevention_tips():
    """Generate prevention tips for network threats"""
    return [
        "Use a reputable firewall to monitor outgoing connections",
        "Keep your antivirus software updated with real-time protection",
        "Be extremely cautious with email attachments and downloads",
        "Regularly monitor network activity for suspicious connections",
        "Use DNS filtering to block access to malicious domains",
        "Enable automatic security updates for your operating system",
        "Avoid clicking on suspicious links or advertisements"
    ]

def determine_user_activity(port, hostname, process_info):
    """Determine what the user is actually doing based on connection"""
    process_name = process_info.get("name", "").lower()
    
    # Web browsing
    if port in [80, 443, 8080, 8443]:
        if "google" in hostname.lower():
            return f"🔍 Browsing Google Search - {hostname}"
        elif "youtube" in hostname.lower():
            return f"📺 Watching YouTube - {hostname}"
        elif "facebook" in hostname.lower():
            return f"📱 Using Facebook - {hostname}"
        elif "twitter" in hostname.lower():
            return f"🐦 Using Twitter - {hostname}"
        elif "instagram" in hostname.lower():
            return f"📸 Using Instagram - {hostname}"
        elif "github" in hostname.lower():
            return f"💻 Accessing GitHub - {hostname}"
        elif "stackoverflow" in hostname.lower():
            return f"❓ Browsing Stack Overflow - {hostname}"
        elif "amazon" in hostname.lower():
            return f"🛒 Shopping on Amazon - {hostname}"
        elif "netflix" in hostname.lower():
            return f"🎬 Streaming Netflix - {hostname}"
        elif "spotify" in hostname.lower():
            return f"🎵 Listening to Spotify - {hostname}"
        else:
            return f"🌐 Web browsing - {hostname}"
    
    # Email
    elif port in [25, 110, 143, 993, 995, 587]:
        return f"📧 Email communication - {hostname}"
    
    # File transfer
    elif port in [21, 22]:
        return f"📁 File transfer - {hostname}"
    
    # Database connections
    elif port in [1433, 3306, 5432, 27017]:
        return f"🗄️ Database connection - {hostname}"
    
    # Gaming
    elif "steam" in hostname.lower():
        return f"🎮 Steam Gaming - {hostname}"
    elif "discord" in hostname.lower():
        return f"💬 Discord Chat - {hostname}"
    
    # Development
    elif port in [3000, 8000, 5000, 4200]:
        return f"⚙️ Development server - {hostname}"
    
    # Remote access
    elif port in [3389, 5900]:
        return f"🖥️ Remote desktop connection - {hostname}"
    
    # Suspicious activities
    elif port in [1337, 31337, 12345, 54321]:
        return f"⚠️ SUSPICIOUS: Connecting to hacker port {port} - {hostname}"
    
    else:
        return f"🔗 Network connection to {hostname}:{port}"

def assess_connection_threat(remote_ip, remote_port, hostname, process_info):
    """Enhanced threat assessment with detailed analysis"""
    # Known malicious indicators
    suspicious_ports = [1337, 31337, 12345, 54321, 9999, 6666]
    suspicious_hostnames = ['tor', 'onion', 'darkweb', 'hack', 'exploit', 'malware']
    
    # Check for suspicious ports
    if remote_port in suspicious_ports:
        return "critical"
    
    # Check for suspicious hostnames
    if any(sus in hostname.lower() for sus in suspicious_hostnames):
        return "critical"
    
    # Check for suspicious processes
    process_name = process_info.get("name", "").lower()
    suspicious_processes = ['keylogger', 'trojan', 'virus', 'malware', 'backdoor']
    if any(sus in process_name for sus in suspicious_processes):
        return "critical"
    
    # Check for unusual high ports
    if remote_port > 49152:
        return "medium"
    
    # Check for private IP ranges (could be lateral movement)
    if remote_ip.startswith(('10.', '172.16.', '192.168.')):
        return "low"
    
    # Standard web traffic
    if remote_port in [80, 443]:
        return "low"
    
    return "low"

def get_process_network_activity(pid):
    """Get network activity for a specific process"""
    try:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid == pid and conn.status == 'ESTABLISHED':
                remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
                remote_port = conn.raddr.port if conn.raddr else 0
                hostname = resolve_hostname(remote_ip)
                connections.append(f"{hostname}:{remote_port}")
        return connections[:5]  # Limit to 5 connections
    except:
        return []

def analyze_process_behavior(proc):
    """Analyze process behavior for detailed threat assessment"""
    try:
        # Get detailed process information
        name = proc.name()
        exe_path = proc.exe()
        cmdline = proc.cmdline()
        cwd = proc.cwd()
        username = proc.username()
        
        # Get network connections
        network_activity = get_process_network_activity(proc.pid)
        
        # Analyze behavior
        behavior_analysis = []
        
        # Check executable location
        if exe_path:
            if "temp" in exe_path.lower() or "appdata" in exe_path.lower():
                behavior_analysis.append("⚠️ Running from temporary directory")
            if "system32" in exe_path.lower() and username != "SYSTEM":
                behavior_analysis.append("🚨 Non-system user running system process")
        
        # Check command line arguments
        if cmdline:
            cmdline_str = " ".join(cmdline).lower()
            if any(word in cmdline_str for word in ['download', 'wget', 'curl', 'powershell', 'cmd']):
                behavior_analysis.append("🔍 Process executing download/command operations")
        
        # Check network activity
        if network_activity:
            behavior_analysis.append(f"🌐 Active connections: {', '.join(network_activity)}")
        
        return {
            "exe_path": exe_path,
            "cmdline": " ".join(cmdline) if cmdline else "",
            "cwd": cwd,
            "username": username,
            "network_activity": network_activity,
            "behavior_analysis": behavior_analysis
        }
    except:
        return {
            "exe_path": "", "cmdline": "", "cwd": "", "username": "",
            "network_activity": [], "behavior_analysis": []
        }

# def generate_user_friendly_threats():
#     """Generate user-friendly threat explanations that anyone can understand"""
    
#     # Simulate finding actual threats (not always the same 3)
#     possible_threats = [
#         {
#             "type": "password_stealer",
#             "name": "Password Stealer Virus",
#             "simple_name": "Password Thief",
#             "threat_level": "critical",
#             "user_explanation": "A virus is stealing your passwords and personal information",
#             "what_it_does": "This virus is secretly copying all your passwords, credit card numbers, and personal files. It's like having a thief looking over your shoulder every time you type.",
#             "how_it_got_here": "It probably came from clicking a bad link in an email or downloading something infected from the internet.",
#             "why_its_bad": "Criminals can use your stolen passwords to break into your bank account, social media, and email. They might steal your money or pretend to be you online.",
#             "what_to_do_now": [
#                 "Change all your passwords immediately (from a different device if possible)",
#                 "Check your bank account for any strange activity",
#                 "Run a virus scan on your computer",
#                 "Tell your bank and credit card companies what happened"
#             ],
#             "how_to_prevent": [
#                 "Don't click links in suspicious emails",
#                 "Only download software from official websites",
#                 "Keep your antivirus software running",
#                 "Use different passwords for different websites"
#             ],
#             "severity_explanation": "EXTREMELY DANGEROUS - Your money and identity are at risk"
#         },
#         {
#             "type": "computer_hijacker", 
#             "name": "Computer Hijacker",
#             "simple_name": "Remote Control Virus",
#             "threat_level": "critical",
#             "user_explanation": "Hackers have taken control of your computer and can see everything you do",
#             "what_it_does": "Bad guys can now control your computer from far away. They can see your screen, access your files, and use your computer like it's theirs.",
#             "how_it_got_here": "This usually happens when you visit a hacked website or click on a malicious advertisement.",
#             "why_its_bad": "The hackers can steal your files, watch what you're doing, and even use your computer to attack other people. You might get in trouble for things they do with your computer.",
#             "what_to_do_now": [
#                 "Disconnect from the internet immediately (unplug your WiFi)",
#                 "Turn off your computer and don't use it until it's cleaned",
#                 "Get help from a computer expert or tech support",
#                 "Change all your passwords from a different, clean device"
#             ],
#             "how_to_prevent": [
#                 "Don't visit suspicious websites",
#                 "Use an ad blocker in your web browser",
#                 "Keep your computer updated with security patches",
#                 "Be careful what you click on"
#             ],
#             "severity_explanation": "EXTREMELY DANGEROUS - Criminals control your computer"
#         },
#         {
#             "type": "crypto_miner",
#             "name": "Cryptocurrency Miner",
#             "simple_name": "Computer Slowdown Virus",
#             "threat_level": "high", 
#             "user_explanation": "A virus is using your computer to make money for criminals, making it very slow",
#             "what_it_does": "This virus is using your computer's power to create digital money (cryptocurrency) for criminals. It's like someone secretly using your electricity to run their business.",
#             "how_it_got_here": "It probably came hidden inside a free program you downloaded or a fake software update.",
#             "why_its_bad": "Your computer will be very slow, get hot, use more electricity, and might break from overworking. Meanwhile, criminals are making money using your computer.",
#             "what_to_do_now": [
#                 "Stop the virus program immediately (check Task Manager)",
#                 "Run a full antivirus scan",
#                 "Check if your computer is running hot or loud",
#                 "Monitor your electricity bill for increases"
#             ],
#             "how_to_prevent": [
#                 "Only download software from official websites",
#                 "Don't trust 'free' versions of expensive software",
#                 "Be suspicious of programs that make your computer slow",
#                 "Use antivirus software with real-time protection"
#             ],
#             "severity_explanation": "HIGH RISK - Your computer is being abused and may be damaged"
#         },
#         {
#             "type": "file_locker",
#             "name": "Ransomware",
#             "simple_name": "File Locker Virus", 
#             "threat_level": "critical",
#             "user_explanation": "A virus is about to lock all your files and demand money to unlock them",
#             "what_it_does": "This virus will encrypt (lock) all your important files - photos, documents, videos - and then demand you pay money to get them back. It's like a digital kidnapper holding your files hostage.",
#             "how_it_got_here": "It usually comes from opening infected email attachments or clicking malicious links in emails that look like they're from real companies.",
#             "why_its_bad": "You could lose all your precious photos, important documents, and files forever. Even if you pay the ransom, there's no guarantee you'll get your files back.",
#             "what_to_do_now": [
#                 "IMMEDIATELY disconnect from the internet",
#                 "Don't restart your computer",
#                 "Call a computer expert right away",
#                 "Check if you have recent backups of your files",
#                 "DO NOT pay the ransom - it encourages more attacks"
#             ],
#             "how_to_prevent": [
#                 "Regularly backup your important files to an external drive",
#                 "Don't open email attachments from people you don't know",
#                 "Be very careful with emails asking you to click links",
#                 "Keep your computer and antivirus software updated"
#             ],
#             "severity_explanation": "CRITICAL - Your files are about to be held for ransom"
#         },
#         {
#             "type": "spy_software",
#             "name": "Spyware",
#             "simple_name": "Digital Spy",
#             "threat_level": "high",
#             "user_explanation": "Software is secretly watching everything you do and reporting back to criminals",
#             "what_it_does": "This spy software is like having someone secretly watching over your shoulder all the time. It records what websites you visit, what you type, and what files you open.",
#             "how_it_got_here": "It often comes bundled with free software downloads or gets installed when you visit compromised websites.",
#             "why_its_bad": "Your privacy is completely gone. Criminals know your habits, interests, and personal information. They might use this to target you with scams or steal your identity.",
#             "what_to_do_now": [
#                 "Run a full system scan with updated antivirus software",
#                 "Check what programs start when your computer boots up",
#                 "Review your browser extensions and remove suspicious ones",
#                 "Change passwords for sensitive accounts"
#             ],
#             "how_to_prevent": [
#                 "Be very careful about what free software you install",
#                 "Read the fine print before installing programs",
#                 "Use privacy-focused web browsers and settings",
#                 "Regularly check what programs are running on your computer"
#             ],
#             "severity_explanation": "HIGH RISK - Your privacy and personal information are being stolen"
#         }
#     ]
    
    # Randomly select 1-3 threats to make it realistic (not always the same)
    num_threats = random.randint(1, 3)
    selected_threats = random.sample(possible_threats, num_threats)
    
    return selected_threats

# def scan_running_processes():
#     """Scan running processes and detect user-friendly threats"""
#     # Get user-friendly threat scenarios
#     threat_scenarios = generate_user_friendly_threats()
    
#     suspicious_processes = []
    
#     for i, threat in enumerate(threat_scenarios):
#         suspicious_processes.append({
#             "pid": random.randint(1000, 9999),
#             "name": threat["simple_name"],  # Use simple name for display
#             "cpu_percent": random.uniform(5, 85) if threat["type"] == "crypto_miner" else random.uniform(2, 25),
#             "memory_percent": random.uniform(5, 30),
#             "create_time": (datetime.utcnow() - timedelta(minutes=random.randint(5, 120))).isoformat(),
#             "threat_level": threat["threat_level"],
#             "threat_type": threat["type"],
            
#             # User-friendly explanations (matching RealDashboard format)
#             "description": threat["what_it_does"],
#             "how_occurred": threat["how_it_got_here"], 
#             "why_dangerous": threat["why_its_bad"],
#             "immediate_impact": threat["user_explanation"],
            
#             # Technical details
#             "exe_path": f"C:\\Windows\\System32\\{threat['name'].replace(' ', '')}.exe",
#             "first_seen": f"{random.randint(1, 30)} minutes ago",
#             "username": "SYSTEM",
#             "cmdline": f"Malicious process: {threat['simple_name']}",
            
#             # Threat indicators for display
#             "threat_indicators": [
#                 f"🚨 {threat['user_explanation']}",
#                 f"💻 {threat['what_it_does'][:50]}...",
#                 f"⚠️ {threat['why_its_bad'][:50]}..."
#             ],
            
#             # Action steps
#             "what_to_do_now": threat["what_to_do_now"],
#             "how_to_prevent": threat["how_to_prevent"],
            
#             "timestamp": datetime.utcnow().isoformat()
#         })
    
#     return suspicious_processes

def generate_remediation_steps(threat_type):
    """Generate specific remediation steps for each threat type"""
    remediation_map = {
        "malware_process": [
            "1. Immediately disconnect from the internet",
            "2. Open Task Manager (Ctrl+Shift+Esc) and end the malicious process",
            "3. Run Windows Defender full system scan",
            "4. Use Malwarebytes to perform additional scan",
            "5. Change all your passwords from a clean device",
            "6. Check bank and credit card statements for unauthorized activity",
            "7. Enable two-factor authentication on all accounts"
        ],
        "cryptominer": [
            "1. End the mining process immediately via Task Manager",
            "2. Delete the malicious file from the temp directory",
            "3. Run antivirus scan to find related files",
            "4. Check startup programs and remove suspicious entries",
            "5. Monitor CPU usage to ensure miner is completely removed",
            "6. Update all software to prevent reinfection",
            "7. Consider using anti-malware with real-time protection"
        ],
        "keylogger": [
            "1. URGENT: Stop typing sensitive information immediately",
            "2. Disconnect from internet to stop data transmission",
            "3. End the keylogger process via Task Manager",
            "4. Run full antivirus and anti-malware scans",
            "5. Change ALL passwords from a different, clean device",
            "6. Contact your bank to monitor for fraudulent activity",
            "7. Enable account alerts and two-factor authentication"
        ],
        "backdoor": [
            "1. Disconnect from internet immediately",
            "2. End the backdoor process and related network connections",
            "3. Run comprehensive malware removal tools",
            "4. Check for unauthorized user accounts or remote access software",
            "5. Review recent file changes and system modifications",
            "6. Reinstall operating system if heavily compromised",
            "7. Restore data from clean backups only"
        ],
        "ransomware_prep": [
            "1. CRITICAL: Disconnect from internet and network immediately",
            "2. End the ransomware process before encryption starts",
            "3. Boot from external antivirus rescue disk",
            "4. Scan and remove all ransomware components",
            "5. Check file integrity - restore from backups if needed",
            "6. Do NOT pay ransom if files are encrypted",
            "7. Report to authorities and use decryption tools if available"
        ]
    }
    
    return remediation_map.get(threat_type, [
        "1. End the suspicious process immediately",
        "2. Run full system antivirus scan",
        "3. Update all software and operating system",
        "4. Monitor system for unusual activity"
    ])

def generate_prevention_tips(threat_type):
    """Generate prevention tips for each threat type"""
    prevention_map = {
        "malware_process": [
            "Never open email attachments from unknown senders",
            "Download software only from official websites",
            "Keep Windows Defender real-time protection enabled",
            "Regularly update your operating system and software",
            "Use a reputable antivirus with real-time scanning"
        ],
        "cryptominer": [
            "Avoid downloading pirated software or games",
            "Be cautious of fake software update notifications",
            "Use ad blockers to prevent malicious advertisements",
            "Monitor CPU usage regularly for unusual spikes",
            "Keep your browser and plugins updated"
        ],
        "keylogger": [
            "Never install browser extensions from untrusted sources",
            "Scan USB drives before opening files",
            "Use virtual keyboards for sensitive information",
            "Enable two-factor authentication on all accounts",
            "Regularly check for suspicious browser extensions"
        ],
        "backdoor": [
            "Keep your web browser updated with latest security patches",
            "Use ad blockers and script blockers",
            "Avoid clicking on suspicious advertisements",
            "Regularly scan for malware and suspicious network activity",
            "Use a firewall to monitor outgoing connections"
        ],
        "ransomware_prep": [
            "Never click links in suspicious emails",
            "Verify sender identity before opening attachments",
            "Keep regular backups of important files offline",
            "Enable email security features and spam filtering",
            "Train yourself to recognize phishing attempts"
        ]
    }
    
    return prevention_map.get(threat_type, [
        "Keep your system and software updated",
        "Use reputable antivirus software",
        "Be cautious with email attachments and downloads",
        "Regularly backup your important data"
    ])

def generate_user_friendly_port_issues():
    """Generate user-friendly explanations of port security issues"""
    
    possible_issues = [
        {
            "port": 3389,
            "issue_name": "Your Computer Can Be Controlled Remotely",
            "simple_explanation": "Your computer is set up so people can control it from far away, but it's not secure",
            "what_this_means": "Remote Desktop is turned on, which lets people control your computer from anywhere in the world. But it's not properly protected.",
            "why_its_dangerous": "Hackers are constantly trying to guess passwords to break into computers with Remote Desktop. If they get in, they can do anything on your computer.",
            "what_hackers_do": [
                "Try thousands of password combinations every hour",
                "Use your computer to attack other people",
                "Steal all your files and personal information",
                "Install viruses and malware",
                "Hold your files for ransom"
            ],
            "what_you_should_do": [
                "Turn off Remote Desktop if you don't need it",
                "If you need it, use a VPN and strong passwords",
                "Change your password to something very strong",
                "Monitor for suspicious login attempts"
            ],
            "urgency": "Fix this immediately - hackers are trying to break in right now"
        },
        {
            "port": 445,
            "issue_name": "Your Files Are Exposed to the Internet",
            "simple_explanation": "Your computer is sharing files over the network without proper security",
            "what_this_means": "File sharing is turned on, which means other people might be able to access your documents, photos, and other files.",
            "why_its_dangerous": "This is how many ransomware attacks spread. Hackers can access your files, steal them, or encrypt them and demand money.",
            "what_hackers_do": [
                "Access your personal documents and photos",
                "Steal sensitive information like tax documents",
                "Install ransomware that locks all your files",
                "Use your computer to attack others on your network"
            ],
            "what_you_should_do": [
                "Turn off file sharing if you don't need it",
                "Set up proper passwords for shared folders",
                "Only share specific folders, not your entire computer",
                "Regularly check what folders are being shared"
            ],
            "urgency": "Fix this soon - your personal files are at risk"
        }
    ]
    
    # Sometimes show issues, sometimes don't (realistic)
    if random.random() < 0.4:  # 40% chance of showing port issues
        return random.sample(possible_issues, random.randint(1, 2))
    else:
        return []

# def scan_open_ports():
#     """Scan for port security issues with user-friendly explanations"""
#     # Get user-friendly port issues
#     port_issues = generate_user_friendly_port_issues()
    
#     risky_ports = []
    
#     for issue in port_issues:
#         risky_ports.append({
#             "port": issue.get("port", 3389),  # Add port field
#             "issue_name": issue["issue_name"],
#             "simple_explanation": issue["simple_explanation"],
#             "what_this_means": issue["what_this_means"],
#             "why_its_dangerous": issue["why_its_dangerous"],
#             "what_hackers_do": issue["what_hackers_do"],
#             "what_you_should_do": issue["what_you_should_do"],
#             "urgency": issue["urgency"],
#             "threat_level": "high",
#             "timestamp": datetime.utcnow().isoformat()
#         })
    
#     return risky_ports

def generate_port_remediation_steps(port):
    """Generate specific remediation steps for each risky port"""
    remediation_map = {
        3389: [  # RDP
            "1. IMMEDIATE: Disable RDP if not needed (Control Panel > System > Remote Settings)",
            "2. If RDP needed: Change default port from 3389 to custom port",
            "3. Enable Network Level Authentication (NLA)",
            "4. Set up VPN access instead of direct internet exposure",
            "5. Configure Windows Firewall to block RDP from internet",
            "6. Use strong passwords and enable account lockout policies",
            "7. Monitor RDP logs for suspicious login attempts"
        ],
        445: [  # SMB
            "1. Disable SMB if file sharing not needed (Control Panel > Programs > Windows Features)",
            "2. If needed: Configure SMB to use SMBv3 only (disable SMBv1)",
            "3. Set up proper authentication and access controls",
            "4. Use Windows Firewall to block SMB from internet",
            "5. Enable SMB encryption for sensitive data",
            "6. Regularly audit shared folder permissions",
            "7. Monitor SMB access logs for unauthorized attempts"
        ],
        22: [  # SSH
            "1. Disable password authentication (use SSH keys only)",
            "2. Change default SSH port from 22 to custom port",
            "3. Disable root login via SSH",
            "4. Install and configure fail2ban to block brute force attempts",
            "5. Use strong SSH key pairs (RSA 4096-bit or Ed25519)",
            "6. Configure SSH to use specific IP addresses only",
            "7. Enable SSH connection logging and monitoring"
        ]
    }
    
    return remediation_map.get(port, [
        "1. Identify the service using this port",
        "2. Disable the service if not needed",
        "3. Configure firewall rules to restrict access",
        "4. Enable authentication and encryption if service is required"
    ])

def generate_port_prevention_tips(port):
    """Generate prevention tips for each risky port"""
    prevention_map = {
        3389: [
            "Use VPN for remote access instead of direct RDP",
            "Enable two-factor authentication for RDP sessions",
            "Regularly update Windows to patch RDP vulnerabilities",
            "Monitor failed RDP login attempts",
            "Use Remote Desktop Gateway for additional security"
        ],
        445: [
            "Keep Windows updated to patch SMB vulnerabilities",
            "Use encrypted file sharing solutions for sensitive data",
            "Regularly audit network shares and permissions",
            "Implement network segmentation to isolate file servers",
            "Monitor SMB traffic for unusual activity"
        ],
        22: [
            "Always use SSH key authentication instead of passwords",
            "Regularly rotate SSH keys and remove unused keys",
            "Keep SSH server software updated",
            "Use SSH connection monitoring and alerting",
            "Implement network-based intrusion detection"
        ]
    }
    
    return prevention_map.get(port, [
        "Keep all network services updated with latest security patches",
        "Use firewalls to control network access",
        "Implement strong authentication mechanisms",
        "Monitor network traffic for suspicious activity"
    ])

def assess_connection_threat(remote_ip, remote_port):
    """Assess threat level of network connection"""
    # Known malicious IP ranges (simplified)
    suspicious_ranges = ['10.0.0.', '192.168.1.', '172.16.']
    
    # Suspicious ports
    suspicious_ports = [1337, 31337, 12345, 54321, 9999]
    
    if remote_port in suspicious_ports:
        return "critical"
    elif any(remote_ip.startswith(range_) for range_ in suspicious_ranges):
        return "medium"
    elif remote_port < 1024:  # System ports
        return "low"
    else:
        return "low"

def perform_system_scan(user_id):
    """Perform comprehensive system scan"""
    scan_results = {
        "scan_id": f"scan_{int(time.time())}_{random.randint(1000, 9999)}",
        "user_id": user_id,
        "timestamp": datetime.now(ist).isoformat(),
        "system_info": get_system_info(),
        "network_connections": scan_network_connections(),
        "suspicious_processes": scan_running_processes(),
        "risky_ports": scan_open_ports(),
        "threats_detected": 0,
        "recommendations": []
    }
    
    # Count total threats
    threats = (len(scan_results["suspicious_processes"]) + 
              len(scan_results["risky_ports"]) +
              len([conn for conn in scan_results["network_connections"] 
                   if conn["threat_level"] in ["high", "critical"]]))
    
    scan_results["threats_detected"] = threats
    
    # Generate recommendations
    recommendations = generate_security_recommendations(scan_results)
    scan_results["recommendations"] = recommendations
    
    return scan_results

def generate_security_recommendations(scan_results):
    """Generate security recommendations based on scan results"""
    recommendations = []
    
    # Process-based recommendations
    if scan_results["suspicious_processes"]:
        recommendations.append({
            "type": "process_security",
            "priority": "high",
            "title": "Suspicious Processes Detected",
            "description": f"Found {len(scan_results['suspicious_processes'])} suspicious processes",
            "action": "Review and terminate suspicious processes immediately",
            "details": [proc["name"] for proc in scan_results["suspicious_processes"]]
        })
    
    # Port-based recommendations
    if scan_results["risky_ports"]:
        recommendations.append({
            "type": "port_security",
            "priority": "medium",
            "title": "Risky Ports Exposed",
            "description": f"Found {len(scan_results['risky_ports'])} potentially risky open ports",
            "action": "Review and secure exposed services",
            "details": [f"Port {port['port']} ({port.get('service', 'Unknown Service')})" for port in scan_results.get("risky_ports", [])]

        })
    
    # Network-based recommendations
    suspicious_connections = [conn for conn in scan_results["network_connections"] 
                            if conn["threat_level"] in ["high", "critical"]]
    if suspicious_connections:
        recommendations.append({
            "type": "network_security",
            "priority": "high",
            "title": "Suspicious Network Activity",
            "description": f"Found {len(suspicious_connections)} suspicious network connections",
            "action": "Monitor and potentially block suspicious connections",
            "details": [f"{conn.get('website', 'Unknown')} - {conn.get('activity_name', 'Unknown Activity')}" for conn in suspicious_connections]
        })
    
    # General recommendations
    recommendations.extend([
        {
            "type": "general_security",
            "priority": "medium",
            "title": "Regular Security Updates",
            "description": "Keep your system and software updated",
            "action": "Enable automatic updates and regularly check for security patches"
        },
        {
            "type": "general_security",
            "priority": "medium",
            "title": "Firewall Configuration",
            "description": "Ensure firewall is properly configured",
            "action": "Review firewall rules and enable if disabled"
        },
        {
            "type": "general_security",
            "priority": "low",
            "title": "Antivirus Protection",
            "description": "Maintain active antivirus protection",
            "action": "Ensure antivirus is updated and running real-time protection"
        }
    ])
    
    return recommendations

def generate_ai_recommendations(risk_stats, threat_types):
    """Generate AI-powered security recommendations"""
    recommendations = []
    
    avg_risk = risk_stats["avg_risk"] or 0
    
    if avg_risk > 70:
        recommendations.append("🚨 High risk detected - Enable advanced threat protection")
        recommendations.append("🔒 Consider implementing zero-trust architecture")
    elif avg_risk > 40:
        recommendations.append("⚠️ Moderate risk - Review security policies")
        recommendations.append("🛡️ Update firewall rules and access controls")
    else:
        recommendations.append("✅ Security posture is good - Maintain current protocols")
        recommendations.append("📊 Continue monitoring for emerging threats")
    
    # Add threat-specific recommendations
    if threat_types:
        top_threat = threat_types[0]["threat_type"]
        if top_threat == "Phishing":
            recommendations.append("📧 Implement advanced email security training")
        elif top_threat == "Malware":
            recommendations.append("🦠 Deploy next-gen antivirus solutions")
        elif top_threat == "DDoS":
            recommendations.append("🌐 Consider DDoS protection services")
    
    return recommendations

def generate_threat_predictions():
    """Generate threat prediction data"""
    predictions = []
    base_time = datetime.now(ist)
    
    for i in range(24):  # Next 24 hours
        time_point = base_time + timedelta(hours=i)
        predicted_count = random.randint(5, 25)
        
        predictions.append({
            "time": time_point.isoformat(),
            "predicted_threat_count": predicted_count,
            "confidence": random.uniform(0.7, 0.95)
        })
    
    return predictions

# ============================================================================
# REAL THREAT SCANNING ENDPOINTS
# ============================================================================

@app.post("/api/real-scan/results")
async def receive_scan_results(scan_data: dict, current_user=Depends(get_current_user), background_tasks: BackgroundTasks = None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Use authenticated user ID to associate scans properly
        user_id = current_user["id"]

        # Generate a unique scan ID
        scan_id = f"scan_{int(time.time())}_{random.randint(1000,9999)}"

        # Cleanup old scans and related data (older than 1 minute) for this user
        cursor.execute("""
            DELETE FROM suspicious_processes WHERE scan_id IN (
                SELECT scan_id FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
            )
        """, (user_id,))

        cursor.execute("""
            DELETE FROM network_connections WHERE scan_id IN (
                SELECT scan_id FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
            )
        """, (user_id,))

        cursor.execute("""
            DELETE FROM risky_ports WHERE scan_id IN (
                SELECT scan_id FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
            )
        """, (user_id,))

        cursor.execute("""
            DELETE FROM system_scans WHERE user_id = ? AND created_at < datetime('now', '-1 minutes')
        """, (user_id,))

        # Insert main scan record
        cursor.execute("""
            INSERT INTO system_scans (scan_id, user_id, system_info, threats_detected, scan_status, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            user_id,
            json.dumps(scan_data.get("system_info", {})),
            scan_data.get("total_threats", 0),
            "completed",
            (datetime.now(ist) + timedelta(hours=1)).isoformat(),
        ))

        # Insert suspicious processes
        for proc in scan_data.get("suspicious_processes", []):
            cursor.execute("""
                INSERT INTO suspicious_processes (scan_id, pid, name, cpu_percent, memory_percent,
                threat_level, threat_reasons, exe_path, cmdline, username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                proc.get("pid"),
                proc.get("name"),
                proc.get("cpu_percent"),
                proc.get("memory_percent"),
                proc.get("threat_level"),
                json.dumps(proc.get("threat_reasons", [])),
                proc.get("exe_path"),
                proc.get("cmdline"),
                proc.get("username"),
            ))
            

        # Insert network threats
        for nt in scan_data.get("network_threats", []):
            cursor.execute("""
                INSERT INTO network_connections (scan_id, local_ip, local_port, remote_ip, remote_port,
                hostname, activity_description, status, pid, process_name, threat_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                nt.get("local_ip"),
                nt.get("local_port"),
                nt.get("remote_ip"),
                nt.get("remote_port"),
                nt.get("hostname"),
                nt.get("activity_description"),
                nt.get("status"),
                nt.get("pid"),
                nt.get("process_name"),
                nt.get("threat_level"),
            ))
            

        # Insert risky ports
        for rp in scan_data.get("risky_ports", []):
            cursor.execute("""
                INSERT INTO risky_ports (scan_id, port, service, threat_level, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                rp.get("port"),
                rp.get("service"),
                rp.get("threat_level"),
                rp.get("reason"),
            ))
            

        conn.commit()
        conn.close()

        # Broadcast update over websocket
        await manager.broadcast(json.dumps({
            "type": "scan_completed",
            "data": {
                "scan_id": scan_id,
                "threats_detected": scan_data.get("total_threats", 0),
                "timestamp": datetime.now(ist).isoformat(),
                "user_id": current_user["id"]
            }
        }))

        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_detected": scan_data.get("total_threats", 0),
            "message": "Scan results successfully processed and saved"
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed processing scan results: {str(e)}")



@app.get("/api/real-scan/results/{scan_id}")
async def get_real_scan_results(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Fetch stored real scan results by scan_id."""
    conn = get_db_connection()
    scan = conn.execute("SELECT * FROM system_scans WHERE scan_id = ? AND user_id = ?", (scan_id, current_user["id"])).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan not found")

    processes = conn.execute("SELECT * FROM suspicious_processes WHERE scan_id = ?", (scan_id,)).fetchall()
    connections = conn.execute("SELECT * FROM network_connections WHERE scan_id = ?", (scan_id,)).fetchall()
    ports = conn.execute("SELECT * FROM risky_ports WHERE scan_id = ?", (scan_id,)).fetchall()
    conn.close()

    return {
        "scan": dict(scan),
        "suspicious_processes": [dict(p) for p in processes],
        "network_connections": [dict(n) for n in connections],
        "risky_ports": [dict(r) for r in ports]
    }



@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get the status of a specific scan"""
    conn = get_db_connection()
    
    scan = conn.execute("""
        SELECT * FROM system_scans 
        WHERE scan_id = ? AND user_id = ?
    """, (scan_id, current_user["id"])).fetchone()
    
    conn.close()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan["scan_id"],
        "status": scan["scan_status"],
        "threats_detected": scan["threats_detected"],
        "created_at": scan["created_at"]
    }

@app.delete("/api/scan/reset")
async def reset_scan_data(current_user: dict = Depends(get_current_user)):
    """Reset all scan data for the current user (clear duplicates and mock data)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all scan IDs for this user
        scan_ids = cursor.execute("""
            SELECT scan_id FROM system_scans WHERE user_id = ?
        """, (current_user["id"],)).fetchall()
        
        # Delete all related data
        for scan_row in scan_ids:
            scan_id = scan_row["scan_id"]
            cursor.execute("DELETE FROM suspicious_processes WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM network_connections WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM risky_ports WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM security_recommendations WHERE scan_id = ?", (scan_id,))
        
        # Delete scan records
        cursor.execute("DELETE FROM system_scans WHERE user_id = ?", (current_user["id"],))
        
        # Clear threat history (including mock data)
        cursor.execute("DELETE FROM threat_history WHERE user_id = ?", (current_user["id"],))
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "message": "All scan data has been reset successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset scan data: {str(e)}")

@app.post("/api/admin/clear-all-mock-data")
async def clear_all_mock_data():
    """Clear all mock/simulated data from the database (public endpoint for demo)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Clear all tables with mock data
        cursor.execute("DELETE FROM suspicious_processes")
        cursor.execute("DELETE FROM network_connections") 
        cursor.execute("DELETE FROM risky_ports")
        cursor.execute("DELETE FROM security_recommendations")
        cursor.execute("DELETE FROM system_scans")
        cursor.execute("DELETE FROM threat_history")
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "message": "All mock data has been cleared successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear mock data: {str(e)}")

# ============================================================================
# ADMIN & MONITORING ENDPOINTS
# ============================================================================

@app.post("/api/real-scan/results")
async def receive_real_scan_results(scan_data: dict):
    """Receive real threat scan results from device agent"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create unique scan ID to prevent duplicates
        scan_id = f"real_scan_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Get or create user (for demo, use user ID 1)
        user_id = current_user["id"]
        
        # Clear old data for this user to prevent duplicates
        cursor.execute("""
            DELETE FROM suspicious_processes 
            WHERE scan_id IN (
                SELECT scan_id FROM system_scans 
                WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
            )
        """, (user_id,))
        
        cursor.execute("""
            DELETE FROM network_connections 
            WHERE scan_id IN (
                SELECT scan_id FROM system_scans 
                WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
            )
        """, (user_id,))
        
        cursor.execute("""
            DELETE FROM risky_ports 
            WHERE scan_id IN (
                SELECT scan_id FROM system_scans 
                WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
            )
        """, (user_id,))
        
        # Delete old scans
        cursor.execute("""
            DELETE FROM system_scans 
            WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
        """, (user_id,))
        
        # Save scan record
        cursor.execute("""
            INSERT INTO system_scans 
            (scan_id, user_id, system_info, threats_detected, scan_status, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            user_id,
            json.dumps(scan_data.get("system_info", {})),
            scan_data.get("total_threats", 0),
            "completed",
            (datetime.now(ist) + timedelta(hours=2)).isoformat()
        ))
        
        # Save suspicious processes
        for process in scan_data.get("suspicious_processes", []):
            cursor.execute("""
                INSERT INTO suspicious_processes 
                (scan_id, pid, name, cpu_percent, memory_percent, threat_level, 
                 threat_reasons, exe_path, cmdline, username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                process.get("pid"),
                process.get("name"),
                process.get("cpu_percent", 0),
                process.get("memory_percent", 0),
                process.get("threat_level", "medium"),
                json.dumps(process.get("threat_reasons", [])),
                process.get("exe_path"),
                process.get("cmdline"),
                process.get("username")
            ))
        
        # Save network threats
        for network in scan_data.get("network_threats", []):
            cursor.execute("""
                INSERT INTO network_connections 
                (scan_id, local_ip, local_port, remote_ip, remote_port, 
                 status, pid, process_name, threat_level, activity_description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                network.get("local_ip"),
                network.get("local_port"),
                network.get("remote_ip"),
                network.get("remote_port"),
                network.get("status"),
                network.get("pid"),
                network.get("process_name"),
                network.get("threat_level", "medium"),
                network.get("activity_description")
            ))
        
        # Save risky ports
        for port in scan_data.get("risky_ports", []):
            cursor.execute("""
                INSERT INTO risky_ports 
                (scan_id, port, service, threat_level, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                port.get("port"),
                port.get("service"),
                port.get("threat_level", "medium"),
                port.get("reason")
            ))
        
        conn.commit()
        conn.close()
        
        # Broadcast real-time update
        await manager.broadcast(json.dumps({
            "type": "real_scan_update",
            "data": {
                "scan_id": scan_id,
                "threats_detected": scan_data.get("total_threats", 0),
                "timestamp": scan_data.get("timestamp"),
                "device_id": scan_data.get("device_id")
            }
        }))
        
        print(f"✅ Real scan results saved: {scan_data.get('total_threats', 0)} threats")
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_processed": scan_data.get("total_threats", 0),
            "message": "Real scan results processed successfully"
        }
        
    except Exception as e:
        print(f"❌ Error processing real scan results: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process scan results: {str(e)}")

# @app.post("/api/scan/start")
# async def start_manual_scan(current_user: dict = Depends(get_current_user), background_tasks: BackgroundTasks = None):
#     """
#     Start manual threat scan by invoking real scan function from agent module.
#     Save results into database and optionally send email notifications.
#     """
#     try:
#         # Perform the real scan by calling the agent's function
#         scan_results = perform_real_threat_scan()

#         scan_id = scan_results.get("scan_id") or f"manual_scan_{int(time.time())}_{random.randint(1000,9999)}"

#         conn = get_db_connection()
#         cursor = conn.cursor()

#         # Insert scan record
#         cursor.execute("""
#             INSERT INTO system_scans (scan_id, user_id, system_info, threats_detected, scan_status)
#             VALUES (?, ?, ?, ?, ?)
#         """, (
#             scan_id,
#             current_user["id"],
#             json.dumps(scan_results.get("system_info", {})),
#             scan_results.get("total_threats", 0),
#             "completed"
#         ))

#         # Insert suspicious processes
#         for proc in scan_results.get("suspicious_processes", []):
#             cursor.execute("""
#                 INSERT INTO suspicious_processes
#                 (scan_id, pid, name, cpu_percent, memory_percent, threat_level, threat_reasons, exe_path, cmdline, username)
#                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#             """, (
#                 scan_id, proc.get("pid"), proc.get("name"), proc.get("cpu_percent"),
#                 proc.get("memory_percent"), proc.get("threat_level"),
#                 json.dumps(proc.get("threat_reasons", [])),
#                 proc.get("exe_path"), proc.get("cmdline"), proc.get("username")
#             ))
#             # Optional email notifications for high threats
#             if proc.get("threat_level", "").lower() in ("high", "critical") and background_tasks:
#                 background_tasks.add_task(send_email, current_user["email"],
#                                           f"🚨 {proc['threat_level'].upper()} Threat Detected",
#                                           f"Suspicious process detected: {proc.get('name')} (PID: {proc.get('pid')})")

#         # Insert network threats
#         for net in scan_results.get("network_threats", []):
#             cursor.execute("""
#                 INSERT INTO network_connections
#                 (scan_id, local_ip, local_port, remote_ip, remote_port, status, pid, process_name, threat_level, activity_description)
#                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#             """, (
#                 scan_id, net.get("local_ip"), net.get("local_port"), net.get("remote_ip"),
#                 net.get("remote_port"), net.get("status"), net.get("pid"), net.get("process_name"),
#                 net.get("threat_level"), net.get("activity_description")
#             ))
#             if net.get("threat_level", "").lower() in ("high", "critical") and background_tasks:
#                 background_tasks.add_task(send_email, current_user["email"],
#                                           f"🚨 {net['threat_level'].upper()} Threat Detected",
#                                           f"Risky connection {net.get('remote_ip')}:{net.get('remote_port')}")

#         # Insert risky ports
#         for port in scan_results.get("risky_ports", []):
#             cursor.execute("""
#                 INSERT INTO risky_ports (scan_id, port, service, threat_level, reason, recommendation)
#                 VALUES (?, ?, ?, ?, ?, ?)
#             """, (
#                 scan_id, port.get("port"), port.get("service"),
#                 port.get("threat_level"), port.get("reason"), port.get("recommendation")
#             ))
#             if port.get("threat_level", "").lower() in ("high", "critical") and background_tasks:
#                 background_tasks.add_task(send_email, current_user["email"],
#                                           f"🚨 {port['threat_level'].upper()} Threat Detected",
#                                           f"Risky port {port.get('port')} ({port.get('service')})")

#         conn.commit()
#         conn.close()

#         return {
#             "status": "success",
#             "scan_id": scan_id,
#             "message": "Manual real scan completed and results saved",
#             "threats_detected": scan_results.get("total_threats", 0)
#         }

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Get the status of a specific scan"""
    conn = get_db_connection()
    
    scan = conn.execute("""
        SELECT * FROM system_scans 
        WHERE scan_id = ? AND user_id = ?
    """, (scan_id, current_user["id"])).fetchone()
    
    conn.close()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan["scan_id"],
        "status": scan["scan_status"],
        "threats_detected": scan["threats_detected"],
        "created_at": scan["created_at"]
    }

@app.post("/api/real-scan/results")
async def receive_real_scan_results(scan_data: dict):
    """Receive real threat scan results from device agent"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create unique scan ID to prevent duplicates
        scan_id = f"real_scan_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Get or create demo user
        user_id = 1
        user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            # Create a demo user
            cursor.execute("""
                INSERT INTO users (id, email, password_hash, full_name, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, 'demo@cybernova.ai', 'demo_hash', 'Demo User', True))
        
        # Clear old data for this user to prevent duplicates
        cursor.execute("""
            DELETE FROM suspicious_processes 
            WHERE scan_id IN (
                SELECT scan_id FROM system_scans 
                WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
            )
        """, (user_id,))
        
        cursor.execute("""
            DELETE FROM network_connections 
            WHERE scan_id IN (
                SELECT scan_id FROM system_scans 
                WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
            )
        """, (user_id,))
        
        cursor.execute("""
            DELETE FROM risky_ports 
            WHERE scan_id IN (
                SELECT scan_id FROM system_scans 
                WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
            )
        """, (user_id,))
        
        # Delete old scans
        cursor.execute("""
            DELETE FROM system_scans 
            WHERE user_id = ? AND created_at < datetime('now', '-1 minute')
        """, (user_id,))
        
        # Save scan record
        cursor.execute("""
            INSERT INTO system_scans 
            (scan_id, user_id, system_info, threats_detected, scan_status, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            user_id,
            json.dumps(scan_data.get("system_info", {})),
            scan_data.get("total_threats", 0),
            "completed",
            (datetime.now(ist) + timedelta(hours=2)).isoformat()
        ))
        
        # Save suspicious processes
        for process in scan_data.get("suspicious_processes", []):
            cursor.execute("""
                INSERT INTO suspicious_processes 
                (scan_id, pid, name, cpu_percent, memory_percent, threat_level, 
                 threat_reasons, exe_path, cmdline, username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                process.get("pid"),
                process.get("name"),
                process.get("cpu_percent", 0),
                process.get("memory_percent", 0),
                process.get("threat_level", "medium"),
                json.dumps(process.get("threat_reasons", [])),
                process.get("exe_path"),
                process.get("cmdline"),
                process.get("username")
            ))
        
        # Save network threats
        for network in scan_data.get("network_threats", []):
            cursor.execute("""
                INSERT INTO network_connections 
                (scan_id, local_ip, local_port, remote_ip, remote_port, 
                 status, pid, process_name, threat_level, activity_description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                network.get("local_ip"),
                network.get("local_port"),
                network.get("remote_ip"),
                network.get("remote_port"),
                network.get("status"),
                network.get("pid"),
                network.get("process_name"),
                network.get("threat_level", "medium"),
                network.get("activity_description")
            ))
        
        # Save risky ports
        for port in scan_data.get("risky_ports", []):
            cursor.execute("""
                INSERT INTO risky_ports 
                (scan_id, port, service, threat_level, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                port.get("port"),
                port.get("service"),
                port.get("threat_level", "medium"),
                port.get("reason")
            ))
        
        conn.commit()
        conn.close()
        
        # Broadcast real-time update
        await manager.broadcast(json.dumps({
            "type": "real_scan_update",
            "data": {
                "scan_id": scan_id,
                "threats_detected": scan_data.get("total_threats", 0),
                "timestamp": scan_data.get("timestamp"),
                "device_id": scan_data.get("device_id")
            }
        }))
        
        print(f"✅ Real scan results saved: {scan_data.get('total_threats', 0)} threats")
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "threats_processed": scan_data.get("total_threats", 0),
            "message": "Real scan results processed successfully"
        }
        
    except Exception as e:
        print(f"❌ Error processing real scan results: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to process scan results: {str(e)}")

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def health():
    """Health check endpoint"""
    conn = get_db_connection()
    
    # Check database connectivity
    try:
        conn.execute("SELECT 1").fetchone()
        db_status = "healthy"
    except:
        db_status = "unhealthy"
    finally:
        conn.close()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now(ist).isoformat(),
        "database": db_status,
        "version": "3.0",
        "services": {
            "authentication": "active",
            "threat_detection": "active",
            "analytics": "active",
            "websocket": "active"
        }
    }

@app.get("/api/admin/stats")
async def admin_stats():
    """Admin statistics (public endpoint for demo)"""
    conn = get_db_connection()
    
    stats = {
        "total_users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "waitlist_count": conn.execute("SELECT COUNT(*) FROM waitlist").fetchone()[0],
        "total_threats": conn.execute("SELECT COUNT(*) FROM threat_events").fetchone()[0],
        "active_connections": len(manager.active_connections)
    }
    
    conn.close()
    return stats

# ============================================================================
# LEGACY ENDPOINTS (for backward compatibility)
# ============================================================================

@app.get("/api/threats/stats")
async def legacy_threat_stats():
    """Legacy endpoint for threat statistics"""
    return {
        "totalThreats": 1247,
        "blockedThreats": 892,
        "criticalThreats": 23,
        "averageRiskScore": 67.5
    }

# @app.get("/api/threats/recent")
# async def legacy_recent_threats():
#     """Legacy endpoint for recent threats"""
#     return generate_demo_threats(20)

# ============================================================================
# BACKGROUND TASKS & AUTOMATION
# ============================================================================

async def auto_scan_system():
    """Disabled auto-scan system - now using real threat scanner instead"""
    print("🔍 Auto-scan system disabled - using real threat scanner")
    # Keep the function but don't do anything
    # Real scanning is now handled by the device agent
    while True:
        await asyncio.sleep(3600)  # Sleep for 1 hour, do nothing

async def cleanup_expired_data():
    """Clean up expired scan data every hour and prevent duplicates"""
    while True:
        try:
            await asyncio.sleep(1800)  # Run every 30 minutes
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Clean up old scans (keep only last 2 hours)
            cursor.execute("DELETE FROM system_scans WHERE created_at < datetime('now', '-2 hours')")
            
            # Clean up orphaned data
            cursor.execute("""
                DELETE FROM network_connections 
                WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
            """)
            
            cursor.execute("""
                DELETE FROM suspicious_processes 
                WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
            """)
            
            cursor.execute("""
                DELETE FROM risky_ports 
                WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
            """)
            
            cursor.execute("""
                DELETE FROM security_recommendations 
                WHERE scan_id NOT IN (SELECT scan_id FROM system_scans)
            """)
            
            # Remove duplicate threat history entries
            cursor.execute("""
                DELETE FROM threat_history 
                WHERE id NOT IN (
                    SELECT MIN(id) FROM threat_history 
                    GROUP BY user_id, threat_type, description
                )
            """)
            
            # Keep only recent threat history (last 20 per user)
            cursor.execute("""
                DELETE FROM threat_history 
                WHERE detected_at < datetime('now', '-24 hours')
            """)
            
            conn.commit()
            conn.close()
            
            print(f"Cleanup completed at {datetime.now(ist)}")
                
        except Exception as e:
            print(f"Cleanup error: {e}")

async def send_security_recommendations_email(email: str, name: str, scan_results: dict):
    """Send security recommendations via email"""
    try:
        recommendations_text = ""
        for rec in scan_results["recommendations"]:
            recommendations_text += f"""
🔸 {rec['title']} (Priority: {rec['priority'].upper()})
   Description: {rec['description']}
   Action Required: {rec['action']}
   
"""
        
        email_body = f"""
🛡️ CyberNova AI - Security Scan Report

Hi {name},

Your automated security scan has been completed. Here's what we found:

📊 SCAN SUMMARY:
• Scan ID: {scan_results['scan_id']}
• Threats Detected: {scan_results['threats_detected']}
• Scan Time: {scan_results['timestamp']}
• System: {scan_results['system_info'].get('hostname', 'Unknown')}

🚨 SECURITY RECOMMENDATIONS:
{recommendations_text}

📋 DETAILED FINDINGS:

🔍 Suspicious Processes: {len(scan_results['suspicious_processes'])}
{chr(10).join([f"• {proc['name']} (PID: {proc['pid']}) - {', '.join(proc.get('threat_reasons', ['Unknown threat']))}" for proc in scan_results['suspicious_processes'][:5]])}

🌐 Network Activity: {len(scan_results['network_connections'])}
{chr(10).join([f"• {conn.get('activity_name', 'Unknown Activity')} - {conn.get('website', 'Unknown')} ({conn.get('threat_level', 'safe')} risk)" for conn in scan_results['network_connections'][:5]])}

🔓 Risky Ports: {len(scan_results['risky_ports'])}
{chr(10).join([f"• Port {port['port']} ({port['service']}) - {port['threat_level']} risk" for port in scan_results['risky_ports'][:5]])}

🔧 IMMEDIATE ACTIONS REQUIRED:
1. Review and terminate any suspicious processes
2. Close unnecessary open ports
3. Monitor suspicious network connections
4. Update your security software
5. Enable firewall protection

📱 Access your full security dashboard: http://localhost:3000/dashboard

Stay secure!
The CyberNova AI Security Team
cybernova073@gmail.com

---
This is an automated security alert. Please do not reply to this email.
        """
        
        await send_email(
            email,
            f"🚨 Security Alert: {scan_results['threats_detected']} Threats Detected",
            email_body
        )
        
    except Exception as e:
        print(f"Failed to send security email: {e}")

# Start background tasks
async def cleanup_all_duplicates():
    """One-time cleanup of all duplicate data on startup"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("Cleaning up duplicate data...")
        
        # Remove all old scan data to start fresh
        cursor.execute("DELETE FROM network_connections")
        cursor.execute("DELETE FROM suspicious_processes") 
        cursor.execute("DELETE FROM risky_ports")
        cursor.execute("DELETE FROM security_recommendations")
        cursor.execute("DELETE FROM system_scans WHERE created_at < datetime('now', '-1 hour')")
        cursor.execute("DELETE FROM threat_history WHERE detected_at < datetime('now', '-1 hour')")
        
        conn.commit()
        conn.close()
        
        print("Duplicate data cleanup completed successfully")
        
    except Exception as e:
        print(f"Cleanup error: {e}")


@app.on_event("startup")
async def startup_event():
    """Initialize database and start background tasks"""
    try:
        # Initialize database
        init_database()
        print("🚀 CyberNova AI Backend Starting...")
        print("📧 Email Service: cybernova073@gmail.com (Simulation Mode)")
        print("🗓️ Launch Date: September 15, 2025")
        print("🛡️ Threat detection engine started")
        
        # Clean up any existing duplicate data first
        await cleanup_all_duplicates()
        
        # Start background tasks
        asyncio.create_task(auto_scan_system())
        asyncio.create_task(cleanup_expired_data())
        print("✅ Background tasks started successfully")
    except Exception as e:
        print(f"⚠️ Startup failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    import uvicorn
    # Support deployment platforms that use PORT environment variable
    port = int(os.getenv("PORT", 8080))
    print("🚀 Starting CyberNova AI Backend...")
    print(f"📡 Server will be available at: http://localhost:{port}")
    print(f"📚 API Documentation: http://localhost:{port}/docs")
    print(f"🔍 Health Check: http://localhost:{port}/api/health")
    uvicorn.run(app, host="0.0.0.0", port=port)
