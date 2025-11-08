# app_enhanced.py
import streamlit as st
import sqlite3
import hashlib
import bcrypt
import pandas as pd
import time
from datetime import datetime
import os
import re
from cryptography.fernet import Fernet

# ---------- CONFIG ----------
DB_PATH = "hospital_enhanced.db"
FERNET_KEY_PATH = "fernet.key"

# ---------- ENCRYPTION HELPERS ----------
def setup_fernet():
    """Setup Fernet encryption"""
    try:
        if not os.path.exists(FERNET_KEY_PATH):
            key = Fernet.generate_key()
            with open(FERNET_KEY_PATH, "wb") as f:
                f.write(key)
            st.sidebar.success("🔐 Encryption key generated")
        
        with open(FERNET_KEY_PATH, "rb") as f:
            key = f.read()
        return Fernet(key)
    except Exception as e:
        st.sidebar.warning(f"Encryption not available: {e}")
        return None

# ---------- DATABASE HELPERS ----------
def get_conn():
    """Get database connection with proper error handling"""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        st.error(f"Database connection failed: {str(e)}")
        return None

def init_db():
    """Initialize database with enhanced schema"""
    st.info("🔄 Initializing enhanced database...")
    
    conn = get_conn()
    if conn is None:
        st.error("❌ Cannot connect to database")
        return False
    
    try:
        cur = conn.cursor()
        
        # Enhanced users table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'receptionist')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )""")
        
        # Enhanced patients table with encryption fields
        cur.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            contact TEXT,
            diagnosis TEXT,
            anonymized_name TEXT,
            anonymized_contact TEXT,
            encrypted_name TEXT,
            encrypted_contact TEXT,
            date_added TEXT,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(user_id)
        )""")
        
        # Enhanced logs table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            role TEXT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )""")
        
        conn.commit()
        st.success("✅ Enhanced database tables created!")
        
        # Add default users
        default_users = [
            ("admin", "admin123", "admin"),
            ("drbob", "doc123", "doctor"),
            ("alice_recep", "rec123", "receptionist")
        ]
        
        users_added = 0
        for username, password, role in default_users:
            try:
                cur.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
                if cur.fetchone()[0] == 0:
                    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    cur.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                        (username, password_hash, role)
                    )
                    users_added += 1
            except Exception as e:
                st.warning(f"Could not add user {username}: {e}")
        
        conn.commit()
        st.success(f"✅ {users_added} default users added")
        
        conn.close()
        return True
        
    except Exception as e:
        st.error(f"❌ Database initialization failed: {str(e)}")
        conn.close()
        return False

# ---------- SECURITY HELPERS ----------
def verify_password(password, hashed):
    """Verify password against bcrypt hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def anonymize_name(name):
    """Enhanced anonymization"""
    if not name:
        return ""
    salt = os.getenv("HOSPITAL_SALT", "default-salt")
    return "ANON_" + hashlib.sha256((name + salt).encode()).hexdigest()[:8]

def mask_contact(contact):
    """Enhanced contact masking"""
    if not contact:
        return ""
    if "@" in contact:  # Email
        parts = contact.split("@")
        if len(parts) == 2:
            name = parts[0]
            domain = parts[1]
            if len(name) > 2:
                masked_name = name[:2] + "*" * (len(name) - 2)
            else:
                masked_name = "**"
            return f"{masked_name}@{domain}"
    # Phone number
    digits = re.sub(r'\D', '', contact)
    if len(digits) >= 4:
        return "XXX-XXX-" + digits[-4:]
    return "XXX-XXX-XXXX"

def encrypt_fernet(fernet, plaintext):
    """Encrypt with Fernet"""
    if not fernet or not plaintext:
        return None
    try:
        return fernet.encrypt(plaintext.encode()).decode()
    except Exception:
        return None

def decrypt_fernet(fernet, token):
    """Decrypt with Fernet"""
    if not fernet or not token:
        return None
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        return None

def log_action(user, action, details=""):
    """Enhanced logging"""
    try:
        conn = get_conn()
        if conn:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO logs (user_id, username, role, action, timestamp, details) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user.get('user_id'), user.get('username'), user.get('role'), 
                 action, datetime.now().isoformat(), details)
            )
            conn.commit()
            conn.close()
    except Exception as e:
        st.error(f"Logging failed: {e}")

# ---------- ROLE PERMISSIONS ----------
def get_permissions(role):
    """Define role-based permissions"""
    return {
        'admin': {
            'view_raw_data': True,
            'edit_raw_data': True,
            'view_anonymized': True,
            'edit_diagnosis': True,
            'add_patients': True,
            'view_logs': True,
            'export_data': True,
            'manage_encryption': True
        },
        'doctor': {
            'view_raw_data': False,
            'edit_raw_data': False,
            'view_anonymized': True,
            'edit_diagnosis': True,
            'add_patients': False,
            'view_logs': False,
            'export_data': False,
            'manage_encryption': False
        },
        'receptionist': {
            'view_raw_data': False,
            'edit_raw_data': False,
            'view_anonymized': False,
            'edit_diagnosis': True,
            'add_patients': True,
            'view_logs': False,
            'export_data': False,
            'manage_encryption': False
        }
    }.get(role, {})

# ---------- PATIENT OPERATIONS ----------
def add_patient(user, name, contact, diagnosis, fernet=None):
    """Add patient with enhanced privacy"""
    try:
        conn = get_conn()
        if not conn:
            return None
            
        cur = conn.cursor()
        
        # Prepare data based on role
        anonym_name = anonymize_name(name)
        anonym_contact = mask_contact(contact)
        
        # Role-based data storage
        permissions = get_permissions(user['role'])
        store_name = name if permissions.get('view_raw_data') else None
        store_contact = contact if permissions.get('view_raw_data') else None
        encrypted_name = encrypt_fernet(fernet, name) if fernet and permissions.get('manage_encryption') else None
        encrypted_contact = encrypt_fernet(fernet, contact) if fernet and permissions.get('manage_encryption') else None
        
        cur.execute("""
            INSERT INTO patients 
            (name, contact, diagnosis, anonymized_name, anonymized_contact, 
             encrypted_name, encrypted_contact, date_added, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (store_name, store_contact, diagnosis, anonym_name, anonym_contact,
              encrypted_name, encrypted_contact, datetime.now().isoformat(), user['user_id']))
        
        patient_id = cur.lastrowid
        conn.commit()
        conn.close()
        
        log_action(user, "add_patient", f"ID: {patient_id}")
        return patient_id
        
    except Exception as e:
        st.error(f"Failed to add patient: {e}")
        return None

def get_patients(user, fernet=None):
    """Get patients with role-based data access"""
    try:
        conn = get_conn()
        if not conn:
            return pd.DataFrame()
            
        patients_df = pd.read_sql_query("SELECT * FROM patients ORDER BY date_added DESC", conn)
        conn.close()
        
        permissions = get_permissions(user['role'])
        
        # Apply role-based data masking
        if not permissions.get('view_raw_data'):
            patients_df['name'] = None
            patients_df['contact'] = None
            
        if permissions.get('view_anonymized') and not permissions.get('view_raw_data'):
            patients_df['name'] = patients_df['anonymized_name']
            patients_df['contact'] = patients_df['anonymized_contact']
        
        # Admin can see decrypted data
        if user['role'] == 'admin' and fernet:
            if 'encrypted_name' in patients_df.columns:
                patients_df['decrypted_name'] = patients_df['encrypted_name'].apply(
                    lambda x: decrypt_fernet(fernet, x) if x else None
                )
            if 'encrypted_contact' in patients_df.columns:
                patients_df['decrypted_contact'] = patients_df['encrypted_contact'].apply(
                    lambda x: decrypt_fernet(fernet, x) if x else None
                )
        
        return patients_df
        
    except Exception as e:
        st.error(f"Failed to load patients: {e}")
        return pd.DataFrame()

def edit_patient(user, patient_id, diagnosis=None, fernet=None):
    """Edit patient diagnosis"""
    try:
        conn = get_conn()
        if not conn:
            return False
            
        cur = conn.cursor()
        
        # Check if patient exists
        cur.execute("SELECT patient_id FROM patients WHERE patient_id = ?", (patient_id,))
        if not cur.fetchone():
            st.error("Patient not found")
            return False
        
        # Update diagnosis
        if diagnosis:
            cur.execute(
                "UPDATE patients SET diagnosis = ? WHERE patient_id = ?",
                (diagnosis, patient_id)
            )
        
        conn.commit()
        conn.close()
        
        log_action(user, "edit_patient", f"ID: {patient_id}")
        return True
        
    except Exception as e:
        st.error(f"Failed to update patient: {e}")
        return False

# ---------- MAIN APPLICATION ----------
def main():
    st.set_page_config(
        page_title="Enhanced Hospital Management",
        layout="wide",
        page_icon="🏥"
    )
    
    # Initialize session state
    if 'auth' not in st.session_state:
        st.session_state.auth = None
    if 'db_initialized' not in st.session_state:
        st.session_state.db_initialized = False
    if 'start_time' not in st.session_state:
        st.session_state.start_time = time.time()
    
    # Setup encryption
    fernet = setup_fernet()
    
    # Initialize database
    if not st.session_state.db_initialized:
        if init_db():
            st.session_state.db_initialized = True
        else:
            st.error("❌ Failed to initialize database.")
            return
    
    st.title("🏥 Enhanced Hospital Management System")
    st.markdown("### Featuring Advanced Privacy Controls & Encryption")
    
    # Login Section
    with st.sidebar:
        st.header("🔐 Login")
        
        if st.session_state.auth is None:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.button("Login", type="primary"):
                if username and password:
                    try:
                        conn = get_conn()
                        if conn:
                            cur = conn.cursor()
                            cur.execute(
                                """SELECT user_id, username, password_hash, role 
                                   FROM users WHERE username = ? AND is_active = 1""",
                                (username,)
                            )
                            user_row = cur.fetchone()
                            conn.close()
                            
                            if user_row and verify_password(password, user_row[2]):
                                user = {
                                    "user_id": user_row[0],
                                    "username": user_row[1],
                                    "role": user_row[3]
                                }
                                st.session_state.auth = user
                                log_action(user, "login_success")
                                st.success("✅ Login successful!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                log_action({"username": username}, "login_failed")
                                st.error("❌ Invalid credentials")
                        else:
                            st.error("❌ Database connection failed")
                    except Exception as e:
                        st.error(f"❌ Login error: {e}")
                else:
                    st.error("⚠️ Please enter both username and password")
        else:
            user = st.session_state.auth
            st.success(f"✅ Signed in as: {user['username']}")
            st.info(f"👤 Role: {user['role']}")
            
            if st.button("Logout"):
                log_action(user, "logout")
                st.session_state.auth = None
                st.success("Logged out successfully!")
                time.sleep(1)
                st.rerun()
        
        # System status
        st.markdown("---")
        st.subheader("🔧 System Status")
        st.write(f"🔐 Encryption: {'✅ Enabled' if fernet else '❌ Disabled'}")
        st.write(f"🗄️ Database: {'✅ Connected' if st.session_state.db_initialized else '❌ Failed'}")
        uptime = int(time.time() - st.session_state.start_time)
        st.write(f"⏱️ Uptime: {uptime}s")
    
    # Show content only if logged in
    if st.session_state.auth is None:
        st.info("👆 Please log in from the sidebar to access the system")
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.subheader("👑 Admin")
            st.write("**Username:** admin")
            st.write("**Password:** admin123")
            st.write("**Permissions:** Full access")
            
        with col2:
            st.subheader("👨‍⚕️ Doctor")
            st.write("**Username:** drbob")
            st.write("**Password:** doc123")
            st.write("**Permissions:** Anonymized data view")
            
        with col3:
            st.subheader("💼 Receptionist")
            st.write("**Username:** alice_recep")
            st.write("**Password:** rec123")
            st.write("**Permissions:** Add patients, limited view")
        
        st.markdown("---")
        st.write("### 🛡️ Security Features:")
        st.write("- Role-based access control")
        st.write("- Patient data anonymization")
        st.write("- Optional Fernet encryption")
        st.write("- Comprehensive audit logging")
        st.write("- GDPR-compliant data handling")
        return
    
    user = st.session_state.auth
    permissions = get_permissions(user['role'])
    
    # Main Application
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("👥 Patient Management")
        
        # Add Patient Form
        if permissions.get('add_patients'):
            with st.expander("➕ Add New Patient", expanded=False):
                with st.form("add_patient_form", clear_on_submit=True):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        name = st.text_input("Full Name *", help="Patient's full name")
                    with col_b:
                        contact = st.text_input("Contact *", help="Phone or email")
                    
                    diagnosis = st.text_area("Diagnosis", help="Medical diagnosis and notes")
                    
                    if st.form_submit_button("Add Patient"):
                        if name and contact:
                            with st.spinner("Adding patient with privacy protection..."):
                                patient_id = add_patient(user, name, contact, diagnosis, fernet)
                                if patient_id:
                                    st.success(f"✅ Patient added successfully! ID: {patient_id}")
                                    st.balloons()
                        else:
                            st.error("❌ Name and contact are required")
        
        # View Patients
        st.subheader("📋 Patient Records")
        patients_df = get_patients(user, fernet)
        
        if len(patients_df) > 0:
            # Clean up display based on role
            if user['role'] != 'admin':
                cols_to_hide = ['encrypted_name', 'encrypted_contact', 'created_by']
                patients_df = patients_df.drop(columns=[col for col in cols_to_hide if col in patients_df.columns])
            
            st.dataframe(patients_df, use_container_width=True)
            st.caption(f"Showing {len(patients_df)} patient records - Data displayed based on your role: {user['role']}")
        else:
            st.info("📝 No patients found. Add some patients to get started.")
        
        # Edit Diagnosis
        if permissions.get('edit_diagnosis'):
            with st.expander("✏️ Edit Patient Diagnosis"):
                with st.form("edit_diagnosis_form"):
                    patient_id = st.number_input("Patient ID", min_value=1, step=1)
                    new_diagnosis = st.text_area("New Diagnosis")
                    
                    if st.form_submit_button("Update Diagnosis"):
                        if edit_patient(user, patient_id, new_diagnosis, fernet):
                            st.success("✅ Diagnosis updated successfully!")
                            st.rerun()
    
    with col2:
        st.header("⚙️ System Tools")
        
        # Role info
        st.subheader("👤 Your Permissions")
        for perm, allowed in permissions.items():
            icon = "✅" if allowed else "❌"
            st.write(f"{icon} {perm.replace('_', ' ').title()}")
        
        # Admin tools
        if user['role'] == 'admin':
            st.subheader("🔧 Admin Controls")
            
            # Encryption management
            if fernet:
                st.success("🔐 Fernet Encryption: ACTIVE")
                if st.button("Encrypt Existing Data"):
                    try:
                        conn = get_conn()
                        cur = conn.cursor()
                        cur.execute("SELECT patient_id, name, contact FROM patients")
                        rows = cur.fetchall()
                        
                        encrypted = 0
                        for row in rows:
                            enc_name = encrypt_fernet(fernet, row['name']) if row['name'] else None
                            enc_contact = encrypt_fernet(fernet, row['contact']) if row['contact'] else None
                            cur.execute(
                                "UPDATE patients SET encrypted_name = ?, encrypted_contact = ? WHERE patient_id = ?",
                                (enc_name, enc_contact, row['patient_id'])
                            )
                            encrypted += 1
                        
                        conn.commit()
                        conn.close()
                        st.success(f"✅ {encrypted} records encrypted")
                        log_action(user, "encrypt_all")
                    except Exception as e:
                        st.error(f"Encryption failed: {e}")
            else:
                st.warning("🔐 Fernet Encryption: UNAVAILABLE")
            
            # Audit logs
            st.subheader("📊 Audit Logs")
            if st.button("View Recent Activity"):
                try:
                    conn = get_conn()
                    logs_df = pd.read_sql_query(
                        "SELECT timestamp, username, role, action, details FROM logs ORDER BY timestamp DESC LIMIT 50", 
                        conn
                    )
                    conn.close()
                    st.dataframe(logs_df, use_container_width=True)
                except Exception as e:
                    st.error(f"Failed to load logs: {e}")
            
            # Data export
            st.subheader("💾 Data Export")
            if st.button("Export Patients (Admin View)"):
                admin_df = get_patients({'role': 'admin'}, fernet)  # Get all data
                csv = admin_df.to_csv(index=False)
                st.download_button(
                    "📥 Download CSV",
                    csv,
                    "patients_full_export.csv",
                    "text/csv"
                )
        
        # System info
        st.markdown("---")
        st.subheader("ℹ️ System Information")
        st.write(f"**Database:** {DB_PATH}")
        st.write(f"**Users:** {len(get_permissions('admin'))} roles defined")
        st.write(f"**Encryption:** {'Fernet Active' if fernet else 'Basic Only'}")
        
        if st.button("🔄 Refresh Data"):
            st.rerun()

if __name__ == "__main__":
    main()