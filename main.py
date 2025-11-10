import streamlit as st
import sqlite3
import hashlib
import bcrypt
import pandas as pd
import time
from datetime import datetime, timedelta
import os
import re
from cryptography.fernet import Fernet

# ---------- configuration ----------
DB_PATH = "hospital_enhanced.db"
FERNET_KEY_PATH = "fernet.key"
RETENTION_DAYS = 30

# ---------- encryption setup ----------
def setup_fernet():
    """initialize fernet encryption for data protection"""
    try:
        if not os.path.exists(FERNET_KEY_PATH):
            key = Fernet.generate_key()
            with open(FERNET_KEY_PATH, "wb") as f:
                f.write(key)
            st.sidebar.success("Encryption Key Generated")
        
        with open(FERNET_KEY_PATH, "rb") as f:
            key = f.read()
        return Fernet(key)
    except Exception as e:
        st.sidebar.warning(f"Encryption Not Available: {e}")
        return None

# ---------- consent management ----------
def check_consent():
    """verify user consent for data processing"""
    if 'consent_given' not in st.session_state:
        st.session_state.consent_given = False
    return st.session_state.consent_given

def show_consent_banner():
    """display gdpr compliance consent banner"""
    if not check_consent():
        with st.container():
            st.markdown("""
            <div style='
                background-color: #ffffff;
                border-left: 4px solid #dc3545;
                padding: 1.5rem;
                margin: 1rem 0;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                border-radius: 4px;
            '>
            <h3 style='color: #2c3e50; margin-top: 0;'>Data Privacy Notice</h3>
            <p style='color: #34495e; margin-bottom: 1.5rem;'>
                We value your privacy and are committed to protecting personal data. 
                This system processes patient information with strict security measures 
                including encryption and role-based access controls.
            </p>
            <div style='display: flex; gap: 1rem; align-items: center;'>
            """, unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.markdown("<p style='color: #7f8c8d; font-size: 0.9rem;'>By continuing, you acknowledge our data handling practices</p>", unsafe_allow_html=True)
            with col2:
                if st.button("Accept", key="consent_accept", type="primary"):
                    st.session_state.consent_given = True
                    st.session_state.consent_timestamp = datetime.now()
                    st.rerun()
            with col3:
                if st.button("Learn More", key="consent_info"):
                    st.session_state.show_consent_details = True
            
            st.markdown("</div></div>", unsafe_allow_html=True)
            
            if st.session_state.get('show_consent_details', False):
                with st.expander("Privacy Details", expanded=True):
                    st.markdown("""
                    **Data We Process:**
                    - Patient names and contact information
                    - Medical diagnoses and treatment records
                    - System access logs and user activity
                    
                    **Security Measures:**
                    - End-to-end encryption for sensitive data
                    - Automatic data anonymization
                    - Role-based access controls
                    - Comprehensive audit logging
                    
                    **Retention Policy:**
                    - Patient data: 30 days maximum
                    - Audit logs: 90 days maximum
                    - Anonymized data: indefinite for analytics
                    
                    **Your Rights:**
                    - Request data access
                    - Ask for data correction
                    - Withdraw consent (limits system access)
                    """)
                    
                    if st.button("Close Details"):
                        st.session_state.show_consent_details = False
                        st.rerun()
        
        st.stop()

# ---------- data retention management ----------
def enforce_data_retention():
    """automatically remove expired data based on retention policy"""
    try:
        conn = get_conn()
        if not conn:
            return
            
        cur = conn.cursor()
        cutoff_date = (datetime.now() - timedelta(days=RETENTION_DAYS)).isoformat()
        
        # count records scheduled for deletion
        cur.execute("SELECT COUNT(*) FROM patients WHERE date_added < ?", (cutoff_date,))
        patient_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM logs WHERE timestamp < ?", (cutoff_date,))
        log_count = cur.fetchone()[0]
        
        # execute data deletion
        if patient_count > 0 or log_count > 0:
            cur.execute("DELETE FROM patients WHERE date_added < ?", (cutoff_date,))
            cur.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_date,))
            conn.commit()
            
            if patient_count > 0 or log_count > 0:
                st.sidebar.info(f"Retention Cleanup: {patient_count} patients, {log_count} logs removed")
        
        conn.close()
        
    except Exception as e:
        st.sidebar.warning(f"Retention Cleanup Skipped: {e}")

def show_retention_timer():
    st.sidebar.subheader("Data Retention")
    
    # calculate remaining days for data retention
    try:
        conn = get_conn()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT date_added FROM patients ORDER BY date_added DESC LIMIT 1")
            result = cur.fetchone()
            conn.close()
            
            if result:
                latest_date = datetime.fromisoformat(result[0])
                expiration_date = latest_date + timedelta(days=RETENTION_DAYS)
                days_remaining = (expiration_date - datetime.now()).days
                
                if days_remaining <= 7:
                    color = "#dc3545"
                    status = "Expiring Soon"
                elif days_remaining <= 15:
                    color = "#fd7e14"
                    status = "Active"
                else:
                    color = "#198754"
                    status = "Active"
                
                st.sidebar.markdown(f"""
                <div style='
                    background: {color}15;
                    border: 1px solid {color}30;
                    border-radius: 6px;
                    padding: 0.75rem;
                    margin: 0.5rem 0;
                '>
                    <div style='color: {color}; font-weight: 600; font-size: 0.9rem;'>{status}</div>
                    <div style='color: #2c3e50; font-size: 0.8rem;'>{days_remaining} Days Remaining</div>
                    <div style='color: #7f8c8d; font-size: 0.7rem;'>30 Day Policy</div>
                </div>
                """, unsafe_allow_html=True)
    
    except Exception as e:
        st.sidebar.error("Retention Status Unavailable")

# ---------- database operations ----------
def get_conn():
    """establish secure database connection"""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        st.error(f"Database Connection Failed: {str(e)}")
        return None

def init_db():
    
    
    conn = get_conn()
    if conn is None:
        st.error("Cannot Connect To Database")
        return False
    
    try:
        cur = conn.cursor()
        
        # users table with role-based access
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'receptionist')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )""")
        
        # patients table with privacy controls
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
        
        # comprehensive audit logs
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
        
        # create default users for testing
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
                st.warning(f"Could Not Add User {username}: {e}")
        
        conn.commit()
        
        
        conn.close()
        return True
        
    except Exception as e:
        st.error(f"Database Initialization Failed: {str(e)}")
        conn.close()
        return False

# ---------- security functions ----------
def verify_password(password, hashed):
    """validate user credentials against stored hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def anonymize_name(name):
    """protect patient identity through anonymization"""
    if not name:
        return ""
    salt = os.getenv("HOSPITAL_SALT", "default-salt")
    return "ANON_" + hashlib.sha256((name + salt).encode()).hexdigest()[:8]

def mask_contact(contact):
    """mask contact information for privacy"""
    if not contact:
        return ""
    if "@" in contact:  # email address
        parts = contact.split("@")
        if len(parts) == 2:
            name = parts[0]
            domain = parts[1]
            if len(name) > 2:
                masked_name = name[:2] + "*" * (len(name) - 2)
            else:
                masked_name = "**"
            return f"{masked_name}@{domain}"
    # phone number masking
    digits = re.sub(r'\D', '', contact)
    if len(digits) >= 4:
        return "XXX-XXX-" + digits[-4:]
    return "XXX-XXX-XXXX"

def encrypt_fernet(fernet, plaintext):
    """encrypt sensitive data using fernet"""
    if not fernet or not plaintext:
        return None
    try:
        return fernet.encrypt(plaintext.encode()).decode()
    except Exception:
        return None

def decrypt_fernet(fernet, token):
    """decrypt fernet-encrypted data"""
    if not fernet or not token:
        return None
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        return None

def log_action(user, action, details=""):
    """record all user actions for audit trail"""
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
        st.error(f"Logging Failed: {e}")

# ---------- role-based permissions ----------
def get_permissions(role):
    """define access controls for each user role"""
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

# ---------- patient data operations ----------
def add_patient(user, name, contact, diagnosis, fernet=None):
    """add new patient with privacy protections"""
    try:
        conn = get_conn()
        if not conn:
            return None
            
        cur = conn.cursor()
        
        # apply privacy transformations
        anonym_name = anonymize_name(name)
        anonym_contact = mask_contact(contact)
        
        # enforce role-based data storage
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
        st.error(f"Failed To Add Patient: {e}")
        return None

def get_patients(user, fernet=None):
    """retrieve patients with role-based data access"""
    try:
        conn = get_conn()
        if not conn:
            return pd.DataFrame()
            
        patients_df = pd.read_sql_query("SELECT * FROM patients ORDER BY date_added DESC", conn)
        conn.close()
        
        permissions = get_permissions(user['role'])
        
        # apply data masking based on role
        if not permissions.get('view_raw_data'):
            patients_df['name'] = None
            patients_df['contact'] = None
            
        if permissions.get('view_anonymized') and not permissions.get('view_raw_data'):
            patients_df['name'] = patients_df['anonymized_name']
            patients_df['contact'] = patients_df['anonymized_contact']
        
        # admin decryption capabilities
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
        st.error(f"Failed To Load Patients: {e}")
        return pd.DataFrame()

def edit_patient(user, patient_id, diagnosis=None, fernet=None):
    """update patient diagnosis with integrity checks"""
    try:
        conn = get_conn()
        if not conn:
            return False
            
        cur = conn.cursor()
        
        # verify patient exists
        cur.execute("SELECT patient_id FROM patients WHERE patient_id = ?", (patient_id,))
        if not cur.fetchone():
            st.error("Patient Not Found")
            return False
        
        # update medical diagnosis
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
        st.error(f"Failed To Update Patient: {e}")
        return False

# ---------- main application ----------
def main():
    st.set_page_config(
        page_title="Hospital Management System",
        layout="wide",
        page_icon="🏥"
    )
    
    # enhanced ui styling
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: #2c3e50;
        font-weight: 700;
        margin-bottom: 1rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #34495e;
        font-weight: 600;
        margin: 1.5rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #3498db;
    }
    .metric-card {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .security-badge {
        background-color: #e8f5e8;
        border: 1px solid #4caf50;
        border-radius: 4px;
        padding: 0.5rem;
        margin: 0.25rem 0;
        font-size: 0.9rem;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # initialize session state
    if 'auth' not in st.session_state:
        st.session_state.auth = None
    if 'db_initialized' not in st.session_state:
        st.session_state.db_initialized = False
    if 'start_time' not in st.session_state:
        st.session_state.start_time = time.time()
    
    # enforce consent before access
    show_consent_banner()
    
    # setup encryption system
    fernet = setup_fernet()
    
    # initialize database
    if not st.session_state.db_initialized:
        if init_db():
            st.session_state.db_initialized = True
        else:
            st.error("Failed To Initialize Database")
            return
    
    # enforce data retention policies
    enforce_data_retention()
    
    # main application header
    st.markdown('<div class="main-header">Hospital Management System</div>', unsafe_allow_html=True)
    st.markdown("Advanced Privacy Controls And Data Protection")
    
    # login interface
    with st.sidebar:
        st.markdown('<div class="section-header">System Access</div>', unsafe_allow_html=True)
        
        if st.session_state.auth is None:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.button("Login", type="primary", use_container_width=True):
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
                                st.success("Login Successful")
                                time.sleep(1)
                                st.rerun()
                            else:
                                log_action({"username": username}, "login_failed")
                                st.error("Invalid Credentials")
                        else:
                            st.error("Database Connection Failed")
                    except Exception as e:
                        st.error(f"Login Error: {e}")
                else:
                    st.error("Please Enter Both Username And Password")
        else:
            user = st.session_state.auth
            st.success(f"Signed In As: {user['username']}")
            st.info(f"Role: {user['role']}")
            
            if st.button("Logout", use_container_width=True):
                log_action(user, "logout")
                st.session_state.auth = None
                st.session_state.consent_given = False
                st.success("Logged Out Successfully")
                time.sleep(1)
                st.rerun()
        
        # system status dashboard
        st.markdown("---")
        st.markdown('<div class="section-header">System Status</div>', unsafe_allow_html=True)

        # data retention monitoring
        show_retention_timer()
        st.markdown("**System Information**")
        st.write(f"Retention Policy: {RETENTION_DAYS} Days")
        st.write(f"User Roles: {len(get_permissions('admin'))} Defined")
        st.write(f"Security Level: {'High' if fernet else 'Standard'}")
        
        # system uptime
        uptime = int(time.time() - st.session_state.start_time)
        st.write(f"System Uptime: {uptime} Seconds")
    
    # public landing page for unauthenticated users
    if st.session_state.auth is None:
        st.info("Please Log In From The Sidebar To Access The System")
        st.markdown("---")
        
        
        return
    
    # main application for authenticated users
    user = st.session_state.auth
    permissions = get_permissions(user['role'])
    
    # application layout
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown('<div class="section-header">Patient Management</div>', unsafe_allow_html=True)
        
        # patient registration form
        if permissions.get('add_patients'):
            with st.expander("Add New Patient", expanded=False):
                with st.form("add_patient_form", clear_on_submit=True):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        name = st.text_input("Full Name", help="Patient's Full Name")
                    with col_b:
                        contact = st.text_input("Contact", help="Phone or Email")
                    
                    diagnosis = st.text_area("Diagnosis", help="Medical Diagnosis and Notes")
                    
                    if st.form_submit_button("Add Patient", use_container_width=True):
                        if name and contact:
                            with st.spinner("Adding Patient With Privacy Protection"):
                                patient_id = add_patient(user, name, contact, diagnosis, fernet)
                                if patient_id:
                                    st.success(f"Patient Added Successfully - ID: {patient_id}")
                        else:
                            st.error("Name And Contact Are Required")
        
        # patient records display
        st.markdown('<div class="section-header">Patient Records</div>', unsafe_allow_html=True)
        patients_df = get_patients(user, fernet)
        
        if len(patients_df) > 0:
            # role-based data filtering
            if user['role'] != 'admin':
                cols_to_hide = ['encrypted_name', 'encrypted_contact', 'created_by']
                patients_df = patients_df.drop(columns=[col for col in cols_to_hide if col in patients_df.columns])
            
            st.dataframe(patients_df, use_container_width=True)
            st.caption(f"Showing {len(patients_df)} Patient Records - Data Displayed Based On Your Role: {user['role']}")
        else:
            st.info("No Patients Found - Add Patients To Begin")
        
        # medical diagnosis updates
        if permissions.get('edit_diagnosis'):
            with st.expander("Update Patient Diagnosis"):
                with st.form("edit_diagnosis_form"):
                    patient_id = st.number_input("Patient Identifier", min_value=1, step=1)
                    new_diagnosis = st.text_area("Clinical Assessment")
                    
                    if st.form_submit_button("Update Diagnosis", use_container_width=True):
                        if edit_patient(user, patient_id, new_diagnosis, fernet):
                            st.success("Diagnosis Updated Successfully")
                            st.rerun()
    
    with col2:
        st.markdown('<div class="section-header">System Tools</div>', unsafe_allow_html=True)
        
        # user permissions display
        st.markdown("**Your Access Permissions**")
        for perm, allowed in permissions.items():
            status = "✓" if allowed else "✗"
            color = "#198754" if allowed else "#dc3545"
            st.markdown(f"<span style='color: {color};'>{status}</span> {perm.replace('_', ' ').title()}", unsafe_allow_html=True)
        
        # administrative controls
        if user['role'] == 'admin':
            st.markdown("---")
            st.markdown("**Administration Controls**")
            
            # encryption management
            if fernet:
                st.success("Fernet Encryption Active")
                if st.button("Encrypt All Data", use_container_width=True):
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
                        st.success(f"{encrypted} Records Encrypted")
                        log_action(user, "encrypt_all")
                    except Exception as e:
                        st.error(f"Encryption Failed: {e}")
            else:
                st.warning("Fernet Encryption Unavailable")
            
            # audit log access
            st.markdown("**Audit And Monitoring**")
            if st.button("View Activity Logs", use_container_width=True):
                try:
                    conn = get_conn()
                    logs_df = pd.read_sql_query(
                        "SELECT timestamp, username, role, action, details FROM logs ORDER BY timestamp DESC LIMIT 50", 
                        conn
                    )
                    conn.close()
                    st.dataframe(logs_df, use_container_width=True)
                    st.markdown("**Integrity Audit Log** - All system actions recorded for accountability")
                except Exception as e:
                    st.error(f"Failed To Load Logs: {e}")
            
            # data export functionality
            st.markdown("**Data Management**")
            if st.button("Export Patient Data", use_container_width=True):
                admin_df = get_patients({'role': 'admin'}, fernet)
                csv = admin_df.to_csv(index=False)
                st.download_button(
                    "Download CSV Export",
                    csv,
                    "patients_full_export.csv",
                    "text/csv",
                    use_container_width=True
                )
        
        # data lifecycle information
        st.markdown("---")
        st.markdown("**Data Lifecycle**")
        st.markdown(f"""
        <div class="metric-card">
        <div style='font-size: 0.9rem; color: #2c3e50;'>Retention Period</div>
        <div style='font-size: 1.2rem; color: #3498db; font-weight: 600;'>{RETENTION_DAYS} Days</div>
        <div style='font-size: 0.8rem; color: #7f8c8d;'>Automatic Cleanup Enabled</div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Refresh Data", use_container_width=True):
            st.rerun()

if __name__ == "__main__":
    main()
