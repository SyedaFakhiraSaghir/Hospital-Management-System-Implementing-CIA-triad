# app_fixed.py
import streamlit as st
import sqlite3
import hashlib
import bcrypt
import pandas as pd
import time
from datetime import datetime
import os
import re

# ---------- CONFIG ----------
DB_PATH = "hospital.db"

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
    """Initialize database with simple schema"""
    st.info("🔄 Initializing database...")
    
    conn = get_conn()
    if conn is None:
        st.error("❌ Cannot connect to database")
        return False
    
    try:
        cur = conn.cursor()
        
        # Remove problematic WAL mode for now
        # cur.execute("PRAGMA journal_mode=WAL")
        
        # Simple users table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )""")
        
        # Simple patients table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            contact TEXT,
            diagnosis TEXT,
            anonymized_name TEXT,
            anonymized_contact TEXT,
            date_added TEXT
        )""")
        
        # Simple logs table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            role TEXT,
            action TEXT,
            timestamp TEXT,
            details TEXT
        )""")
        
        conn.commit()
        st.success("✅ Database tables created successfully!")
        
        # Add default users
        default_users = [
            ("admin", "admin123", "admin"),
            ("doctor", "doc123", "doctor"),
            ("reception", "rec123", "receptionist")
        ]
        
        users_added = 0
        for username, password, role in default_users:
            try:
                # Check if user exists
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
    """Simple anonymization"""
    if not name:
        return ""
    return "ANON_" + hashlib.sha256(name.encode()).hexdigest()[:8]

def mask_contact(contact):
    """Mask contact information"""
    if not contact:
        return ""
    if "@" in contact:  # Email
        parts = contact.split("@")
        if len(parts) == 2:
            return f"{parts[0][:2]}***@{parts[1]}"
    # Phone number
    if len(contact) >= 4:
        return "XXX-XXX-" + contact[-4:]
    return "XXX-XXX-XXXX"

def log_action(username, role, action, details=""):
    """Simple logging"""
    try:
        conn = get_conn()
        if conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO logs (username, role, action, timestamp, details) VALUES (?, ?, ?, ?, ?)",
                (username, role, action, datetime.now().isoformat(), details)
            )
            conn.commit()
            conn.close()
    except Exception as e:
        st.error(f"Logging failed: {e}")

# ---------- PATIENT OPERATIONS ----------
def add_patient(user, name, contact, diagnosis):
    """Add a new patient"""
    try:
        conn = get_conn()
        if not conn:
            return None
            
        cur = conn.cursor()
        
        # Always store anonymized data
        anonym_name = anonymize_name(name)
        anonym_contact = mask_contact(contact)
        
        # Only admin stores raw data
        store_name = name if user['role'] == 'admin' else None
        store_contact = contact if user['role'] == 'admin' else None
        
        cur.execute("""
            INSERT INTO patients (name, contact, diagnosis, anonymized_name, anonymized_contact, date_added)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (store_name, store_contact, diagnosis, anonym_name, anonym_contact, datetime.now().isoformat()))
        
        patient_id = cur.lastrowid
        conn.commit()
        conn.close()
        
        log_action(user['username'], user['role'], "add_patient", f"ID: {patient_id}")
        return patient_id
        
    except Exception as e:
        st.error(f"Failed to add patient: {e}")
        return None

def get_patients(role):
    """Get patients based on role"""
    try:
        conn = get_conn()
        if not conn:
            return []
            
        patients = pd.read_sql_query("SELECT * FROM patients ORDER BY date_added DESC", conn)
        conn.close()
        
        # Apply role-based masking
        if role != 'admin':
            patients['name'] = patients['anonymized_name']
            patients['contact'] = patients['anonymized_contact']
        
        # Clean up for display
        patients = patients.drop(['anonymized_name', 'anonymized_contact'], axis=1, errors='ignore')
        return patients
        
    except Exception as e:
        st.error(f"Failed to load patients: {e}")
        return pd.DataFrame()

# ---------- MAIN APPLICATION ----------
def main():
    st.set_page_config(
        page_title="Hospital Management System",
        layout="wide",
        page_icon="🏥"
    )
    
    # Initialize session state
    if 'auth' not in st.session_state:
        st.session_state.auth = None
    if 'db_initialized' not in st.session_state:
        st.session_state.db_initialized = False
    
    # Initialize database (only once)
    if not st.session_state.db_initialized:
        if init_db():
            st.session_state.db_initialized = True
        else:
            st.error("❌ Failed to initialize database. Please check the console for errors.")
            return
    
    st.title("🏥 Hospital Management System")
    
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
                                "SELECT user_id, username, password_hash, role FROM users WHERE username = ?",
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
                                log_action(username, user['role'], "login_success")
                                st.success("✅ Login successful!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                log_action(username, "unknown", "login_failed")
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
                log_action(user['username'], user['role'], "logout")
                st.session_state.auth = None
                st.success("Logged out successfully!")
                time.sleep(1)
                st.rerun()
    
    # Show content only if logged in
    if st.session_state.auth is None:
        st.info("👆 Please log in from the sidebar to access the system")
        st.markdown("---")
        st.write("### Default Login Credentials:")
        st.write("- **Admin**: admin / admin123")
        st.write("- **Doctor**: doctor / doc123") 
        st.write("- **Receptionist**: reception / rec123")
        return
    
    user = st.session_state.auth
    
    # Main Application
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("👥 Patient Management")
        
        # Add Patient Form
        if user['role'] in ['admin', 'receptionist']:
            with st.expander("➕ Add New Patient", expanded=False):
                with st.form("add_patient_form", clear_on_submit=True):
                    name = st.text_input("Full Name *", help="Patient's full name")
                    contact = st.text_input("Contact *", help="Phone or email")
                    diagnosis = st.text_area("Diagnosis", help="Medical diagnosis")
                    
                    if st.form_submit_button("Add Patient"):
                        if name and contact:
                            with st.spinner("Adding patient..."):
                                patient_id = add_patient(user, name, contact, diagnosis)
                                if patient_id:
                                    st.success(f"✅ Patient added successfully! ID: {patient_id}")
                        else:
                            st.error("❌ Name and contact are required")
        
        # View Patients
        st.subheader("📋 Patient Records")
        patients_df = get_patients(user['role'])
        
        if len(patients_df) > 0:
            st.dataframe(patients_df, use_container_width=True)
            st.caption(f"Showing {len(patients_df)} patient records")
        else:
            st.info("📝 No patients found. Add some patients to get started.")
    
    with col2:
        st.header("⚙️ System Info")
        
        st.metric("User Role", user['role'])
        st.metric("Username", user['username'])
        
        if user['role'] == 'admin':
            st.subheader("🔧 Admin Tools")
            
            # View logs
            if st.button("View Activity Logs"):
                try:
                    conn = get_conn()
                    if conn:
                        logs_df = pd.read_sql_query(
                            "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50", 
                            conn
                        )
                        conn.close()
                        st.dataframe(logs_df)
                    else:
                        st.error("Database connection failed")
                except Exception as e:
                    st.error(f"Failed to load logs: {e}")
            
            # Export data
            if st.button("Export Patients CSV"):
                patients_df = get_patients('admin')  # Get all data for admin
                csv = patients_df.to_csv(index=False)
                st.download_button(
                    "Download CSV",
                    csv,
                    "patients_export.csv",
                    "text/csv"
                )
        
        st.markdown("---")
        st.subheader("ℹ️ About")
        st.write("""
        This system demonstrates:
        - **Role-based access control**
        - **Patient data anonymization** 
        - **Audit logging**
        - **Privacy protection**
        """)

if __name__ == "__main__":
    main()