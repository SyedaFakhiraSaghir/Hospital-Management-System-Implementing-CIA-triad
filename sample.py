# app_simple.py
import streamlit as st

st.set_page_config(page_title="Test App", layout="wide")
st.title("🏥 Hospital System - TEST")
st.write("If you can see this, Streamlit is working!")

# Simple login test
with st.sidebar:
    st.header("Login Test")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Test Login"):
        st.success(f"Hello {username}!")

st.success("✅ Streamlit is working correctly!")