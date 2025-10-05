import streamlit as st
from backend.db import check_user, register_user

st.set_page_config(page_title="Login - Smart Code Analysis", page_icon="🤖", layout="wide")

# Session state variables ko initialize karna
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""

def show_auth_page():
    """Login aur registration forms dikhata hai."""
    st.title("🤖 Smart Code Analysis")
    st.write("")

    auth_option = st.radio(
        "Select an option",
        ["Login", "Register"],
        horizontal=True,
        label_visibility="collapsed"
    )

    if auth_option == "Login":
        with st.form("login_form"):
            st.header("🔐 User Login")
            username = st.text_input("Username", placeholder="e.g., vivek")
            password = st.text_input("Password", type="password", placeholder="e.g., 1234")
            submitted = st.form_submit_button("Login", use_container_width=True, type="primary")

            if submitted:
                if check_user(username, password):
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = username
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")

    elif auth_option == "Register":
        with st.form("register_form"):
            st.header("✍️ Create a New Account")
            new_username = st.text_input("New Username", placeholder="Choose a username")
            new_password = st.text_input("New Password", type="password", placeholder="Choose a strong password")
            confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
            register_submitted = st.form_submit_button("Register", use_container_width=True, type="primary")

            if register_submitted:
                if not new_username or not new_password:
                    st.error("Username and password cannot be empty.")
                elif new_password != confirm_password:
                    st.error("Passwords do not match.")
                elif len(new_password) < 4:
                    st.error("Password must be at least 4 characters long.")
                elif register_user(new_username, new_password):
                    st.success("Registration successful! You can now log in.")
                    st.balloons()
                else:
                    st.error("Username already exists.")

# --- Main App Logic ---
if not st.session_state.get("authenticated", False):
    # --- YEH CODE ADD KAREIN ---
    # Login page par sidebar hide karne ke liye CSS
    st.markdown(
        """
        <style>
            [data-testid="stSidebar"] {
                display: none;
            }
        </style>
        """,
        unsafe_allow_html=True
    )
    # --------------------------
    show_auth_page()
else:
    st.switch_page("pages/1_Dashboard.py")