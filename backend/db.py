from pymongo import MongoClient
from dotenv import load_dotenv
import hashlib
import os

# --- Load environment variables ---
load_dotenv()

# --- Read Mongo credentials from .env ---
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

# --- Connect to MongoDB Atlas (Global) ---
try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    users_collection = db["users"]
    print("✅ Connected to MongoDB Atlas successfully.")
except Exception as e:
    print("❌ Failed to connect to MongoDB Atlas:", e)

def hash_password(password):
    """Hashes the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def check_user(username, password):
    """Checks if a user exists and the password is correct."""
    if not username or not password:
        return False
    user = users_collection.find_one({"username": username})
    if user and user["password"] == hash_password(password):
        return True
    return False

def register_user(username, password):
    """Registers a new user in the database."""
    if users_collection.find_one({"username": username}):
        return False  # User already exists
    hashed_pwd = hash_password(password)
    users_collection.insert_one({"username": username, "password": hashed_pwd})
    return True
