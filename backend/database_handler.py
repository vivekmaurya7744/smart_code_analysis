from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv
import os

# --- Load environment variables from .env ---
load_dotenv()

# --- Read Mongo credentials securely ---
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

# --- Connect to Global MongoDB Atlas ---
try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    files_collection = db["files"]
    print("✅ Connected to MongoDB Atlas successfully.")
except Exception as e:
    print("❌ Failed to connect to MongoDB Atlas:", e)

def save_file(username, filename, content):
    """Save uploaded file in MongoDB or update if already exists"""
    loc = len(content.splitlines())
    size_kb = len(content.encode("utf-8")) / 1024

    existing = files_collection.find_one({"username": username, "filename": filename})
    if existing:
        files_collection.update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "content": content,
                "size_kb": size_kb,
                "loc": loc,
                "uploaded_at": datetime.utcnow()
            }}
        )
    else:
        files_collection.insert_one({
            "username": username,
            "filename": filename,
            "content": content,
            "size_kb": size_kb,
            "loc": loc,
            "uploaded_at": datetime.utcnow()
        })

def get_user_files(username):
    """Fetch all files uploaded by a user"""
    return list(files_collection.find({"username": username}))

def delete_file(username, filename):
    """Delete a specific file of a user"""
    files_collection.delete_one({"username": username, "filename": filename})
