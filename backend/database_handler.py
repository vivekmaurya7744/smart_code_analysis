from pymongo import MongoClient
from datetime import datetime

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "smart_code_analysis"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
files_collection = db["files"]

def save_file(username, filename, content):
    """Save uploaded file in MongoDB or update if already exists"""
    loc = len(content.splitlines())
    size_kb = len(content.encode("utf-8")) / 1024

    existing = files_collection.find_one({"username": username, "filename": filename})
    if existing:
        # Update existing file
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
        # Insert new file
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
