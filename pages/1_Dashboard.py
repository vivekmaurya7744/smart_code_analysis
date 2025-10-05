import streamlit as st
import pandas as pd
from backend.database_handler import save_file, get_user_files, delete_file

st.set_page_config(layout="wide", page_title="Smart Code Analysis Dashboard", page_icon="🤖")

# --- Current logged in user ---
username = st.session_state.get("username", "guest")

# --- AI-Themed Banner ---
st.markdown("""
<div style="text-align:center; background-color:#f0f8ff; padding:20px; border-radius:10px;">
    <h1 style="color:#0d47a1;">📊 Smart Code Analysis Dashboard</h1>
    <p style="font-size:18px; color:#555;">Welcome to your central hub for AI-powered code analysis. Upload your Python project files below to get started.</p>
    <img src="https://img.icons8.com/fluency/240/artificial-intelligence.png" width="120"/>
</div>
""", unsafe_allow_html=True)
st.divider()

# --- Initialize session_state ---
if "uploaded_files" not in st.session_state:
    st.session_state.uploaded_files = []

# --- File Uploader ---
st.subheader("📂 Upload Your Project Files")
new_uploaded_files = st.file_uploader(
    "Select one or more Python (.py) files",
    type=["py"],
    accept_multiple_files=True,
    label_visibility="collapsed"
)

# --- Save new files to MongoDB and session_state ---
if new_uploaded_files:
    # Loop through files and save only if not already in session_state
    for file in new_uploaded_files:
        file.seek(0)
        content = file.getvalue().decode("utf-8")
        save_file(username, file.name, content)  # MongoDB save/update

        # Add to session_state only if not already present
        if file.name not in [f.name for f in st.session_state.uploaded_files]:
            st.session_state.uploaded_files.append(file)

    st.success(f"✅ Successfully uploaded {len(new_uploaded_files)} file(s)!", icon="🎉")
    
    # --- Reset uploader to avoid duplicate appends on rerun ---
    st.session_state["new_uploaded_files"] = None


# --- Fetch all files (session_state + MongoDB) ---
# We preserve session_state files and also show all files from MongoDB
user_files = get_user_files(username)

if user_files or st.session_state.uploaded_files:
    st.header("Project Overview")

    files_data = []
    total_loc = 0
    total_size = 0

    # --- Add MongoDB files ---
    for f in user_files:
        files_data.append({
            "name": f["filename"],
            "loc": f["loc"],
            "size_kb": f["size_kb"],
            "content": f["content"]
        })
        total_loc += f["loc"]
        total_size += f["size_kb"]

    # --- Optional: add session_state files that are not in MongoDB yet (just uploaded) ---
    for file in st.session_state.uploaded_files:
        if file.name not in [f["name"] for f in files_data]:
            file.seek(0)
            content = file.getvalue().decode("utf-8")
            loc = len(content.splitlines())
            size_kb = len(content.encode("utf-8")) / 1024
            files_data.append({
                "name": file.name,
                "loc": loc,
                "size_kb": size_kb,
                "content": content
            })
            total_loc += loc
            total_size += size_kb

    # --- Dashboard Layout ---
    col1, col2 = st.columns([1, 1.5])

    with col1:
        st.subheader("Key Metrics")
        c1, c2, c3 = st.columns(3)
        c1.metric("📄 Files", len(files_data))
        c2.metric("📏 Lines of Code", f"{total_loc:,}")
        c3.metric("💾 Size (KB)", f"{total_size:.2f}")

        st.subheader("Lines of Code per File")
        loc_df = pd.DataFrame(files_data)[['name', 'loc']].set_index('name')
        st.bar_chart(loc_df, color="#0d47a1")

    with col2:
        st.subheader("File Previews")
        for file_info in files_data:
            with st.expander(f"📄 {file_info['name']} ({file_info['loc']} lines)"):
                st.code(
                    file_info['content'][:1000] + ("..." if len(file_info['content']) > 1000 else ""),
                    language="python"
                )
                if st.button(f"🗑️ Delete {file_info['name']}", key=file_info['name']):
                    delete_file(username, file_info['name'])
                    # Also remove from session_state if exists
                    st.session_state.uploaded_files = [
                        f for f in st.session_state.uploaded_files if f.name != file_info['name']
                    ]
                    st.warning(f"Deleted {file_info['name']}")
                    st.rerun()
else:
    st.divider()
    st.markdown("""
    <div style="text-align:center; background-color:#f0f8ff; padding:20px; border-radius:10px;">
        <h2 style="color:#0d47a1;">🚀 Getting Started</h2>
        <p style="font-size:16px; color:#555;">
            1️⃣ Upload your Python project files using the uploader above.<br>
            2️⃣ Navigate through the sidebar to explore: <strong>File Explorer</strong>, <strong>Code Visualization</strong>, <strong>Security Center</strong>, and more.<br>
            3️⃣ Analyze your code and get actionable insights on complexity, vulnerabilities, and documentation coverage.
        </p>
        <img src="https://img.icons8.com/fluency/200/artificial-intelligence.png" width="100"/>
    </div>
    """, unsafe_allow_html=True)
