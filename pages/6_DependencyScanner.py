# pages/6_DependencyScanner.py
import streamlit as st
import pandas as pd
import ast
import requests
import re
from dataclasses import dataclass
from packaging.version import parse as parse_version
from concurrent.futures import ThreadPoolExecutor
# NEW: Import backend functions to get saved files
from backend.database_handler import get_user_files

st.set_page_config(layout="wide", page_title="Dependency Scanner")
st.title("📦 Advanced Dependency Scanner")
st.markdown("Analyze `requirements.txt` or Python files to check for outdated packages, view licenses, and more.")

# --- Dataclass for holding package information ---
@dataclass
class PackageInfo:
    name: str
    current_version: str = "N/A"
    latest_version: str = "N/A"
    license: str = "N/A"
    status: str = "Unknown"
    summary: str = "N/A"
    pypi_url: str = ""
    
# --- Core Logic with Caching and Concurrency ---

@st.cache_data(ttl=3600) # Cache data for 1 hour
def get_pypi_data(pkg_name):
    """Fetches package data from PyPI API. Cached to avoid repeated requests."""
    try:
        response = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def parse_requirements(file_content):
    """Parses a requirements.txt file, extracting package names and versions."""
    packages = {}
    req_pattern = re.compile(r"([a-zA-Z0-9\-_]+)\s*([~>=<]=?)\s*([0-9\.]+)?")
    lines = file_content.splitlines()
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            match = req_pattern.match(line)
            if match:
                name = match.group(1)
                version = match.group(3) if match.group(3) else "N/A"
                packages[name.lower()] = version
            else:
                packages[line.lower()] = "N/A"
    return packages

# CHANGED: This function now works with file data from the database
def get_imported_packages_from_db(user_files):
    """Scans Python file content from the database to find top-level imports."""
    packages = set()
    std_lib = {"os", "sys", "re", "json", "datetime", "math", "random", "collections", "itertools", "functools"}
    
    for file_data in user_files:
        # Content is already a string from the database
        content = file_data.get("content", "")
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for n in node.names:
                        pkg_name = n.name.split('.')[0]
                        if pkg_name not in std_lib:
                            packages.add(pkg_name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.level == 0:
                        pkg_name = node.module.split('.')[0]
                        if pkg_name not in std_lib:
                            packages.add(pkg_name)
        except Exception:
            continue
    return {pkg.lower(): "N/A" for pkg in packages}

def check_package_versions(packages_to_check):
    """Uses a thread pool to fetch and process package data concurrently."""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_pkg = {executor.submit(get_pypi_data, name): name for name in packages_to_check.keys()}
        
        for future in future_to_pkg:
            pkg_name = future_to_pkg[future]
            current_version_str = packages_to_check[pkg_name]
            pypi_data = future.result()
            
            if pypi_data:
                info = pypi_data.get("info", {})
                latest_version_str = info.get("version", "N/A")
                
                status = "✅ Up-to-date"
                if current_version_str != "N/A" and latest_version_str != "N/A":
                    try:
                        current_v = parse_version(current_version_str)
                        latest_v = parse_version(latest_version_str)
                        if latest_v > current_v:
                            status = "⚠️ Outdated"
                            if latest_v.major > current_v.major:
                                status = "❌ Major Update"
                    except Exception:
                        status = "❓ Invalid Version"
                elif current_version_str == "N/A":
                    status = "ℹ️ Latest"

                license_str = info.get("license")
                final_license = (license_str.strip() if isinstance(license_str, str) else "") or "Not Specified"

                results.append(PackageInfo(
                    name=pkg_name,
                    current_version=current_version_str,
                    latest_version=latest_version_str,
                    license=final_license,
                    summary=info.get("summary", "No summary available.").strip(),
                    status=status,
                    pypi_url=info.get("package_url", "")
                ))
            else:
                results.append(PackageInfo(name=pkg_name, status="❓ Not Found on PyPI"))
    return sorted(results, key=lambda x: x.name)

# --- Streamlit UI ---

# NEW: Get username to fetch the correct files
username = st.session_state.get("username", "guest")

tab1, tab2 = st.tabs(["Scan `requirements.txt`", "Scan Project Python Files"])

with tab1:
    st.header("Upload `requirements.txt`")
    uploaded_req_file = st.file_uploader("Choose a requirements.txt file", type=['txt'])

    if uploaded_req_file:
        content = uploaded_req_file.getvalue().decode("utf-8")
        packages_to_check = parse_requirements(content)
        
        if st.button("🕵️ Scan `requirements.txt` Dependencies", key="scan_req"):
            with st.spinner(f"Scanning {len(packages_to_check)} packages... This might take a moment."):
                results = check_package_versions(packages_to_check)
                st.session_state.scan_results = results

with tab2:
    st.header("Scan Imported Packages from Project Files")
    st.info("This will find all imported packages in the Python files saved to your project via the main dashboard.")
    
    # CHANGED: Fetching files directly from the database
    user_files = get_user_files(username)
    py_files_from_db = [f for f in user_files if f.get("filename", "").endswith(".py")]
    
    if not py_files_from_db:
        st.warning("No Python files found in your project. Please upload some on the 'Project Dashboard' page first.")
    else:
        st.write(f"Found **{len(py_files_from_db)}** Python file(s) in your project to analyze.")
        if st.button("🕵️ Scan Project File Imports", key="scan_py"):
            with st.spinner("Scanning imports and fetching package info..."):
                # Use the new function to process DB data
                packages_to_check = get_imported_packages_from_db(py_files_from_db)
                results = check_package_versions(packages_to_check)
                st.session_state.scan_results = results

# --- Display Results ---
if 'scan_results' in st.session_state:
    results = st.session_state.scan_results
    if not results:
        st.error("No packages found to analyze.")
    else:
        st.divider()
        st.header("Scan Results")
        
        outdated_count = sum(1 for r in results if r.status in ["⚠️ Outdated", "❌ Major Update"])
        license_types = len(set(r.license for r in results if r.license != "N/A" and r.license != "Not Specified"))

        col1, col2, col3 = st.columns(3)
        col1.metric("📦 Total Packages", len(results))
        col2.metric("⬆️ Outdated Packages", outdated_count)
        col3.metric("📜 License Types", license_types)
        
        df = pd.DataFrame(results)
        st.dataframe(
            df,
            column_config={
                "pypi_url": st.column_config.LinkColumn("PyPI Link", display_text="🔗 View on PyPI"),
                "name": "Package",
                "current_version": "Current Version",
                "latest_version": "Latest Version",
                "status": "Status",
                "license": "License",
                "summary": "Summary"
            },
            use_container_width=True,
            hide_index=True
        )