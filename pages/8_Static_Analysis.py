# pages/8_Static_Analysis.py
import streamlit as st
import pandas as pd
import tempfile
import os
import io
import re
from contextlib import redirect_stdout

# Pylint and MyPy are required for this page
try:
    from pylint.lint import Run as PylintRun
    from mypy import api as mypy_api
except ImportError:
    st.error("Pylint and MyPy are required for this page. Please install them: `pip install pylint mypy`")
    st.stop()

st.set_page_config(layout="wide")
st.title("⚙️ Static Code Analysis / Bug Finder")
st.markdown("Perform a deep code analysis using **Pylint** and **MyPy** to find potential bugs, enforce standards, and check type safety.")

# --- Analysis Logic ---

@st.cache_data
def run_pylint_analysis(code_content: str):
    """
    Runs Pylint on the given code content and returns the score and issues.
    """
    issues = []
    score = 0.0
    
    # Using UTF-8 to prevent encoding errors
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as tmp_file:
        tmp_file.write(code_content)
        tmp_file_path = tmp_file.name

    # Capture Pylint's output
    pylint_output = io.StringIO()
    try:
        with redirect_stdout(pylint_output):
            results = PylintRun([tmp_file_path], do_exit=False)
            score = results.linter.stats.global_note
    except Exception as e:
        # The key fix is adding a placeholder 'symbol' to make the data structure consistent
        return score, [{"type": "Fatal", "line": 1, "message": f"Pylint failed to run: {e}", "code": "F0001", "symbol": "fatal-error"}]
    finally:
        os.unlink(tmp_file_path)

    output = pylint_output.getvalue()
    
    pattern = re.compile(r".*?:(\d+):\d+: ([A-Z]): \((.*?),(.*?)\) (.*)")
    
    lines = output.split('\n')
    for line in lines:
        match = pattern.match(line)
        if match:
            issue_type_map = {'R': 'Refactor', 'C': 'Convention', 'W': 'Warning', 'E': 'Error', 'F': 'Fatal'}
            issues.append({
                "line": int(match.group(1)),
                "type": issue_type_map.get(match.group(2), "Unknown"),
                "symbol": match.group(3),
                "code": match.group(4).strip(),
                "message": match.group(5).strip()
            })
            
    return score, issues

@st.cache_data
def run_mypy_analysis(code_content: str):
    """
    Runs MyPy on the given code content and returns the findings.
    """
    args = ['--command', code_content, '--ignore-missing-imports', '--show-error-codes']
    
    try:
        result = mypy_api.run(args)
        stdout, stderr, exit_status = result
        
        parsed_errors = []
        if exit_status != 0:
            for line in stdout.split('\n'):
                if line and not line.startswith("Found") and not line.startswith("Success"):
                    parts = line.split(':')
                    if len(parts) >= 4:
                        parsed_errors.append({
                            "line": int(parts[1]),
                            "type": parts[2].strip(),
                            "message": ":".join(parts[3:]).strip()
                        })
        return parsed_errors, stderr
    except Exception as e:
        return [], f"MyPy failed to run: {e}"

# --- UI ---

uploaded_files = st.session_state.get("uploaded_files", [])
python_files = [f for f in uploaded_files if f.name.endswith('.py')]

if not python_files:
    st.warning("Please upload some Python files from the 'Project Dashboard' to begin analysis.")
else:
    file_options = [f.name for f in python_files]
    selected_file_name = st.selectbox("Select a Python file to analyze", file_options)
    
    selected_file = next((f for f in python_files if f.name == selected_file_name), None)

    if selected_file:
        code_content = selected_file.getvalue().decode("utf-8")

        if st.button("🔍 Analyze Code for Bugs & Quality", use_container_width=True, type="primary"):
            pylint_score, pylint_issues = run_pylint_analysis(code_content)
            mypy_errors, mypy_stderr = run_mypy_analysis(code_content)

            st.session_state['pylint_score'] = pylint_score
            st.session_state['pylint_issues'] = pylint_issues
            st.session_state['mypy_errors'] = mypy_errors
            st.session_state['mypy_stderr'] = mypy_stderr
    
    if 'pylint_issues' in st.session_state:
        st.header(f"Analysis Report for `{selected_file_name}`")
        
        tab1, tab2 = st.tabs(["Pylint Bug & Quality Report", "MyPy Type Safety Report"])

        # --- Pylint Tab ---
        with tab1:
            pylint_score = st.session_state['pylint_score']
            pylint_issues = st.session_state['pylint_issues']

            st.subheader("Pylint Code Quality Score")
            st.progress(pylint_score / 10.0, text=f"Score: {pylint_score:.2f} / 10.0")

            st.subheader("Detected Issues")
            if not pylint_issues:
                st.success("✅ Pylint found no issues. Excellent code quality!")
                st.balloons()
            else:
                df = pd.DataFrame(pylint_issues)
                
                issue_types = df['type'].unique()
                selected_types = st.multiselect("Filter by issue type:", options=issue_types, default=list(issue_types))
                
                filtered_df = df[df['type'].isin(selected_types)]
                st.dataframe(filtered_df[['line', 'type', 'code', 'symbol', 'message']], use_container_width=True, hide_index=True)
        
        # --- MyPy Tab ---
        with tab2:
            mypy_errors = st.session_state['mypy_errors']
            mypy_stderr = st.session_state['mypy_stderr']

            st.subheader("MyPy Type Safety Analysis")
            st.metric("Total Type Errors Found", len(mypy_errors))

            if mypy_stderr:
                st.error("MyPy encountered an error during execution:")
                st.code(mypy_stderr)

            if not mypy_errors:
                st.success("✅ MyPy found no type errors. Your code is type-safe!")
            else:
                df_mypy = pd.DataFrame(mypy_errors)
                st.dataframe(df_mypy[['line', 'type', 'message']], use_container_width=True, hide_index=True)