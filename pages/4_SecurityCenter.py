# pages/4_SecurityCenter.py
import streamlit as st
import ast
import re
import math
from dataclasses import dataclass, asdict # FIX: Import 'asdict'

# --- Data Structure and Main Analysis Class ---

@dataclass
class SecurityFinding:
    severity: str  # Critical, High, Medium, Low
    title: str
    description: str
    line_number: int
    code: str
    remediation: str

def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string to guess if it's a secret."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

class SecurityVisitor(ast.NodeVisitor):
    """
    A single-pass AST visitor to efficiently find common security vulnerabilities.
    """
    def __init__(self, lines: list[str]):
        self.lines = lines
        self.findings: list[SecurityFinding] = []
        self.secret_keywords = re.compile(
            r'key|secret|token|password|passwd|api_key|auth_token|client_secret|db_pass', re.I
        )

    def _add_finding(self, node, title, description, severity, remediation):
        finding = SecurityFinding(
            severity=severity, title=title, description=description,
            line_number=node.lineno,
            code=self.lines[node.lineno - 1].strip(),
            remediation=remediation
        )
        self.findings.append(finding)

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            secret_value = node.value.value
            for target in node.targets:
                if isinstance(target, ast.Name) and self.secret_keywords.search(target.id):
                    if calculate_entropy(secret_value) > 3.5:
                        self._add_finding(
                            node, "High-Entropy Hardcoded Secret Detected",
                            "A string with high entropy (high randomness) assigned to a secret-like variable name was found. This is very likely a real credential.",
                            "Critical",
                            "Store secrets in environment variables or a dedicated secrets management service. Never commit secrets to version control."
                        )
                        break
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.upper() == 'DEBUG':
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                        self._add_finding(
                            node, "Debug Mode appears to be Enabled",
                            "Running an application in production with debug mode enabled can expose sensitive information and security risks.",
                            "High",
                            "Ensure debug mode is disabled in production settings. Use environment variables to control this configuration."
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ast.unparse(node.func)
        if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
            self._add_finding(node, f"Use of Dangerous Function: {node.func.id}", f"The `{node.func.id}` function can execute arbitrary code and is a major security risk if used with untrusted input.", "Critical", "Avoid `eval()` and `exec()`. Refactor the code to use safer alternatives.")
        if 'pickle.load' in func_name:
            self._add_finding(node, "Insecure Deserialization with Pickle", "Deserializing data with `pickle` from an untrusted source can lead to arbitrary code execution.", "Critical", "Use a safe serialization format like JSON if interacting with untrusted data.")
        if 'os.system' in func_name:
            self._add_finding(node, "Potential Command Injection via os.system", "Using `os.system` with user-controlled input can allow an attacker to execute arbitrary shell commands.", "High", "Use the `subprocess` module with command arguments passed as a list (e.g., `subprocess.run(['ls', '-l'])`).")
        if 'subprocess' in func_name:
            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self._add_finding(node, "Potential Command Injection via shell=True", "Using `subprocess` functions with `shell=True` and user input can lead to shell command injection.", "High", "Avoid `shell=True`. Pass command arguments as a list to the `subprocess` function.")
        if 'hashlib.md5' in func_name or 'hashlib.sha1' in func_name:
            algo = "MD5" if 'md5' in func_name else "SHA1"
            self._add_finding(node, f"Use of Weak Hashing Algorithm: {algo}", f"{algo} is considered cryptographically weak and should not be used for security purposes like password hashing.", "Medium", "Use a strong algorithm like SHA-256. For passwords, use a dedicated library like Argon2 or Bcrypt.")
        if 'mktemp' in func_name:
            self._add_finding(node, "Use of Insecure tempfile.mktemp", "`tempfile.mktemp()` is insecure due to a potential race condition.", "Medium", "Use `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile` instead.")
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        sql_keywords = r"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)"
        full_string_guess = "".join([s.value for s in node.values if isinstance(s, ast.Constant)])
        if re.search(sql_keywords, full_string_guess, re.I):
            self._add_finding(node, "Potential SQL Injection Risk (f-string)", "An f-string appears to be constructing an SQL query. This is highly vulnerable to SQL injection if variables contain user input.", "High", "Use parameterized queries or an ORM like SQLAlchemy.")
        self.generic_visit(node)

# --- Main Scanner & UI ---

@st.cache_data
def run_security_scan(content: str) -> list[dict]: # FIX: Return type is now list[dict]
    """Runs all security checks on the given file content using an AST visitor."""
    lines = content.splitlines()
    try:
        tree = ast.parse(content)
        visitor = SecurityVisitor(lines)
        visitor.visit(tree)
        # FIX: Convert list of objects to list of dictionaries before returning
        severity_order = ["Critical", "High", "Medium", "Low"]
        # Sort by line number first, then severity
        sorted_findings = sorted(
            visitor.findings,
            key=lambda f: (f.line_number, severity_order.index(f.severity))
        )
        return [asdict(f) for f in sorted_findings]
    except SyntaxError:
        return []

st.set_page_config(layout="wide")
st.title("🛡️ Security Center")
st.markdown("This tool performs an **AST-based static analysis** for common security vulnerabilities in your Python code.")

uploaded_files = st.session_state.get("uploaded_files", [])

if not uploaded_files:
    st.info("Upload Python files in the '📂 Project Dashboard' to begin a security scan.")
else:
    file_names = [f.name for f in uploaded_files if f.name.endswith('.py')]
    if not file_names:
        st.warning("No Python (.py) files found. The security scanner works with Python files.")
    else:
        selected_file_name = st.selectbox("Select a Python file to scan", file_names)
        selected_file = next((f for f in uploaded_files if f.name == selected_file_name), None)

        if selected_file:
            selected_file.seek(0) # Ensure file pointer is at the beginning
            try:
                content = selected_file.getvalue().decode("utf-8")
            except UnicodeDecodeError:
                st.warning("Could not decode as UTF-8. Trying 'latin-1' as a fallback.")
                selected_file.seek(0)
                content = selected_file.getvalue().decode("latin-1")
            
            with st.spinner("🧠 Performing deep code analysis..."):
                findings = run_security_scan(content)
            
            st.header(f"Scan Report for `{selected_file_name}`")

            # This UI code now works correctly because `findings` is a list of dictionaries
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for f in findings:
                if f['severity'] in severity_counts:
                    severity_counts[f['severity']] += 1
            
            score = 100 - (severity_counts["Critical"] * 20 + severity_counts["High"] * 10 + severity_counts["Medium"] * 3 + severity_counts["Low"] * 1)
            score = max(0, score)
            
            st.progress(score, text=f"Security Score: {score}/100")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("🚨 Critical Issues", severity_counts["Critical"])
            col2.metric("⚠️ High Severity", severity_counts["High"])
            col3.metric("ℹ️ Medium Severity", severity_counts["Medium"])
            
            st.divider()

            if not findings:
                st.success("✅ No major security vulnerabilities found. Great work!")
            else:
                st.subheader("Vulnerabilities Found:")
                severity_emojis = {"Critical": "🚨", "High": "⚠️", "Medium": "ℹ️", "Low": "🔹"}
                for finding in findings:
                    emoji = severity_emojis.get(finding['severity'], "")
                    with st.expander(f"{emoji} **{finding['severity']}**: {finding['title']} (Line {finding['line_number']})", expanded=finding['severity']=="Critical"):
                        st.markdown(f"**Description:** {finding['description']}")
                        st.code(finding['code'], language="python")
                        st.markdown(f"**💡 Remediation:** {finding['remediation']}")