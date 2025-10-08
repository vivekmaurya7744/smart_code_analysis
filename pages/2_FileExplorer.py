# pages/2_FileExplorer.py
import streamlit as st
import ast
import re
import pandas as pd
import graphviz
from dataclasses import dataclass, asdict
from typing import List, Set

# Try to import radon, provide helpful error if it's not installed.
try:
    from radon.visitors import ComplexityVisitor
    from radon.metrics import mi_visit
    from radon.raw import analyze as analyze_raw
except ImportError:
    st.error("The 'radon' library is not installed. Please install it to use advanced complexity metrics: `pip install radon`")
    st.stop()

# --- Data Structures for Clean Analysis (No changes here) ---
@dataclass
class CodeIssue:
    line: int
    message: str
    code: str = ""
    severity: str = "Info"

@dataclass
class FunctionInfo:
    name: str
    lineno: int
    end_lineno: int
    args: list[str]
    lines_of_code: int
    has_docstring: bool
    type_hint_coverage: float
    complexity: int = 0

@dataclass
class ClassInfo:
    name: str
    lineno: int
    end_lineno: int
    lines_of_code: int
    has_docstring: bool

# --- The Core Analyzer using ast.NodeVisitor (No changes here) ---
class CodeAnalyzerVisitor(ast.NodeVisitor):
    """An efficient AST visitor to gather code metrics and issues in a single pass."""
    def __init__(self, lines: List[str]):
        self.lines = lines
        self.functions: List[FunctionInfo] = []
        self.classes: List[ClassInfo] = []
        self.imports: Set[str] = set()
        self.imported_names: Set[str] = set()
        self.used_names: Set[str] = set()
        self.issues: List[CodeIssue] = []

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        current_node = node
        while isinstance(current_node, ast.Attribute):
            current_node = current_node.value
        if isinstance(current_node, ast.Name):
            self.used_names.add(current_node.id)
        self.generic_visit(node)
        
    def visit_FunctionDef(self, node: ast.FunctionDef):
        num_lines = (node.end_lineno - node.lineno) + 1
        args = [arg.arg for arg in node.args.args]
        hinted_args = sum(1 for arg in node.args.args if arg.annotation is not None)
        type_hint_coverage = (hinted_args / len(args)) * 100 if args else 100.0
        func_info = FunctionInfo(name=node.name, lineno=node.lineno, end_lineno=node.end_lineno, args=args, lines_of_code=num_lines, has_docstring=ast.get_docstring(node) is not None, type_hint_coverage=type_hint_coverage)
        self.functions.append(func_info)
        if num_lines > 50: self.issues.append(CodeIssue(node.lineno, f"Function `{node.name}` is too long ({num_lines} lines). Consider refactoring.", severity="Warning"))
        if len(args) > 5: self.issues.append(CodeIssue(node.lineno, f"Function `{node.name}` has too many arguments ({len(args)}). Consider using a dataclass.", severity="Warning"))
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.issues.append(CodeIssue(node.lineno, f"Function `{node.name}` uses a mutable default argument.", severity="Warning"))
                break
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        num_lines = (node.end_lineno - node.lineno) + 1
        class_info = ClassInfo(name=node.name, lineno=node.lineno, end_lineno=node.end_lineno, lines_of_code=num_lines, has_docstring=ast.get_docstring(node) is not None)
        self.classes.append(class_info)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name.split('.')[0])
            self.imported_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module: self.imports.add(node.module.split('.')[0])
        for alias in node.names:
            if alias.name == '*': self.issues.append(CodeIssue(node.lineno, "Star import (`from ... import *`) is used, which is a bad practice.", severity="Warning"))
            self.imported_names.add(alias.asname or alias.name)
        self.generic_visit(node)
    
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None and not node.body: self.issues.append(CodeIssue(node.lineno, "Bare `except:` block can hide errors. Specify an exception type.", severity="Warning"))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']: self.issues.append(CodeIssue(node.lineno, f"Use of `{node.func.id}` is a major security risk.", severity="Danger"))
        if isinstance(node.func, ast.Attribute) and node.func.attr in ['run', 'call', 'check_call', 'Popen'] and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
            for kw in node.keywords:
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True: self.issues.append(CodeIssue(node.lineno, "Using `subprocess` with `shell=True` is a security risk.", severity="Danger"))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, (int, float)) and node.value not in [0, 1]:
            line_content = self.lines[node.lineno - 1]
            if not re.search(r'def .*\((.*=.*)\):', line_content) and not re.match(r'^[A-Z_]+\s*=\s*[\d.]+$', line_content.strip()) and len(line_content.split()) > 3:
                self.issues.append(CodeIssue(node.lineno, f"Magic number `{node.value}` found. Consider defining it as a constant.", code=line_content.strip(), severity="Info"))
        self.generic_visit(node)

# --- Helper function to calculate a quality score (No changes here) ---
def calculate_quality_score(analysis: dict) -> int:
    score = 100
    mi = analysis.get('maintainability_index', 70)
    if mi < 50: score -= (50 - mi) * 0.5
    for issue in analysis.get("issues", []):
        if issue['severity'] == "Danger": score -= 15
        elif issue['severity'] == "Warning": score -= 5
        else: score -= 1
    doc_cov = analysis.get('docstring_coverage', 100)
    if doc_cov < 80: score -= (80 - doc_cov) * 0.2
    return max(0, int(score))

# --- Main Analysis Function (with Caching) ---
@st.cache_data
def analyze_code(content: str):
    """Performs a comprehensive static analysis and returns a dictionary of results."""
    lines = content.splitlines()
    if not lines: return None
    
    analysis = {"lines": lines, "issues": []}

    for i, line in enumerate(lines):
        line_num = i + 1
        if len(line) > 99: analysis["issues"].append(CodeIssue(line_num, "Line is longer than 99 characters.", code=line, severity="Info"))
        if re.search(r'#\s*(TODO|FIXME)', line, re.I): analysis["issues"].append(CodeIssue(line_num, "TODO/FIXME comment found.", code=line.strip()))
        if re.search(r'\s+$', line): analysis["issues"].append(CodeIssue(line_num, "Trailing whitespace detected."))
    
    analysis['issues'] = [asdict(i) for i in analysis['issues']]

    try:
        tree = ast.parse(content)
        visitor = CodeAnalyzerVisitor(lines)
        visitor.visit(tree)
        
        analysis["functions"] = [asdict(f) for f in visitor.functions]
        analysis["classes"] = [asdict(c) for c in visitor.classes]
        analysis["imports"] = visitor.imports
        analysis["imported_names"] = visitor.imported_names
        analysis["used_names"] = visitor.used_names
        analysis["issues"].extend([asdict(i) for i in visitor.issues])
        
    except SyntaxError as e:
        st.error(f"Cannot parse file: Invalid Python syntax at line {e.lineno}. Details: {e.msg}")
        return None

    try:
        complexity_visitor = ComplexityVisitor.from_code(content)
        analysis["maintainability_index"] = mi_visit(content, multi=True)
        func_map = {f['name']: f for f in analysis["functions"]}
        for block in complexity_visitor.functions:
            if block.name in func_map and func_map[block.name]['lineno'] == block.lineno:
                func_map[block.name]['complexity'] = block.complexity
    except Exception:
        analysis["maintainability_index"] = -1

    analysis["unused_imports"] = sorted([name for name in analysis["imported_names"] if name not in analysis["used_names"] and name not in ['_']])
    
    raw_stats = analyze_raw(content)
    analysis["loc"] = raw_stats.loc
    analysis["lloc"] = raw_stats.lloc
    total_funcs = len(analysis["functions"])
    docstring_funcs = sum(1 for f in analysis["functions"] if f['has_docstring'])
    analysis['docstring_coverage'] = (docstring_funcs / total_funcs * 100) if total_funcs else 100
    
    analysis['quality_score'] = calculate_quality_score(analysis)
    return analysis

# --- Streamlit UI ---
st.set_page_config(layout="wide", page_title="Advanced Code Explorer")
st.title("📄 Advanced Code Explorer & Linter")

uploaded_files = st.session_state.get("uploaded_files", [])

if not uploaded_files:
    st.info("To get started, upload Python files on the '📂 Project Dashboard' page.")
else:
    file_names = [f.name for f in uploaded_files if f.name.endswith('.py')]
    if not file_names:
        st.warning("No Python (.py) files were found. This tool is designed for Python code analysis.")
    else:
        selected_file_name = st.selectbox("Select a Python file to explore", file_names)
        selected_file = next((f for f in uploaded_files if f.name == selected_file_name), None)

        if selected_file:
            selected_file.seek(0)
            content = selected_file.getvalue().decode("utf-8", errors="replace")
            
            results = analyze_code(content)
            
            if results:
                st.markdown(f"### Analysis for `{selected_file.name}`")
                
                tabs = ["📊 Dashboard", "📈 Complexity", "📄 Code Viewer", "🌐 Dependencies", "🗺️ Navigation"]
                tab1, tab2, tab3, tab4, tab5 = st.tabs(tabs)

                with tab1:
                    score = results.get('quality_score', 0)
                    st.header(f"Code Quality Score: {score}/100")
                    st.progress(score, text="⭐ Excellent" if score >= 85 else ("👍 Good" if score >= 60 else "🔧 Needs Improvement"))
                    st.markdown("---")
                    
                    mi = results.get('maintainability_index', -1)
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Logical Lines of Code", results.get("lloc", "N/A"))
                    col2.metric("Function Count", len(results["functions"]))
                    col3.metric("Class Count", len(results["classes"]))
                    col4.metric("Maintainability Index", f"{mi:.1f}" if mi != -1 else "N/A", help="A score from 0-100. Higher is better. >60 is good, <40 is poor.", delta_color="normal" if mi >= 60 else ("off" if mi >= 40 else "inverse"))

                    with st.expander("⚠️ Quality Alerts & Linter Results", expanded=True):
                        sorted_issues = sorted(results["issues"], key=lambda x: ("Danger", "Warning", "Info").index(x['severity']))
                        if not sorted_issues: st.success("✅ No major quality issues detected. Excellent work!")
                        else:
                            for issue in sorted_issues:
                                if issue['severity'] == "Danger": st.error(f"**L{issue['line']}:** {issue['message']}", icon="🚨")
                                elif issue['severity'] == "Warning": st.warning(f"**L{issue['line']}:** {issue['message']}", icon="⚠️")
                                else: st.info(f"**L{issue['line']}:** {issue['message']}", icon="ℹ️")
                                if issue['code']: st.code(issue['code'], language='python')
                    
                    with st.expander("📋 Code Coverage & Structure"):
                         if results["unused_imports"]: st.warning(f"Potentially Unused Imports: `{', '.join(results['unused_imports'])}`")
                         doc_cov = results.get('docstring_coverage', 100)
                         st.progress(int(doc_cov), text=f"Docstring Coverage: {doc_cov:.1f}%")

                with tab2:
                    st.subheader("Function Complexity Analysis")
                    st.info("Cyclomatic Complexity measures independent paths in code. Lower is better (1-5 is great, >10 is complex).", icon="💡")
                    if results["functions"]:
                        df = pd.DataFrame(
                            [(f['name'], f['complexity'], f['lines_of_code'], f['type_hint_coverage']) for f in results["functions"]],
                            columns=["Function", "Complexity", "Lines of Code", "Type Hint Coverage (%)"]
                        ).set_index("Function")
                        st.scatter_chart(df, x="Lines of Code", y="Complexity", color=["#FF4B4B"])
                        with st.expander("View Complexity Data Table", expanded=False): st.dataframe(df.sort_values(by="Complexity", ascending=False))
                    else: st.markdown("No functions found to analyze.")

                with tab3:
                    search_term = st.text_input("Search in code", placeholder="Enter search term to highlight...", key="search_code")
                    
                    lines_with_numbers = []
                    for i, line in enumerate(results["lines"]):
                        display_line = line
                        if search_term and search_term.lower() in line.lower():
                            display_line = re.sub(f'({re.escape(search_term)})', r'>>\1<<', line, flags=re.IGNORECASE)
                        lines_with_numbers.append(f"{i+1:<4d}| {display_line}")

                    full_code_text = "\n".join(lines_with_numbers)
                    st.code(full_code_text, language="python", line_numbers=False)
                
                with tab4:
                    st.subheader("Import Dependency Graph")
                    if results['imports']:
                        dot = graphviz.Digraph(comment='Dependency Graph')
                        dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue')
                        dot.node(selected_file.name, style='rounded,filled', fillcolor='lightgreen')
                        for imp in sorted(list(results['imports'])):
                            dot.node(imp)
                            dot.edge(selected_file.name, imp)
                        st.graphviz_chart(dot)
                    else: st.info("No external imports found in this file.")

                with tab5:
                    st.subheader("🚀 Jump to Definition")
                    c1, c2 = st.columns(2)
                    func_names = ["Select a function..."] + sorted([f['name'] for f in results["functions"]])
                    selected_func = c1.selectbox("Functions", func_names, key="nav_func")
                    if selected_func != "Select a function...":
                        func = next(f for f in results["functions"] if f['name'] == selected_func)
                        code = "\n".join(results["lines"][func['lineno']-1:func['end_lineno']])
                        st.code(code, language="python", line_numbers=True)

                    class_names = ["Select a class..."] + sorted([c['name'] for c in results["classes"]])
                    selected_class = c2.selectbox("Classes", class_names, key="nav_class")
                    if selected_class != "Select a class...":
                        cls = next(c for c in results["classes"] if c['name'] == selected_class)
                        code = "\n".join(results["lines"][cls['lineno']-1:cls['end_lineno']])
                        st.code(code, language="python", line_numbers=True)