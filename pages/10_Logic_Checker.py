# pages/10_Logic_Checker.py
import streamlit as st
import ast
import yaml
import pandas as pd
import re
from collections import defaultdict
from dataclasses import dataclass, field

# Radon is used for cyclomatic complexity analysis and works offline.
try:
    from radon.visitors import ComplexityVisitor
except ImportError:
    st.error("The 'radon' library is required for complexity analysis. Please install it: `pip install radon`")
    st.stop()

st.set_page_config(layout="wide")
st.title("⚙️ Advanced Logic Analyzer")
st.markdown("Analyze code against a library of pre-built checks and your own custom-defined rules without using any external APIs.")

# --- SAFE CONDITION EVALUATOR (Replaces raw eval()) ---

class SafeEvalVisitor(ast.NodeVisitor):
    """
    Visits the AST of a condition string and raises an error if it contains unsafe nodes.
    """
    ALLOWED_NODES = (
        ast.Expression, ast.Compare, ast.BinOp, ast.UnaryOp, ast.boolop,
        ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Lt, ast.LtE,
        ast.Gt, ast.GtE, ast.Is, ast.IsNot, ast.In, ast.NotIn,
        ast.Load, ast.Name, ast.Attribute, ast.Constant
    )

    def generic_visit(self, node):
        if not isinstance(node, self.ALLOWED_NODES):
            raise ValueError(f"Unsafe operation '{type(node).__name__}' found in condition.")
        super().generic_visit(node)

def safe_eval_condition(condition_str: str, context: dict) -> bool:
    """
    Safely evaluates a condition string by parsing it into an AST, validating its nodes,
    and then compiling and evaluating it.
    """
    try:
        tree = ast.parse(condition_str, mode='eval')
        validator = SafeEvalVisitor()
        validator.visit(tree)
        # The expression is safe, so we can compile and evaluate it.
        return eval(compile(tree, '<string>', 'eval'), {"__builtins__": {}}, context)
    except (ValueError, SyntaxError, NameError, AttributeError) as e:
        st.warning(f"Could not evaluate condition '{condition_str}': {e}")
        return False

# --- EXPANDED DATA CLASSES FOR AST NODES ---
@dataclass
class FunctionNode:
    name: str
    raw_node: ast.AST = field(repr=False)
    lines_of_code: int = 0
    arg_count: int = 0
    cyclomatic_complexity: int = 1
    has_docstring: bool = False
    type_hint_coverage: float = 0.0
    is_snake_case: bool = True

@dataclass
class ClassNode:
    name: str
    raw_node: ast.AST = field(repr=False)
    lines_of_code: int = 0
    method_count: int = 0
    has_docstring: bool = False
    is_pascal_case: bool = True

# --- CORE ANALYSIS LOGIC ---

class LogicVisitor(ast.NodeVisitor):
    def __init__(self, rules):
        self.rules = rules
        self.findings = []

    def visit_ClassDef(self, node: ast.ClassDef):
        lines = (getattr(node, 'end_lineno', node.lineno) - node.lineno) + 1
        methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
        class_node = ClassNode(
            name=node.name,
            raw_node=node,
            lines_of_code=lines,
            method_count=len(methods),
            has_docstring=bool(ast.get_docstring(node)),
            is_pascal_case=bool(re.match(r'^[A-Z][a-zA-Z0-9]*$', node.name))
        )
        
        for rule in self.rules.get("class", []):
            if safe_eval_condition(rule['condition'], {"node": class_node}):
                self.findings.append({"line": node.lineno, "rule_name": rule['rule_name'], "message": rule['message'].format(node=class_node)})
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Correctly calculate cyclomatic complexity
        visitor = ComplexityVisitor()
        visitor.visit(node)
        
        # Accurately calculate type hint coverage for all argument types
        all_args = node.args.args + node.args.kwonlyargs
        if node.args.vararg: all_args.append(node.args.vararg)
        if node.args.kwarg: all_args.append(node.args.kwarg)
        total_args = len(all_args)
        hinted_args = sum(1 for arg in all_args if arg.annotation is not None)
        
        func_node = FunctionNode(
            name=node.name,
            raw_node=node,
            lines_of_code=(getattr(node, 'end_lineno', node.lineno) - node.lineno) + 1,
            arg_count=total_args,
            has_docstring=bool(ast.get_docstring(node)),
            type_hint_coverage=(hinted_args / total_args * 100) if total_args else 100.0,
            is_snake_case=bool(re.match(r'^[a-z_][a-z0-9_]*$', node.name)),
            cyclomatic_complexity=visitor.complexity
        )

        for rule in self.rules.get("function", []):
            if safe_eval_condition(rule['condition'], {"node": func_node}):
                self.findings.append({"line": node.lineno, "rule_name": rule['rule_name'], "message": rule['message'].format(node=func_node)})
        
        self.generic_visit(node)

@st.cache_data
def run_custom_analysis(code_content: str, custom_rules_yaml: str):
    rules = defaultdict(list)
    try:
        if custom_rules_yaml.strip():
            custom_rules = yaml.safe_load(custom_rules_yaml)
            if custom_rules:
                for rule in custom_rules:
                    if rule and rule.get('target') in ['function', 'class']:
                        rules[rule['target']].append(rule)
    except yaml.YAMLError as e:
        return f"Error parsing your custom YAML rules: {e}"

    try:
        tree = ast.parse(code_content)
        visitor = LogicVisitor(rules)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError as e:
        return f"Could not parse Python code: {e}"

# --- IMPROVED YAML RULE TEMPLATE ---
DEFAULT_YAML_RULES = """
# ------------------ FUNCTION RULES ------------------
# You can access: name, lines_of_code, arg_count, cyclomatic_complexity,
# has_docstring (bool), type_hint_coverage (0-100), is_snake_case (bool)

- rule_name: "High Cyclomatic Complexity"
  target: function
  condition: "node.cyclomatic_complexity > 10"
  message: "Function '{node.name}' has high complexity ({node.cyclomatic_complexity}). Simplify it."

- rule_name: "Missing Docstring"
  target: function
  condition: "not node.has_docstring"
  message: "Function '{node.name}' is missing a docstring."

- rule_name: "Poor Type Hint Coverage"
  target: function
  condition: "node.type_hint_coverage < 100"
  message: "Function '{node.name}' has only {node.type_hint_coverage:.0f}% type hint coverage."

- rule_name: "Improper Function Naming"
  target: function
  condition: "not node.is_snake_case and node.name != '__init__'"
  message: "Function name '{node.name}' is not in snake_case."

# ------------------- CLASS RULES --------------------
# You can access: name, lines_of_code, method_count,
# has_docstring (bool), is_pascal_case (bool)

- rule_name: "Bloated Class"
  target: class
  condition: "node.lines_of_code > 200 and node.method_count > 10"
  message: "Class '{node.name}' is bloated ({node.lines_of_code} lines, {node.method_count} methods)."

- rule_name: "Improper Class Naming"
  target: class
  condition: "not node.is_pascal_case"
  message: "Class name '{node.name}' is not in PascalCase."
"""

# --- STREAMLIT UI ---
if "uploaded_files" not in st.session_state:
    st.session_state["uploaded_files"] = []

python_files = [f for f in st.session_state.uploaded_files if f.name.endswith('.py')]

if not python_files:
    st.warning("Please upload Python files from the '📂 Project Dashboard' to use this feature.")
else:
    st.subheader("1. Select Code to Analyze")
    selected_file_name = st.selectbox("Select a file", [f.name for f in python_files])
    
    st.subheader("2. Define Analysis Rules (YAML)")
    custom_rules_yaml = st.text_area(
        "Define your rules here. Conditions are safely evaluated (no function calls).",
        value=DEFAULT_YAML_RULES,
        height=400
    )

    if st.button("🔬 Analyze with Custom Rules", use_container_width=True, type="primary"):
        file_to_scan = next((f for f in python_files if f.name == selected_file_name), None)
        if file_to_scan:
            file_to_scan.seek(0)
            code_content = file_to_scan.getvalue().decode("utf-8")
            
            with st.spinner("Applying advanced logic..."):
                findings = run_custom_analysis(code_content, custom_rules_yaml)
                st.session_state['logic_findings'] = findings

    if 'logic_findings' in st.session_state:
        st.subheader("3. Analysis Results")
        findings = st.session_state['logic_findings']
        
        if isinstance(findings, str):
            st.error(findings)
        elif not findings:
            st.success("✅ No violations of the specified rules were found.")
            st.balloons()
        else:
            df = pd.DataFrame(findings)
            st.dataframe(df.sort_values(by="line").reset_index(drop=True), use_container_width=True, hide_index=True)