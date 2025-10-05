# pages/11_Duplicate_Finder.py
import streamlit as st
import ast
import hashlib
from collections import defaultdict

st.set_page_config(layout="wide")
st.title("✂️ Duplicate Code Finder")
st.markdown("This tool analyzes all Python files in your project to identify duplicate functions and classes.")

# --- CORE LOGIC ---

def normalize_code_block(node):
    """
    Normalizes the code from an AST node (function/class) by removing docstrings and comments.
    """
    if not isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
        return None

    # Remove the docstring from the node's body
    if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
        # Create a copy of the node to modify it
        node_copy = ast.parse(ast.unparse(node)).body[0]
        node_copy.body = node_copy.body[1:] if len(node_copy.body) > 1 else [ast.Pass()]
        return ast.unparse(node_copy)
    
    return ast.unparse(node)


class CodeVisitor(ast.NodeVisitor):
    """
    Traverses the AST to find and hash functions and classes.
    """
    def __init__(self, file_name):
        self.file_name = file_name
        self.hashes = defaultdict(list)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._hash_node(node, "Function")
        self.generic_visit(node) # To find nested functions

    def visit_ClassDef(self, node: ast.ClassDef):
        self._hash_node(node, "Class")
        self.generic_visit(node) # To find nested classes/methods

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._hash_node(node, "Async Function")
        self.generic_visit(node)

    def _hash_node(self, node, node_type):
        """Helper function to normalize, hash, and store a node."""
        # Unparse the node to get a standardized code representation
        normalized_code = normalize_code_block(node)
        if not normalized_code or not normalized_code.strip():
            return

        # Create a SHA256 hash of the normalized code
        code_hash = hashlib.sha256(normalized_code.encode()).hexdigest()
        
        # Store the location of this hash
        location_info = {
            "file_name": self.file_name,
            "name": node.name,
            "line": node.lineno,
            "type": node_type,
            "code": normalized_code
        }
        self.hashes[code_hash].append(location_info)


@st.cache_data
def find_duplicates(python_files: list):
    """
    Analyzes all Python files to find duplicate code blocks.
    """
    project_hashes = defaultdict(list)
    
    for file in python_files:
        file.seek(0)
        file_name = file.name
        try:
            content = file.getvalue().decode("utf-8")
            tree = ast.parse(content, filename=file_name)
            
            visitor = CodeVisitor(file_name)
            visitor.visit(tree)
            
            # Merge the hashes from each file into the project-wide hashes
            for code_hash, locations in visitor.hashes.items():
                project_hashes[code_hash].extend(locations)
                
        except SyntaxError as e:
            st.warning(f"Could not parse file '{file_name}' (Syntax Error): {e}", icon="⚠️")
        except Exception as e:
            st.error(f"An error occurred while processing '{file_name}': {e}")

    # Return only the hashes that appeared more than once
    duplicates = {code_hash: locations for code_hash, locations in project_hashes.items() if len(locations) > 1}
    return duplicates

# --- STREAMLIT UI ---

# Access uploaded files from the session state
if "uploaded_files" not in st.session_state:
    st.session_state["uploaded_files"] = []

python_files = [f for f in st.session_state.uploaded_files if f.name.endswith('.py')]

if not python_files:
    st.warning("To find duplicate code, please upload Python files from the '📂 Project Dashboard'.")
else:
    st.info(f"Found **{len(python_files)}** Python files for analysis.")
    
    if st.button("✂️ Find Duplicate Code", use_container_width=True, type="primary"):
        with st.spinner("Comparing all files..."):
            duplicate_results = find_duplicates(python_files)
            st.session_state['duplicate_results'] = duplicate_results

if 'duplicate_results' in st.session_state:
    st.divider()
    results = st.session_state['duplicate_results']
    
    if not results:
        st.success("🎉 Congratulations! No duplicate functions or classes were found.")
        st.balloons()
    else:
        st.error(f"**{len(results)}** unique duplicate code blocks were found.", icon="🚨")
        
        # Sort results by the number of duplicates, descending
        sorted_results = sorted(results.values(), key=len, reverse=True)
        
        for i, locations in enumerate(sorted_results):
            first_item = locations[0]
            header = f"Duplicate {first_item['type']} `{first_item['name']}` (found in {len(locations)} locations)"
            
            with st.expander(header, expanded=i < 3): # Keep the first 3 results expanded by default
                # Display the code snippet
                st.code(first_item['code'], language='python')
                
                # Create a list of all locations
                st.markdown("**Locations:**")
                for loc in locations:
                    st.write(f"- `{loc['file_name']}` (Line: **{loc['line']}**)")