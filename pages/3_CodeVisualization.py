# pages/3_CodeVisualization.py
import streamlit as st
import ast
import pandas as pd
import plotly.express as px

# --- Core Analysis Logic ---

class CodeStructureVisitor(ast.NodeVisitor):
    """
    An efficient AST visitor to extract classes, functions, calls,
    and inheritance relationships in a single pass with corrected logic.
    """
    def __init__(self, filename):
        self.filename = filename
        self.structure = []
        self.call_graph_edges = set()
        self.inheritance_edges = set()
        self.current_scope = [filename]

    def _get_full_name(self, name):
        return ".".join(self.current_scope + [name])

    def visit_ClassDef(self, node: ast.ClassDef):
        class_name = node.name
        full_class_name = self._get_full_name(class_name)
        loc = (node.end_lineno - node.lineno) + 1
        parent_scope = ".".join(self.current_scope)
        self.structure.append({
            "id": full_class_name, "parent": parent_scope, "name": class_name,
            "type": "Class", "loc": loc
        })
        for base in node.bases:
            base_name = None
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
            if base_name:
                self.inheritance_edges.add((base_name, class_name))
        self.current_scope.append(class_name)
        self.generic_visit(node)
        self.current_scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        func_name = node.name
        full_func_name = self._get_full_name(func_name)
        loc = (node.end_lineno - node.lineno) + 1
        parent_scope = ".".join(self.current_scope)
        self.structure.append({
            "id": full_func_name, "parent": parent_scope, "name": func_name,
            "type": "Function", "loc": loc
        })
        self.current_scope.append(func_name)
        self.generic_visit(node)
        self.current_scope.pop()

    def visit_Call(self, node: ast.Call):
        if not self.current_scope:
            self.generic_visit(node)
            return
        caller_name = ".".join(self.current_scope)
        callee_name = None
        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee_name = node.func.attr
        if callee_name:
            self.call_graph_edges.add((caller_name, callee_name))
        self.generic_visit(node)

@st.cache_data
def analyze_code_structure(content, filename):
    """
    Analyzes python code content and returns its structure.
    This function is cached for performance.
    """
    try:
        tree = ast.parse(content)
        visitor = CodeStructureVisitor(filename)
        visitor.visit(tree)
        return {
            "structure": visitor.structure,
            "call_edges": visitor.call_graph_edges,
            "inheritance_edges": visitor.inheritance_edges
        }
    except SyntaxError as e:
        st.error(f"Cannot parse {filename}: Invalid Python syntax at line {e.lineno}. {e.msg}")
        return None

def generate_graphviz_dot(nodes, edges, graph_type='call', internal_nodes=None):
    """Generates a DOT language string for Graphviz with better styling."""
    dot_lines = [
        'digraph G {', '    rankdir=LR;', '    splines=true;', '    overlap=false;',
        '    graph [fontname="Helvetica", fontsize=10];',
        '    node [fontname="Helvetica", fontsize=10];',
        '    edge [fontname="Helvetica", fontsize=9];'
    ]
    internal_nodes = internal_nodes or set()
    node_styles = {
        'call_internal': 'shape=box, style="rounded,filled", fillcolor="#a6d8f0"',
        'call_external': 'shape=box, style="filled", fillcolor="#e0e0e0"',
        'inheritance': 'shape=ellipse, style="filled", fillcolor="#d8f0a6"',
    }
    for node_name in nodes:
        if graph_type == 'call':
            style = node_styles['call_internal'] if node_name in internal_nodes else node_styles['call_external']
        else:
            style = node_styles['inheritance']
        dot_lines.append(f'    "{node_name}" [{style}];')
    for edge in edges:
        if graph_type == 'inheritance':
            dot_lines.append(f'    "{edge[0]}" -> "{edge[1]}" [arrowhead=empty, style=bold];')
        else:
            dot_lines.append(f'    "{edge[0]}" -> "{edge[1]}";')
    dot_lines.append('}')
    return "\n".join(dot_lines)

# --- Streamlit UI ---
st.set_page_config(layout="wide")
st.title("🕸️ Advanced Code Structure Visualization")

uploaded_files = st.session_state.get("uploaded_files", [])

if not uploaded_files:
    st.info("To get started, upload Python files on the '📂 Project Dashboard' page.")
else:
    file_names = [f.name for f in uploaded_files if f.name.endswith('.py')]
    if not file_names:
        st.warning("No Python (.py) files were found for visualization.")
    else:
        selected_file_name = st.selectbox("Select a Python file to visualize", file_names)
        selected_file = next((f for f in uploaded_files if f.name == selected_file_name), None)

        if selected_file:
            try:
                content = selected_file.getvalue().decode("utf-8")
            except UnicodeDecodeError:
                st.warning("Could not decode as UTF-8. Trying 'latin-1' as a fallback.")
                content = selected_file.getvalue().decode("latin-1")

            analysis_results = analyze_code_structure(content, selected_file_name)
            
            if not analysis_results or not analysis_results["structure"]:
                st.warning("Could not find any classes or functions to visualize in this file.")
                st.stop()
            
            structure, call_edges, inheritance_edges = analysis_results.values()
            tab1, tab2, tab3 = st.tabs(["📊 Code Map (Sunburst)", "🔗 Call Graph", "🏛️ Inheritance Diagram"])

            with tab1:
                st.subheader("Interactive Code Map")
                st.info("Visualize code hierarchy. Slice size equals Lines of Code (LOC). Click to zoom.", icon="💡")
                df = pd.DataFrame(structure)
                total_loc = df['loc'].sum()
                root_node = pd.DataFrame([{"id": selected_file_name, "parent": "", "name": selected_file_name, "loc": total_loc, "type": "File"}])
                df = pd.concat([root_node, df], ignore_index=True)
                max_depth = st.slider("Set max chart depth", min_value=2, max_value=10, value=3)
                fig = px.sunburst(
                    df, ids='id', names='name', parents='parent', values='loc', color='type',
                    color_discrete_map={'File':'#1f77b4', 'Class':'#ff7f0e', 'Function':'#2ca02c'},
                    title=f"Code Structure of {selected_file_name}", hover_data={'loc': True}, maxdepth=max_depth
                )
                fig.update_layout(margin=dict(t=50, l=10, r=10, b=10))
                st.plotly_chart(fig, use_container_width=True)

            with tab2:
                st.subheader("Function Call Graph")
                st.info("Shows which functions call others. Helps understand code flow and dependencies.", icon="💡")
                if call_edges:
                    all_funcs_in_edges = set(sum(call_edges, ()))
                    internal_funcs = {item['name'] for item in structure if item['type'] == 'Function'}
                    
                    ideal_exclusions = ['print', 'len', 'range', 'isinstance', 'getattr', 'setattr', 'str', 'int', 'list', 'dict', 'set', 'tuple', 'append', 'sum', 'join']
                    
                    # ### FIX: Only use default values that actually exist in the options list. ###
                    # This prevents the app from crashing.
                    actual_defaults = [func for func in ideal_exclusions if func in all_funcs_in_edges]
                    
                    excluded_funcs = st.multiselect(
                        "Exclude common functions from graph",
                        options=sorted(list(all_funcs_in_edges)),
                        default=actual_defaults
                    )
                    
                    filtered_edges = {edge for edge in call_edges if edge[0].split('.')[-1] not in excluded_funcs and edge[1] not in excluded_funcs}
                    
                    if filtered_edges:
                        nodes_to_draw = set(sum(filtered_edges, ()))
                        dot_string = generate_graphviz_dot(nodes_to_draw, filtered_edges, graph_type='call', internal_nodes=internal_funcs)
                        st.graphviz_chart(dot_string, use_container_width=True)
                    else:
        
                        st.success("All calls were filtered out. Adjust the filter to see more.")
                    with st.expander("Show Raw Call Data"):
                        st.json({"detected_calls": list(call_edges)})
                else:
                    st.success("No direct function calls were detected between functions defined in this file.")

            with tab3:
                st.subheader("Class Inheritance Diagram")
                st.info("Shows parent-child relationships between classes (inheritance).", icon="💡")
                if inheritance_edges:
                    all_classes_in_graph = set(sum(inheritance_edges, ()))
                    dot_string = generate_graphviz_dot(all_classes_in_graph, inheritance_edges, graph_type='inheritance')
                    st.graphviz_chart(dot_string, use_container_width=True)
                    with st.expander("Show Raw Inheritance Data"):
                        st.json({"detected_inheritance": list(inheritance_edges)})
                else:
                    st.success("No class inheritance was detected in this file.")