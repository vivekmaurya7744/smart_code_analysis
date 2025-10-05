# pages/9_Comment_Tracker.py
import streamlit as st
import pandas as pd
import re
from collections import defaultdict
from datetime import datetime # <-- FIX: Added this import

st.set_page_config(layout="wide")
st.title("📝 TODO / Comment Tracker")
st.markdown("Scan your entire project for technical debt and action items hidden in comments like `TODO`, `FIXME`, `HACK`, etc.")

# --- Core Logic ---

# Define the tags we are looking for and their properties
COMMENT_TAGS = {
    "FIXME": {"priority": 1, "icon": "🔥", "description": "High-priority issue that must be fixed."},
    "TODO": {"priority": 2, "icon": "📝", "description": "A task or feature that needs to be implemented."},
    "HACK": {"priority": 3, "icon": "🛠️", "description": "A temporary or suboptimal solution."},
    "NOTE": {"priority": 4, "icon": "💡", "description": "An important note or clarification."},
    "DEPRECATED": {"priority": 3, "icon": "🗑️", "description": "Code that is obsolete and should be removed."},
}

@st.cache_data
def scan_project_for_comments(files: list):
    """
    Scans all uploaded files for comments with specific tags.
    This is a text-based scan, as comments are not part of the AST.
    """
    findings = []
    
    # Regex to capture: TAG, optional (Assignee), and the message
    # Example: # TODO(vivek): Refactor this function
    tag_pattern = re.compile(
        r'#\s*(?P<tag>TODO|FIXME|HACK|NOTE|DEPRECATED)\s*(?:\((?P<assignee>.*?)\))?:\s*(?P<message>.*)',
        re.IGNORECASE
    )

    python_files = [f for f in files if f.name.endswith('.py')]
    for file in python_files:
        file.seek(0)
        content = file.getvalue().decode("utf-8")
        for line_num, line in enumerate(content.splitlines(), 1):
            match = tag_pattern.search(line)
            if match:
                data = match.groupdict()
                findings.append({
                    "file_path": file.name,
                    "line": line_num,
                    "tag": data["tag"].upper(),
                    "assignee": data["assignee"] if data["assignee"] else "Unassigned",
                    "message": data["message"].strip()
                })
    return findings


# --- UI ---

uploaded_files = st.session_state.get("uploaded_files", [])

if not uploaded_files:
    st.warning("Please upload your project files from the 'Project Dashboard' to begin.")
else:
    if st.button("📊 Scan Project for Comment Tags", use_container_width=True, type="primary"):
        with st.spinner("Scanning all files for comment tags..."):
            comment_findings = scan_project_for_comments(uploaded_files)
            st.session_state['comment_findings'] = comment_findings
            st.session_state['scan_time'] = datetime.now().strftime("%I:%M:%S %p on %B %d, %Y")

    if 'comment_findings' in st.session_state:
        findings = st.session_state['comment_findings']
        
        st.header("Comment Tracker Dashboard")
        st.caption(f"Last scanned on: {st.session_state['scan_time']}")
        
        if not findings:
            st.success("✅ No special comment tags found. Your codebase is clean!")
            st.balloons()
        else:
            df = pd.DataFrame(findings)
            
            # --- Top-Level Metrics ---
            tag_counts = df['tag'].value_counts()
            cols = st.columns(len(COMMENT_TAGS))
            for i, (tag, props) in enumerate(COMMENT_TAGS.items()):
                count = tag_counts.get(tag, 0)
                cols[i].metric(f"{props['icon']} {tag}s", count, help=props['description'])

            st.divider()

            # --- Interactive Filtering and Display ---
            st.subheader("Explore Findings")
            
            # Create a filter for tags
            tag_options = sorted(list(df['tag'].unique()))
            selected_tags = st.multiselect(
                "Filter by tag:",
                options=tag_options,
                default=tag_options
            )
            
            filtered_df = df[df['tag'].isin(selected_tags)]

            # Tabbed view for different presentations
            tab1, tab2 = st.tabs(["Categorized View", "All Findings (Table)"])

            with tab1:
                st.markdown("Findings grouped by tag type:")
                if filtered_df.empty:
                    st.info("No comments match the current filter.")
                else:
                    # Group by the tag for the categorized view
                    grouped = filtered_df.groupby('tag')
                    # Sort groups by priority
                    sorted_tags = sorted(grouped.groups.keys(), key=lambda t: COMMENT_TAGS.get(t, {}).get('priority', 99))
                    
                    for tag in sorted_tags:
                        group_df = grouped.get_group(tag)
                        props = COMMENT_TAGS.get(tag, {})
                        with st.expander(f"{props.get('icon', '🔹')} {tag} ({len(group_df)} found)", expanded=props.get('priority', 99) <= 2):
                            for _, row in group_df.iterrows():
                                st.markdown(
                                    f"**`{row['file_path']}:{row['line']}`** - *({row['assignee']})* - {row['message']}"
                                )
                                st.code(f"#{row['tag']}({row['assignee']}): {row['message']}", language="python")

            with tab2:
                st.markdown("All findings in a searchable table:")
                st.dataframe(filtered_df, use_container_width=True, hide_index=True)