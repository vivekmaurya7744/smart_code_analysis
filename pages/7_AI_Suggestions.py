# pages/7_AI_Suggestions.py
import streamlit as st
import google.generativeai as genai
import time

st.set_page_config(layout="wide", page_title="AI Code Assistant")

# --- Page Title and Introduction ---
st.title("🤖 AI Suggestions & Refactoring")
st.markdown("Use the power of Google's Gemini models to review, refactor, and improve your code.")

# --- API Key Configuration ---
# The API key is now hardcoded directly into the script.
# NOTE: For public deployment, using st.secrets is the recommended and more secure method.
GEMINI_API_KEY = "AIzaSyDKm5J7S14dvuqvUdd2F6yGzsDUufX5rIQ"

# Configure the generative AI model
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        # --- THIS IS THE UPDATED LINE ---
        model = genai.GenerativeModel('gemini-2.0-flash-001')
        st.sidebar.success("AI model initialized successfully!", icon="✅")
    except Exception as e:
        st.error(f"Error configuring the API. Please check the hardcoded key. Details: {e}")
        st.stop()
else:
    # This will now only trigger if the hardcoded key above is deleted.
    st.error("The Gemini API key is missing from the code. Please add it.")
    st.stop()


# --- Caching the AI Call ---
@st.cache_data(show_spinner=False)
def get_ai_response(prompt: str):
    """Sends a prompt to the Gemini API and returns the response."""
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        # Handle potential API errors gracefully
        return f"An error occurred with the API call: {e}"

# --- Main UI ---
uploaded_files = st.session_state.get("uploaded_files", [])
python_files = [f for f in uploaded_files if f.name.endswith('.py')]

if not python_files:
    st.warning("Please upload some Python files from the 'Project Dashboard' first.")
    st.stop()

# File selection and code display
col1, col2 = st.columns([1, 2])
with col1:
    st.subheader("Select Code")
    file_options = [f.name for f in python_files]
    selected_file = st.selectbox("Choose a file to analyze:", file_options)
    
    if selected_file:
        file_content = next((f.getvalue().decode("utf-8") for f in python_files if f.name == selected_file), "")
        st.session_state['current_code'] = file_content

with col2:
    st.subheader("Your Code")
    code_to_analyze = st.text_area("Editable Code", value=st.session_state.get('current_code', ''), height=400, key="code_input")

# --- AI Action Buttons ---
st.subheader("✨ Choose an AI Action")
action_col1, action_col2, action_col3, action_col4 = st.columns(4)

if action_col1.button("🕵️ Code Review", use_container_width=True, help="Get a detailed analysis of potential bugs, style issues, and best practices."):
    if code_to_analyze:
        prompt = f"""
        Act as an expert Python code reviewer. Analyze the following code for potential bugs, performance issues, style violations (PEP 8), and adherence to best practices. Provide a clear, concise, and actionable list of suggestions for improvement. Structure your feedback with categories (e.g., Bugs, Performance, Style).

        Here is the code:
        ```python
        {code_to_analyze}
        ```
        """
        st.session_state['last_action'] = ('review', prompt)

if action_col2.button("🧹 Refactor for Readability", use_container_width=True, help="Let the AI rewrite the code to make it cleaner and more maintainable."):
    if code_to_analyze:
        prompt = f"""
        Act as an expert Python programmer. Your task is to refactor the following code to improve its readability and maintainability. Use clear variable names, break down complex functions into smaller, logical units, and simplify the logic where possible. 
        
        IMPORTANT: Provide ONLY the complete, refactored Python code in a single markdown code block. Do not add any explanations or comments outside of the code block itself.

        Here is the code to refactor:
        ```python
        {code_to_analyze}
        ```
        """
        st.session_state['last_action'] = ('refactor', prompt)

if action_col3.button("✍️ Add Docstrings & Hints", use_container_width=True, help="Automatically add Google-style docstrings and type hints to your code."):
    if code_to_analyze:
        prompt = f"""
        Act as an expert Python developer. Your task is to add comprehensive Google-style docstrings and type hints to the following Python code. Ensure all functions, classes, and methods are fully documented.
        
        IMPORTANT: Provide ONLY the complete, updated Python code in a single markdown code block. Do not add explanations.

        Here is the code to update:
        ```python
        {code_to_analyze}
        ```
        """
        st.session_state['last_action'] = ('docs', prompt)

if action_col4.button("🐛 Find Potential Bugs", use_container_width=True, help="A focused check for logical errors and unhandled edge cases."):
    if code_to_analyze:
        prompt = f"""
        Act as a meticulous quality assurance engineer. Scrutinize the following Python code for potential bugs, logical errors, and unhandled edge cases. Do not comment on style. Focus only on things that could cause the program to crash or behave unexpectedly. Provide a list of potential issues and explain why each is a problem.

        Here is the code:
        ```python
        {code_to_analyze}
        ```
        """
        st.session_state['last_action'] = ('bugs', prompt)

# --- Display AI Response ---
if 'last_action' in st.session_state:
    action_type, prompt = st.session_state['last_action']
    
    st.subheader("💡 Gemini's Response")
    with st.spinner("Gemini is thinking... This might take a few moments..."):
        response = get_ai_response(prompt)

        # Clean up the response for code-only outputs
        if action_type in ['refactor', 'docs']:
            # This regex finds a python code block and extracts its content
            import re
            match = re.search(r'```python\n(.*?)```', response, re.DOTALL)
            if match:
                clean_response = match.group(1)
            else:
                # Fallback if the regex doesn't find a match
                clean_response = response.strip('`').strip()
            st.code(clean_response, language="python")
        else:
            # For reviews, display as markdown
            st.markdown(response)

st.sidebar.markdown("---")
st.sidebar.info("**Note:** AI suggestions should be reviewed carefully by a human before implementation. API calls are cached for performance.")