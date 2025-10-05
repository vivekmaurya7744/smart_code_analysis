# Home.py
import streamlit as st

# -------------------- Page Config --------------------
st.set_page_config(
    page_title="Smart Code Review Assistant",
    page_icon="🤖",
    layout="wide"
)

# -------------------- Homepage --------------------
st.title("🤖 Welcome to the Smart Code Review Assistant!")

st.markdown("""
This is an advanced tool designed to help you write **cleaner, more efficient, and more secure Python code**.  
It leverages *static analysis*, *complexity metrics*, *security scanning*, and *AI* to provide comprehensive feedback on your projects.
""")

st.header("🚀 How to Get Started")

st.markdown("""
1. Navigate to the **📊 Project Dashboard** page from the sidebar.  
2. Upload your `.py` files.  
3. Once analysis is complete, explore the other pages in the sidebar for detailed insights:
   - **📄 File Explorer** → Deep-dive into individual files.  
   - **🕸️ Code Visualization** → See project-wide complexity maps.  
   - **🛡️ Security Center** → Check for code and dependency vulnerabilities.  
   - **📋 Report Generator** → Download a complete analysis report.  
""")

st.info("👈 Select a page from the sidebar to begin.")
