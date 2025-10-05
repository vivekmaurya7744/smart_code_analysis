# pages/5_ReportGenerator.py
import streamlit as st
import pandas as pd
from datetime import datetime
import importlib

# FPDF is required for PDF export.
try:
    from fpdf import FPDF
except ImportError:
    st.error("The 'fpdf2' library is required for PDF exports. Please install it: `pip install fpdf2`")
    st.stop()

# --- Dynamically import analysis functions from other pages ---
try:
    security_module = importlib.import_module("pages.4_SecurityCenter")
    run_security_scan = security_module.run_security_scan
    
    linter_module = importlib.import_module("pages.2_FileExplorer")
    analyze_code_quality = linter_module.analyze_code
except ImportError as e:
    st.error(f"Could not import a required page module. Please ensure all page files exist. Error: {e}")
    st.stop()

# --- Combined Report Generation Logic ---

@st.cache_data
def generate_full_report_data(files: list):
    """
    Runs both security and code quality scans on all files and aggregates the data.
    """
    project_report = {
        "summary": {},
        "all_security_findings": [],
        "all_linter_issues": [],
        "all_functions": [],
        "file_summaries": []
    }
    
    python_files = [f for f in files if f.name.endswith('.py')]

    for file in python_files:
        file.seek(0)
        try:
            content = file.getvalue().decode("utf-8")
        except UnicodeDecodeError:
            file.seek(0)
            content = file.getvalue().decode("latin-1")
        
        # 1. Run Security Scan
        security_findings = run_security_scan(content)
        for finding in security_findings:
            finding['file_path'] = file.name
            project_report["all_security_findings"].append(finding)
            
        # 2. Run Code Quality & Linter Scan
        quality_analysis = analyze_code_quality(content)
        if quality_analysis:
            for issue in quality_analysis.get("issues", []):
                issue['file_path'] = file.name
                project_report["all_linter_issues"].append(issue)
            
            for func in quality_analysis.get("functions", []):
                func['file_path'] = file.name
                project_report["all_functions"].append(func)
            
            project_report["file_summaries"].append({
                "file_path": file.name,
                "quality_score": quality_analysis.get("quality_score", 0),
                "maintainability_index": quality_analysis.get("maintainability_index", 0),
                "total_lines": quality_analysis.get("total_lines", 0)
            })

    # --- Create Project-Level Summary from aggregated data ---
    crit_count = sum(1 for f in project_report["all_security_findings"] if f['severity'] == 'Critical')
    high_count = sum(1 for f in project_report["all_security_findings"] if f['severity'] == 'High')
    security_score = max(0, 100 - (crit_count * 20) - (high_count * 10))

    if project_report["file_summaries"]:
        avg_quality_score = sum(s['quality_score'] for s in project_report["file_summaries"]) / len(project_report["file_summaries"])
        avg_mi = sum(s['maintainability_index'] for s in project_report["file_summaries"] if s['maintainability_index'] > 0) / len(project_report["file_summaries"])
        total_loc = sum(s['total_lines'] for s in project_report["file_summaries"])
    else:
        avg_quality_score = 100
        avg_mi = 100
        total_loc = 0

    project_report["summary"] = {
        "file_count": len(python_files),
        "total_loc": total_loc,
        "security_score": int(security_score),
        "quality_score": int(avg_quality_score),
        "overall_score": int((security_score * 0.6) + (avg_quality_score * 0.4)),
        "critical_vulns": crit_count,
        "high_vulns": high_count,
        "total_lint_issues": len(project_report["all_linter_issues"]),
        "avg_maintainability": avg_mi
    }
    return project_report

# --- PDF Export Class ---
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Comprehensive Code Analysis Report', 0, 1, 'C')
        self.set_font('Arial', '', 8)
        self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(5)
    
    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, body, ln=1)
        self.ln()

    def add_finding(self, finding_dict):
        title = finding_dict.get('title', finding_dict.get('message', 'N/A'))
        line = finding_dict.get('line_number', finding_dict.get('line', 'N/A'))
        
        self.set_font('Arial', 'B', 10)
        # FIX: Added ln=1 to all multi_cell calls to ensure the cursor moves to the next line.
        self.multi_cell(0, 5, f"{finding_dict.get('severity', 'N/A')}: {title} (File: {finding_dict.get('file_path', 'N/A')}, Line: {line})", ln=1)
        
        self.set_font('Arial', '', 9)
        if finding_dict.get('remediation'):
             self.multi_cell(0, 5, f"Remediation: {finding_dict.get('remediation')}", ln=1)
        
        if finding_dict.get('code'):
             self.set_font('Courier', '', 9)
             self.multi_cell(0, 5, f"Code: {finding_dict.get('code')}", ln=1)
        
        self.ln(4) # Add some space after the entry

def generate_pdf(report_data):
    pdf = PDFReport()
    pdf.add_page()
    
    summary = report_data["summary"]
    pdf.chapter_title("1. Executive Summary")
    summary_text = (f"Overall Project Score: {summary['overall_score']}/100\n"
                    f"Security Score: {summary['security_score']}/100\n"
                    f"Code Quality Score: {summary['quality_score']}/100\n\n"
                    f"Files Analyzed: {summary['file_count']}\n"
                    f"Total Lines of Code: {summary['total_loc']}\n"
                    f"Critical Vulnerabilities: {summary['critical_vulns']}\n"
                    f"High Severity Vulnerabilities: {summary['high_vulns']}\n"
                    f"Total Linter Issues: {summary['total_lint_issues']}")
    pdf.chapter_body(summary_text)

    if report_data["all_security_findings"]:
        pdf.add_page()
        pdf.chapter_title("2. Detailed Security Findings")
        for finding in sorted(report_data["all_security_findings"], key=lambda x: x['severity']):
            pdf.add_finding(finding)
    
    if report_data["all_linter_issues"]:
        pdf.add_page()
        pdf.chapter_title("3. Detailed Code Quality Issues")
        for issue in sorted(report_data["all_linter_issues"], key=lambda x: x['severity']):
            pdf.add_finding(issue)

    return bytes(pdf.output(dest='S'))

# --- Streamlit UI ---
st.set_page_config(layout="wide")
st.title("📑 Comprehensive Project Report")
st.markdown("Consolidate all security, quality, and complexity analyses into one report.")

uploaded_files = st.session_state.get("uploaded_files", [])

if not uploaded_files:
    st.info("Upload your project files in the '📂 Project Dashboard' to generate a report.")
else:
    if st.button("🚀 Generate Full Project Report", use_container_width=True, type="primary"):
        with st.spinner("Performing deep analysis on all files... This may take a moment."):
            report_data = generate_full_report_data(uploaded_files)
            st.session_state['report_data'] = report_data
    
    if 'report_data' in st.session_state:
        report = st.session_state['report_data']
        summary = report['summary']
        
        st.header("Project Analysis Dashboard")
        st.download_button(
            label="📥 Download Full PDF Report",
            data=generate_pdf(report),
            file_name=f"FullCodeReport_{datetime.now().strftime('%Y%m%d')}.pdf",
            mime="application/pdf",
            use_container_width=True
        )
        st.divider()
        
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Summary", "🛡️ Security", "📈 Code Quality", "⚙️ Complexity"])

        with tab1:
            st.subheader("Overall Project Health")
            st.progress(summary['overall_score'], text=f"Overall Score: {summary['overall_score']}/100")
            
            c1, c2, c3 = st.columns(3)
            c1.metric("🛡️ Security Score", f"{summary['security_score']}/100")
            c2.metric("📈 Code Quality Score", f"{summary['quality_score']}/100")
            c3.metric("🛠️ Maintainability", f"{summary['avg_maintainability']:.1f}/100")
            
            st.divider()
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("🚨 Critical Vulns", summary['critical_vulns'])
            c2.metric("⚠️ High Vulns", summary['high_vulns'])
            c3.metric("📝 Linter Issues", summary['total_lint_issues'])
            c4.metric("📄 Python Files", summary['file_count'])
        
        with tab2:
            st.subheader("Security Vulnerability Breakdown")
            security_df = pd.DataFrame(report["all_security_findings"])
            if not security_df.empty:
                st.dataframe(security_df[['severity', 'title', 'file_path', 'line_number', 'code', 'remediation']], use_container_width=True)
            else:
                st.success("No security findings to report.")

        with tab3:
            st.subheader("Code Quality & Linter Issues")
            linter_df = pd.DataFrame(report["all_linter_issues"])
            if not linter_df.empty:
                st.dataframe(linter_df[['severity', 'message', 'file_path', 'line', 'code']], use_container_width=True)
            else:
                st.success("No major code quality issues to report.")

        with tab4:
            st.subheader("Project-Wide Function Complexity")
            func_df = pd.DataFrame(report["all_functions"])
            if not func_df.empty:
                st.scatter_chart(func_df, x="lines_of_code", y="complexity", color="file_path", size="complexity")
                with st.expander("View Full Function Data"):
                    st.dataframe(func_df[['name', 'file_path', 'complexity', 'lines_of_code', 'type_hint_coverage']], use_container_width=True)
            else:
                st.info("No functions found to analyze.")