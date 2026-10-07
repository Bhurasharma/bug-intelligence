"""
🔍 BugIntel — AI-Powered Software Quality & Bug Intelligence Platform
Main Streamlit Application
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import json
import time
import textwrap
from datetime import datetime

from analyzer.static_analyzer import StaticAnalyzer, Severity, IssueCategory
from analyzer.test_generator import TestGenerator
from analyzer.ai_engine import get_ai_analysis, get_fix_suggestion, chat_with_code
from analyzer.dependency_scanner import DependencyScanner, DependencyAuditResult, VulnerabilitySeverity
from analyzer.quality_gate import QualityGate, AuditReportGenerator, QualityGateResult
from analyzer.repository_scanner import RepositoryScanner, RepositoryAuditResult
DEFAULT_SAMPLE_REQUIREMENTS = """# Production Requirements (Legacy API Service)
# Vulnerable to OWASP 2025 A06 Supply-Chain risks
requests==2.25.1
urllib3==1.26.15
django==3.2.20
pyyaml==5.3.1
flask==2.0.1
pillow==9.5.0
jinja2==2.11.3
cryptography==3.4.8
numpy==1.21.5
pydantic
gunicorn
"""

try:
    from utils.helpers import (
        SEVERITY_COLORS, SEVERITY_EMOJIS, CATEGORY_ICONS,
        risk_color, risk_label, complexity_color, SAMPLE_FILES,
        SAMPLE_REQUIREMENTS, SAMPLE_MULTI_PROJECT
    )
except ImportError:
    try:
        from utils import (
            SEVERITY_COLORS, SEVERITY_EMOJIS, CATEGORY_ICONS,
            risk_color, risk_label, complexity_color, SAMPLE_FILES,
            SAMPLE_REQUIREMENTS, SAMPLE_MULTI_PROJECT
        )
    except ImportError:
        from utils.helpers import (
            SEVERITY_COLORS, SEVERITY_EMOJIS, CATEGORY_ICONS,
            risk_color, risk_label, complexity_color, SAMPLE_FILES
        )
        SAMPLE_REQUIREMENTS = DEFAULT_SAMPLE_REQUIREMENTS
        sample_vals = list(SAMPLE_FILES.values())
        SAMPLE_MULTI_PROJECT = {
            "services/order_service.py": sample_vals[0],
            "auth/auth_manager.py": sample_vals[1] if len(sample_vals) > 1 else sample_vals[0],
            "etl/pipeline_worker.py": sample_vals[2] if len(sample_vals) > 2 else sample_vals[0],
        }

import difflib

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PAGE CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.set_page_config(
    page_title="BugIntel — AI Bug Intelligence",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CUSTOM CSS — Premium Dark Theme
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<style>
    /* ── Import Google Fonts ──────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* ── Root variables ───────────────────────── */
    :root {
        --bg-primary: #0a0e1a;
        --bg-secondary: #111827;
        --bg-card: #1a1f35;
        --bg-card-hover: #222845;
        --border-color: #2a3050;
        --text-primary: #e8eaf6;
        --text-secondary: #9ea4c1;
        --accent-blue: #60a5fa;
        --accent-purple: #a78bfa;
        --accent-cyan: #22d3ee;
        --accent-green: #34d399;
        --accent-red: #f87171;
        --accent-orange: #fb923c;
        --accent-yellow: #fbbf24;
        --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        --gradient-accent: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
        --gradient-danger: linear-gradient(135deg, #f87171 0%, #fb923c 100%);
        --shadow-glow: 0 0 30px rgba(96, 165, 250, 0.15);
        --shadow-card: 0 4px 24px rgba(0, 0, 0, 0.3);
    }

    /* ── Global Styles ────────────────────────── */
    .stApp {
        background: var(--bg-primary) !important;
        font-family: 'Inter', sans-serif !important;
    }

    .main .block-container {
        padding: 1rem 2rem 3rem 2rem;
        max-width: 1400px;
    }

    /* ── Sidebar ──────────────────────────────── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f1629 0%, #111827 100%) !important;
        border-right: 1px solid var(--border-color);
    }

    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown li {
        color: var(--text-secondary) !important;
        font-size: 0.9rem;
    }

    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 {
        color: var(--text-primary) !important;
    }

    /* ── Headers ──────────────────────────────── */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif !important;
        color: var(--text-primary) !important;
    }

    /* ── Hero Section ─────────────────────────── */
    .hero-banner {
        background: linear-gradient(135deg, #1a1145 0%, #0d1b3e 40%, #0a2540 100%);
        border: 1px solid rgba(96, 165, 250, 0.15);
        border-radius: 20px;
        padding: 2.5rem 3rem;
        margin-bottom: 2rem;
        position: relative;
        overflow: hidden;
    }

    .hero-banner::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle at 30% 50%, rgba(96, 165, 250, 0.08) 0%, transparent 50%),
                    radial-gradient(circle at 70% 50%, rgba(167, 139, 250, 0.06) 0%, transparent 50%);
        animation: pulse 8s ease-in-out infinite;
    }

    @keyframes pulse {
        0%, 100% { transform: scale(1); opacity: 0.5; }
        50% { transform: scale(1.05); opacity: 1; }
    }

    .hero-title {
        font-size: 2.4rem;
        font-weight: 800;
        background: linear-gradient(135deg, #60a5fa, #a78bfa, #22d3ee);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
        position: relative;
        z-index: 1;
    }

    .hero-subtitle {
        font-size: 1.1rem;
        color: var(--text-secondary);
        font-weight: 400;
        position: relative;
        z-index: 1;
    }

    /* ── Metric Cards ─────────────────────────── */
    .metric-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 1.5rem;
        text-align: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }

    .metric-card:hover {
        transform: translateY(-4px);
        border-color: rgba(96, 165, 250, 0.4);
        box-shadow: var(--shadow-glow);
    }

    .metric-card::after {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        border-radius: 16px 16px 0 0;
    }

    .metric-card.blue::after { background: var(--gradient-accent); }
    .metric-card.red::after { background: var(--gradient-danger); }
    .metric-card.green::after { background: linear-gradient(135deg, #34d399, #22d3ee); }
    .metric-card.purple::after { background: var(--gradient-primary); }
    .metric-card.orange::after { background: linear-gradient(135deg, #fb923c, #fbbf24); }

    .metric-value {
        font-size: 2.8rem;
        font-weight: 800;
        margin: 0.3rem 0;
        line-height: 1;
    }

    .metric-label {
        font-size: 0.85rem;
        color: var(--text-secondary);
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .metric-icon {
        font-size: 1.5rem;
        margin-bottom: 0.3rem;
    }

    /* ── Issue Cards ──────────────────────────── */
    .issue-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 14px;
        padding: 1.3rem 1.5rem;
        margin-bottom: 0.8rem;
        transition: all 0.3s ease;
        border-left: 4px solid transparent;
    }

    .issue-card:hover {
        background: var(--bg-card-hover);
        transform: translateX(4px);
    }

    .issue-card.critical { border-left-color: #ff1744; }
    .issue-card.high { border-left-color: #ff5722; }
    .issue-card.medium { border-left-color: #ff9800; }
    .issue-card.low { border-left-color: #ffc107; }
    .issue-card.info { border-left-color: #00bcd4; }

    .issue-title {
        font-size: 1.05rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 0.4rem;
    }

    .issue-desc {
        font-size: 0.9rem;
        color: var(--text-secondary);
        line-height: 1.5;
    }

    .issue-meta {
        display: flex;
        gap: 1rem;
        margin-top: 0.6rem;
        flex-wrap: wrap;
    }

    .issue-badge {
        display: inline-flex;
        align-items: center;
        padding: 0.2rem 0.7rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        gap: 0.3rem;
    }

    .badge-critical { background: rgba(255, 23, 68, 0.15); color: #ff6b8a; }
    .badge-high { background: rgba(255, 87, 34, 0.15); color: #ff8a65; }
    .badge-medium { background: rgba(255, 152, 0, 0.15); color: #ffb74d; }
    .badge-low { background: rgba(255, 193, 7, 0.15); color: #ffe082; }
    .badge-info { background: rgba(0, 188, 212, 0.15); color: #4dd0e1; }

    .badge-category {
        background: rgba(96, 165, 250, 0.12);
        color: var(--accent-blue);
    }

    .badge-confidence {
        background: rgba(167, 139, 250, 0.12);
        color: var(--accent-purple);
    }

    .badge-line {
        background: rgba(34, 211, 153, 0.12);
        color: var(--accent-green);
    }

    /* ── Section Headers ──────────────────────── */
    .section-header {
        display: flex;
        align-items: center;
        gap: 0.8rem;
        margin: 2rem 0 1rem 0;
        padding-bottom: 0.8rem;
        border-bottom: 1px solid var(--border-color);
    }

    .section-header h2 {
        font-size: 1.4rem;
        font-weight: 700;
        margin: 0;
    }

    /* ── Code Blocks ──────────────────────────── */
    .code-block {
        background: #0d1117;
        border: 1px solid #21262d;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        line-height: 1.6;
        overflow-x: auto;
        color: #c9d1d9;
    }

    /* ── Risk Gauge ───────────────────────────── */
    .risk-gauge {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 16px;
        padding: 1.5rem;
        text-align: center;
    }

    /* ── Tabs ─────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: var(--bg-secondary);
        border-radius: 12px;
        padding: 0.3rem;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 10px;
        padding: 0.6rem 1.2rem;
        font-weight: 500;
        color: var(--text-secondary) !important;
    }

    .stTabs [aria-selected="true"] {
        background: var(--bg-card) !important;
        color: var(--accent-blue) !important;
    }

    /* ── Expanders ────────────────────────────── */
    .streamlit-expanderHeader {
        background: var(--bg-card) !important;
        border-radius: 12px !important;
        border: 1px solid var(--border-color) !important;
        font-weight: 600 !important;
    }

    /* ── Text areas and inputs ────────────────── */
    .stTextArea textarea, .stTextInput input {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 10px !important;
        color: var(--text-primary) !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: var(--accent-blue) !important;
        box-shadow: 0 0 0 2px rgba(96, 165, 250, 0.2) !important;
    }

    /* ── Buttons ──────────────────────────────── */
    .stButton > button {
        background: var(--gradient-accent) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        padding: 0.5rem 1.5rem !important;
        transition: all 0.3s ease !important;
        font-family: 'Inter', sans-serif !important;
    }

    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(96, 165, 250, 0.3) !important;
    }

    /* ── Download buttons ─────────────────────── */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #34d399, #22d3ee) !important;
        color: #0a0e1a !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
    }

    /* ── File uploader ────────────────────────── */
    .stFileUploader {
        border: 2px dashed var(--border-color) !important;
        border-radius: 14px !important;
        background: var(--bg-card) !important;
    }

    [data-testid="stFileUploader"] section {
        padding: 1.5rem !important;
    }

    /* ── Select box ───────────────────────────── */
    .stSelectbox > div > div {
        background: var(--bg-card) !important;
        border-color: var(--border-color) !important;
        border-radius: 10px !important;
    }

    /* ── Info/Warning boxes ────────────────────── */
    .ai-insight {
        background: linear-gradient(135deg, rgba(96, 165, 250, 0.08), rgba(167, 139, 250, 0.08));
        border: 1px solid rgba(96, 165, 250, 0.2);
        border-radius: 14px;
        padding: 1.2rem 1.5rem;
        margin: 1rem 0;
    }

    .ai-insight-title {
        font-size: 1rem;
        font-weight: 700;
        color: var(--accent-blue);
        margin-bottom: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .ai-insight-body {
        font-size: 0.92rem;
        color: var(--text-secondary);
        line-height: 1.6;
    }

    /* ── Divider ──────────────────────────────── */
    hr {
        border: none;
        border-top: 1px solid var(--border-color);
        margin: 1.5rem 0;
    }

    /* ── Scrollbar ────────────────────────────── */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: var(--bg-primary);
    }
    ::-webkit-scrollbar-thumb {
        background: var(--border-color);
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #3a4070;
    }

    /* ── Animation ────────────────────────────── */
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .animate-in {
        animation: fadeInUp 0.6s ease-out forwards;
    }

    /* ── Footer ───────────────────────────────── */
    .footer {
        text-align: center;
        padding: 2rem 0 1rem 0;
        color: var(--text-secondary);
        font-size: 0.85rem;
        border-top: 1px solid var(--border-color);
        margin-top: 3rem;
    }

    .footer a {
        color: var(--accent-blue);
        text-decoration: none;
    }
</style>
""", unsafe_allow_html=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SESSION STATE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if 'analysis_result' not in st.session_state:
    st.session_state.analysis_result = None
if 'source_code' not in st.session_state:
    st.session_state.source_code = ""
if 'ai_analysis' not in st.session_state:
    st.session_state.ai_analysis = None
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'generated_tests' not in st.session_state:
    st.session_state.generated_tests = None
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'repo_audit' not in st.session_state:
    st.session_state.repo_audit = None
if 'dep_audit' not in st.session_state:
    st.session_state.dep_audit = None
if 'sandbox_code' not in st.session_state:
    st.session_state.sandbox_code = ""
if 'sandbox_result' not in st.session_state:
    st.session_state.sandbox_result = None
if 'quality_gate_result' not in st.session_state:
    st.session_state.quality_gate_result = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SIDEBAR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1rem 0;">
        <div style="font-size: 2.5rem; margin-bottom: 0.3rem;">🔍</div>
        <div style="font-size: 1.5rem; font-weight: 800; background: linear-gradient(135deg, #60a5fa, #a78bfa); 
             -webkit-background-clip: text; -webkit-text-fill-color: transparent;">BugIntel</div>
        <div style="font-size: 0.8rem; color: #9ea4c1; margin-top: 0.2rem;">AI Bug Intelligence</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Platform Mode Switcher
    st.markdown("#### 🧭 Platform Workspace")
    platform_mode = st.radio(
        "Choose workspace:",
        [
            "🎯 Single File Code Inspector",
            "📁 Multi-File Repository Scanner",
            "📦 OWASP Supply-Chain & Dependencies"
        ],
        label_visibility="collapsed"
    )
    st.markdown("---")

    # API Key (Global)
    st.markdown("#### 🔑 AI Configuration")
    api_key = st.text_input(
        "Gemini API Key",
        type="password",
        placeholder="Enter your Google Gemini API key...",
        help="Required for AI-powered analysis, fix suggestions, and chat. Get your key at https://aistudio.google.com/apikey"
    )
    st.markdown("---")

    severity_filter = ["Critical", "High", "Medium", "Low", "Info"]
    category_filter = ["Bug", "Security", "Reliability", "Code Smell", "Performance", "Maintainability"]
    min_confidence = 0.5

    if platform_mode == "🎯 Single File Code Inspector":
        # Input Method
        st.markdown("#### 📂 Code Input")
        input_method = st.radio(
            "Choose input method:",
            ["📝 Paste Code", "📁 Upload File", "🧪 Sample Projects"],
            label_visibility="collapsed"
        )
        st.markdown("---")

        # Analysis Settings
        st.markdown("#### ⚙️ Analysis Settings")
        severity_filter = st.multiselect(
            "Show Severity Levels",
            ["Critical", "High", "Medium", "Low", "Info"],
            default=["Critical", "High", "Medium", "Low"],
        )
        category_filter = st.multiselect(
            "Show Categories",
            ["Bug", "Security", "Reliability", "Code Smell", "Performance", "Maintainability"],
            default=["Bug", "Security", "Reliability", "Code Smell", "Performance", "Maintainability"],
        )
        min_confidence = st.slider("Minimum Confidence", 0.0, 1.0, 0.5, 0.05)
        strict_gate = st.checkbox("Strict Quality Gate", value=False, help="Requires 0 High defects and risk score <= 5.0")
        st.session_state.strict_gate = strict_gate

    elif platform_mode == "📁 Multi-File Repository Scanner":
        st.markdown("#### 📂 Repository Source")
        repo_input_method = st.radio(
            "Choose repository input:",
            ["📦 Upload ZIP Archive", "📂 Upload Multiple .py Files", "🧪 Load Sample Microservice"],
            label_visibility="collapsed"
        )

    elif platform_mode == "📦 OWASP Supply-Chain & Dependencies":
        st.markdown("#### 📦 Dependency Input")
        dep_input_method = st.radio(
            "Choose dependency input:",
            ["📝 Paste requirements.txt", "📁 Upload requirements.txt", "🧪 Sample Legacy Stack"],
            label_visibility="collapsed"
        )

    st.markdown("---")
    st.markdown("""
    <div style="text-align:center; font-size: 0.78rem; color: #6b7280; padding: 0.5rem;">
        Built with ❤️ using Python<br/>
        AST Analysis • OWASP 2025 • Google Gemini
    </div>
    """, unsafe_allow_html=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WORKSPACE 1: SINGLE FILE CODE INSPECTOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if platform_mode == "🎯 Single File Code Inspector":
    st.markdown("""
    <div class="hero-banner">
        <div class="hero-title">🔍 BugIntel — Code Inspector & Quality Gate</div>
        <div class="hero-subtitle">
            Analyse source code • Detect 30+ defect patterns • Quality Gate • Generate tests • Interactive sandbox
        </div>
    </div>
    """, unsafe_allow_html=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CODE INPUT SECTION
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    source_code = ""
    file_name = "input.py"

    if input_method == "📝 Paste Code":
        st.markdown('<div class="section-header"><h2>📝 Paste Your Python Code</h2></div>', unsafe_allow_html=True)
        source_code = st.text_area(
            "Paste Python code here",
            height=300,
            placeholder="# Paste your Python code here...\ndef my_function():\n    pass",
            label_visibility="collapsed"
        )

    elif input_method == "📁 Upload File":
        st.markdown('<div class="section-header"><h2>📁 Upload Python File</h2></div>', unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Upload a Python (.py) file",
            type=["py"],
            help="Upload any Python file for analysis",
            label_visibility="collapsed"
        )
        if uploaded_file is not None:
            source_code = uploaded_file.read().decode("utf-8")
            file_name = uploaded_file.name
            st.success(f"✅ Loaded `{file_name}` — {len(source_code.split(chr(10)))} lines")

    elif input_method == "🧪 Sample Projects":
        st.markdown('<div class="section-header"><h2>🧪 Sample Buggy Projects</h2></div>', unsafe_allow_html=True)
        selected_sample = st.selectbox(
            "Choose a sample project to analyze:",
            list(SAMPLE_FILES.keys()),
            label_visibility="collapsed"
        )
        source_code = SAMPLE_FILES[selected_sample]
        file_name = selected_sample.split("(")[1].rstrip(")") if "(" in selected_sample else "sample.py"
        st.markdown(f"""
        <div class="ai-insight">
            <div class="ai-insight-title">🧪 Sample Project Loaded</div>
            <div class="ai-insight-body">
                This sample contains intentional bugs, security vulnerabilities, and code smells for demonstration.
                Click <b>🚀 Analyze Code</b> to see the full analysis.
            </div>
        </div>
        """, unsafe_allow_html=True)


    # Show code preview if we have code
    if source_code:
        with st.expander("👁️ Preview Code", expanded=False):
            st.code(source_code, language="python", line_numbers=True)


    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ANALYZE BUTTON
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])

    with col_btn1:
        analyze_clicked = st.button("🚀 Analyze Code", use_container_width=True, disabled=not source_code)

    with col_btn2:
        ai_analyze = st.button("🤖 AI Deep Analysis", use_container_width=True,
                               disabled=not (source_code and api_key))

    with col_btn3:
        gen_tests = st.button("🧪 Generate Tests", use_container_width=True, disabled=not source_code)


    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # RUN ANALYSIS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if analyze_clicked and source_code:
        with st.spinner("🔍 Analyzing code for defects, vulnerabilities, and code smells..."):
            analyzer = StaticAnalyzer()
            result = analyzer.analyze(source_code, file_name)
            st.session_state.analysis_result = result
            st.session_state.source_code = source_code
            st.session_state.analysis_history.append({
                'file': file_name,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'issues': len(result.issues),
                'risk': result.risk_score,
            })
            time.sleep(0.3)  # Small delay for visual effect

    if ai_analyze and source_code and api_key:
        with st.spinner("🤖 Running AI-powered deep analysis..."):
            analyzer = StaticAnalyzer()
            result = analyzer.analyze(source_code, file_name)
            st.session_state.analysis_result = result
            st.session_state.source_code = source_code
            ai_result = get_ai_analysis(source_code, result.issues, api_key)
            st.session_state.ai_analysis = ai_result

    if gen_tests and source_code:
        with st.spinner("🧪 Generating test cases..."):
            generator = TestGenerator()
            tests = generator.generate_tests(source_code, file_name)
            st.session_state.generated_tests = tests
            # Also run analysis if not done
            if not st.session_state.analysis_result:
                analyzer = StaticAnalyzer()
                result = analyzer.analyze(source_code, file_name)
                st.session_state.analysis_result = result
                st.session_state.source_code = source_code


    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # RESULTS DASHBOARD
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    result = st.session_state.analysis_result

    if result:
        # Filter issues
        filtered_issues = [
            i for i in result.issues
            if i.severity.value in severity_filter
            and i.category.value in category_filter
            and i.confidence >= min_confidence
        ]

        # ── Overview Metrics ─────────────────────────────────
        st.markdown('<div class="section-header"><h2>📊 Analysis Overview</h2></div>', unsafe_allow_html=True)

        severity_counts = {}
        for sev in Severity:
            severity_counts[sev.value] = len([i for i in filtered_issues if i.severity == sev])

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.markdown(f"""
            <div class="metric-card red">
                <div class="metric-icon">🎯</div>
                <div class="metric-value" style="color: {risk_color(result.risk_score)};">{result.risk_score}</div>
                <div class="metric-label">{risk_label(result.risk_score)}</div>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown(f"""
            <div class="metric-card blue">
                <div class="metric-icon">🐛</div>
                <div class="metric-value" style="color: var(--accent-blue);">{len(filtered_issues)}</div>
                <div class="metric-label">Total Issues</div>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            st.markdown(f"""
            <div class="metric-card orange">
                <div class="metric-icon">🔴</div>
                <div class="metric-value" style="color: #ff1744;">{severity_counts.get('Critical', 0)}</div>
                <div class="metric-label">Critical</div>
            </div>
            """, unsafe_allow_html=True)

        with col4:
            st.markdown(f"""
            <div class="metric-card purple">
                <div class="metric-icon">📏</div>
                <div class="metric-value" style="color: var(--accent-purple);">{result.lines_of_code}</div>
                <div class="metric-label">Lines of Code</div>
            </div>
            """, unsafe_allow_html=True)

        with col5:
            avg_conf = sum(i.confidence for i in filtered_issues) / max(len(filtered_issues), 1)
            st.markdown(f"""
            <div class="metric-card green">
                <div class="metric-icon">🎯</div>
                <div class="metric-value" style="color: var(--accent-green);">{avg_conf:.0%}</div>
                <div class="metric-label">Avg Confidence</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br/>", unsafe_allow_html=True)

        # ── Tabs for detailed views ──────────────────────────
        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
            "🐛 Issues & Defects",
            "📊 Visualizations",
            "🔬 Root Cause Analysis",
            "🧪 Generated Tests",
            "🛡️ Quality Gate & Audit",
            "🔀 Fix Sandbox & Delta",
            "🤖 AI Insights",
            "💬 Ask AI"
        ])

        # ────────────────────────────────────────────────────
        # TAB 1: Issues List
        # ────────────────────────────────────────────────────
        with tab1:
            if not filtered_issues:
                st.markdown("""
                <div class="ai-insight">
                    <div class="ai-insight-title">✅ No Issues Found</div>
                    <div class="ai-insight-body">
                        No issues matched your current filter settings. Try adjusting severity or category filters in the sidebar.
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                # Sort controls
                sort_col1, sort_col2 = st.columns([1, 3])
                with sort_col1:
                    sort_by = st.selectbox("Sort by:", ["Severity", "Confidence", "Line Number", "Category"])

                if sort_by == "Severity":
                    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                    filtered_issues.sort(key=lambda x: sev_order.get(x.severity.value, 5))
                elif sort_by == "Confidence":
                    filtered_issues.sort(key=lambda x: x.confidence, reverse=True)
                elif sort_by == "Line Number":
                    filtered_issues.sort(key=lambda x: x.line_number)
                elif sort_by == "Category":
                    filtered_issues.sort(key=lambda x: x.category.value)

                for issue in filtered_issues:
                    sev_class = issue.severity.value.lower()
                    emoji = SEVERITY_EMOJIS.get(issue.severity.value, "")
                    cat_icon = CATEGORY_ICONS.get(issue.category.value, "📋")

                    st.markdown(f"""
                    <div class="issue-card {sev_class}">
                        <div class="issue-title">{emoji} {issue.title}</div>
                        <div class="issue-desc">{issue.description}</div>
                        <div class="issue-meta">
                            <span class="issue-badge badge-{sev_class}">{issue.severity.value}</span>
                            <span class="issue-badge badge-category">{cat_icon} {issue.category.value}</span>
                            <span class="issue-badge badge-confidence">🎯 {issue.confidence:.0%}</span>
                            <span class="issue-badge badge-line">📍 Line {issue.line_number}</span>
                            {f'<span class="issue-badge badge-info">🔗 {issue.cwe_id}</span>' if issue.cwe_id else ''}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    with st.expander(f"📋 Details — {issue.id}: {issue.title}"):
                        det_col1, det_col2 = st.columns([2, 1])
                        with det_col1:
                            if issue.code_snippet:
                                st.markdown("**📄 Code Snippet:**")
                                st.code(issue.code_snippet, language="python")
                            if issue.suggestion:
                                st.markdown(f"**💡 Suggestion:** {issue.suggestion}")
                            if issue.root_cause:
                                st.markdown(f"**🔬 Root Cause:** {issue.root_cause}")
                        with det_col2:
                            st.markdown(f"**Rule ID:** `{issue.rule_id}`")
                            if issue.cwe_id:
                                st.markdown(f"**CWE:** [{issue.cwe_id}](https://cwe.mitre.org/data/definitions/{issue.cwe_id.split('-')[1]}.html)")
                            st.markdown(f"**File:** `{issue.file_path}`")
                            st.markdown(f"**Line:** `{issue.line_number}`")

                        if issue.fix_example:
                            st.markdown("**🔧 Fix Example:**")
                            st.code(issue.fix_example, language="python")

                        # AI Fix button
                        if api_key:
                            if st.button(f"🤖 Get AI Fix for {issue.id}", key=f"fix_{issue.id}"):
                                with st.spinner("Generating AI-powered fix..."):
                                    fix = get_fix_suggestion(
                                        st.session_state.source_code,
                                        issue.title, issue.description,
                                        issue.line_number, api_key
                                    )
                                    if "error" not in fix:
                                        st.markdown(f"**Explanation:** {fix.get('explanation', 'N/A')}")
                                        if fix.get('changes_made'):
                                            st.markdown("**Changes Made:**")
                                            for change in fix['changes_made']:
                                                st.markdown(f"- {change}")
                                        if fix.get('before_snippet'):
                                            st.markdown("**Before:**")
                                            st.code(fix['before_snippet'], language="python")
                                        if fix.get('after_snippet'):
                                            st.markdown("**After:**")
                                            st.code(fix['after_snippet'], language="python")
                                        if fix.get('verification'):
                                            st.info(f"🔍 **Verification:** {fix['verification']}")
                                    else:
                                        st.error(fix["error"])

                # Export functionality
                st.markdown("---")
                export_col1, export_col2 = st.columns([1, 1])
                with export_col1:
                    # CSV export
                    df_issues = pd.DataFrame([{
                        'ID': i.id,
                        'Title': i.title,
                        'Severity': i.severity.value,
                        'Category': i.category.value,
                        'Line': i.line_number,
                        'Confidence': f"{i.confidence:.0%}",
                        'Description': i.description,
                        'Suggestion': i.suggestion,
                        'CWE': i.cwe_id or '',
                        'Rule': i.rule_id,
                    } for i in filtered_issues])
                    csv = df_issues.to_csv(index=False)
                    st.download_button("📥 Export Issues as CSV", csv, "bugintel_issues.csv", "text/csv",
                                     use_container_width=True)
                with export_col2:
                    # JSON export
                    json_data = json.dumps([{
                        'id': i.id, 'title': i.title,
                        'severity': i.severity.value, 'category': i.category.value,
                        'line': i.line_number, 'confidence': i.confidence,
                        'description': i.description, 'suggestion': i.suggestion,
                        'root_cause': i.root_cause, 'cwe': i.cwe_id,
                    } for i in filtered_issues], indent=2)
                    st.download_button("📥 Export Issues as JSON", json_data, "bugintel_issues.json",
                                     "application/json", use_container_width=True)


        # ────────────────────────────────────────────────────
        # TAB 2: Visualizations
        # ────────────────────────────────────────────────────
        with tab2:
            viz_col1, viz_col2 = st.columns(2)

            with viz_col1:
                # Severity Distribution
                sev_data = pd.DataFrame([
                    {"Severity": s.value, "Count": len([i for i in filtered_issues if i.severity == s])}
                    for s in Severity
                ])
                sev_data = sev_data[sev_data['Count'] > 0]
                if not sev_data.empty:
                    fig_sev = go.Figure(data=[go.Pie(
                        labels=sev_data['Severity'],
                        values=sev_data['Count'],
                        hole=0.55,
                        marker=dict(colors=[SEVERITY_COLORS.get(s, '#999') for s in sev_data['Severity']]),
                        textinfo='label+value',
                        textfont=dict(size=13, family='Inter'),
                        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>"
                    )])
                    fig_sev.update_layout(
                        title=dict(text="🎯 Severity Distribution", font=dict(size=16, color='#e8eaf6', family='Inter')),
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#9ea4c1', family='Inter'),
                        legend=dict(font=dict(color='#9ea4c1')),
                        height=400,
                        margin=dict(t=50, b=20, l=20, r=20),
                        annotations=[dict(text=f"<b>{len(filtered_issues)}</b><br>Issues", x=0.5, y=0.5,
                                          font_size=18, font_color='#e8eaf6', font_family='Inter', showarrow=False)]
                    )
                    st.plotly_chart(fig_sev, use_container_width=True)

            with viz_col2:
                # Category Distribution
                cat_data = pd.DataFrame([
                    {"Category": c.value, "Count": len([i for i in filtered_issues if i.category == c])}
                    for c in IssueCategory
                ])
                cat_data = cat_data[cat_data['Count'] > 0]
                if not cat_data.empty:
                    fig_cat = go.Figure(data=[go.Bar(
                        x=cat_data['Category'],
                        y=cat_data['Count'],
                        marker=dict(
                            color=['#60a5fa', '#a78bfa', '#22d3ee', '#34d399', '#fb923c', '#f87171'][:len(cat_data)],
                            line=dict(width=0),
                        ),
                        text=cat_data['Count'],
                        textposition='outside',
                        textfont=dict(color='#e8eaf6', size=13, family='Inter'),
                        hovertemplate="<b>%{x}</b><br>Issues: %{y}<extra></extra>"
                    )])
                    fig_cat.update_layout(
                        title=dict(text="📋 Category Breakdown", font=dict(size=16, color='#e8eaf6', family='Inter')),
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#9ea4c1', family='Inter'),
                        xaxis=dict(showgrid=False, color='#9ea4c1'),
                        yaxis=dict(showgrid=True, gridcolor='rgba(42,48,80,0.5)', color='#9ea4c1'),
                        height=400,
                        margin=dict(t=50, b=20, l=20, r=20),
                        bargap=0.3,
                    )
                    st.plotly_chart(fig_cat, use_container_width=True)

            # Risk Gauge
            gauge_col1, gauge_col2 = st.columns(2)

            with gauge_col1:
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number+delta",
                    value=result.risk_score,
                    title=dict(text="Code Risk Score", font=dict(size=18, color='#e8eaf6', family='Inter')),
                    gauge=dict(
                        axis=dict(range=[0, 10], tickwidth=1, tickcolor='#2a3050', dtick=2),
                        bar=dict(color=risk_color(result.risk_score), thickness=0.3),
                        bgcolor='#1a1f35',
                        borderwidth=2,
                        bordercolor='#2a3050',
                        steps=[
                            dict(range=[0, 2], color='rgba(52, 211, 153, 0.15)'),
                            dict(range=[2, 4], color='rgba(251, 191, 36, 0.15)'),
                            dict(range=[4, 6], color='rgba(255, 152, 0, 0.15)'),
                            dict(range=[6, 8], color='rgba(255, 87, 34, 0.15)'),
                            dict(range=[8, 10], color='rgba(255, 23, 68, 0.15)'),
                        ],
                        threshold=dict(line=dict(color='#ff1744', width=3), thickness=0.8, value=8),
                    ),
                    number=dict(font=dict(size=42, color='#e8eaf6', family='Inter'), suffix="/10"),
                ))
                fig_gauge.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    height=320, margin=dict(t=80, b=20, l=40, r=40),
                )
                st.plotly_chart(fig_gauge, use_container_width=True)

            with gauge_col2:
                # Complexity chart
                if result.complexity:
                    comp_data = pd.DataFrame([
                        {"Function": name, "Complexity": data['complexity'], "Rating": data['rating']}
                        for name, data in result.complexity.items()
                    ]).sort_values('Complexity', ascending=True)

                    fig_comp = go.Figure(data=[go.Bar(
                        y=comp_data['Function'],
                        x=comp_data['Complexity'],
                        orientation='h',
                        marker=dict(
                            color=[complexity_color(r) for r in comp_data['Rating']],
                            line=dict(width=0),
                        ),
                        text=[f"{c} ({r})" for c, r in zip(comp_data['Complexity'], comp_data['Rating'])],
                        textposition='outside',
                        textfont=dict(color='#e8eaf6', size=11, family='Inter'),
                        hovertemplate="<b>%{y}</b><br>Complexity: %{x}<br>Rating: %{text}<extra></extra>"
                    )])
                    fig_comp.update_layout(
                        title=dict(text="🧠 Cyclomatic Complexity", font=dict(size=16, color='#e8eaf6', family='Inter')),
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#9ea4c1', family='Inter'),
                        xaxis=dict(showgrid=True, gridcolor='rgba(42,48,80,0.5)', color='#9ea4c1', title="Complexity Score"),
                        yaxis=dict(showgrid=False, color='#9ea4c1'),
                        height=320,
                        margin=dict(t=50, b=40, l=20, r=60),
                    )
                    st.plotly_chart(fig_comp, use_container_width=True)

            # Code Metrics
            if result.metrics:
                st.markdown('<div class="section-header"><h2>📏 Code Metrics</h2></div>', unsafe_allow_html=True)
                met_cols = st.columns(5)
                metrics_display = [
                    ("Total Lines", result.metrics.get('total_lines', 0), "📄"),
                    ("Code Lines", result.metrics.get('code_lines', 0), "💻"),
                    ("Functions", result.metrics.get('num_functions', 0), "🔧"),
                    ("Classes", result.metrics.get('num_classes', 0), "🏗️"),
                    ("Comment Ratio", f"{result.metrics.get('comment_ratio', 0)}%", "💬"),
                ]
                for col, (label, value, icon) in zip(met_cols, metrics_display):
                    with col:
                        st.markdown(f"""
                        <div class="metric-card blue">
                            <div class="metric-icon">{icon}</div>
                            <div class="metric-value" style="color: var(--accent-cyan); font-size: 2rem;">{value}</div>
                            <div class="metric-label">{label}</div>
                        </div>
                        """, unsafe_allow_html=True)

            # Confidence distribution
            if filtered_issues:
                st.markdown("<br/>", unsafe_allow_html=True)
                conf_values = [i.confidence for i in filtered_issues]
                fig_conf = go.Figure(data=[go.Histogram(
                    x=conf_values,
                    nbinsx=10,
                    marker=dict(color='rgba(96, 165, 250, 0.6)', line=dict(color='#60a5fa', width=1)),
                    hovertemplate="Confidence: %{x:.0%}<br>Count: %{y}<extra></extra>"
                )])
                fig_conf.update_layout(
                    title=dict(text="🎯 Confidence Distribution", font=dict(size=16, color='#e8eaf6', family='Inter')),
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#9ea4c1', family='Inter'),
                    xaxis=dict(title="Confidence", showgrid=False, color='#9ea4c1', tickformat='.0%'),
                    yaxis=dict(title="Number of Issues", showgrid=True, gridcolor='rgba(42,48,80,0.5)', color='#9ea4c1'),
                    height=300,
                    margin=dict(t=50, b=40, l=40, r=20),
                )
                st.plotly_chart(fig_conf, use_container_width=True)


        # ────────────────────────────────────────────────────
        # TAB 3: Root Cause Analysis
        # ────────────────────────────────────────────────────
        with tab3:
            st.markdown('<div class="section-header"><h2>🔬 Root Cause Analysis</h2></div>', unsafe_allow_html=True)

            # Group issues by root cause patterns
            rca_groups = {}
            for issue in filtered_issues:
                if issue.root_cause:
                    category_key = issue.category.value
                    if category_key not in rca_groups:
                        rca_groups[category_key] = []
                    rca_groups[category_key].append(issue)

            if rca_groups:
                for category, issues_list in rca_groups.items():
                    cat_icon = CATEGORY_ICONS.get(category, "📋")
                    st.markdown(f"### {cat_icon} {category} Issues")

                    for issue in issues_list:
                        sev_emoji = SEVERITY_EMOJIS.get(issue.severity.value, "")
                        st.markdown(f"""
                        <div class="ai-insight">
                            <div class="ai-insight-title">{sev_emoji} {issue.title} <span style="font-size:0.8rem; color:#6b7280;">(Line {issue.line_number})</span></div>
                            <div class="ai-insight-body">
                                <b>🔬 Root Cause:</b> {issue.root_cause}<br/><br/>
                                <b>💡 Recommendation:</b> {issue.suggestion}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.info("Run the analysis first to see root cause details.")

            # Issue Heatmap by line
            if filtered_issues:
                st.markdown('<div class="section-header"><h2>🗺️ Issue Heatmap</h2></div>', unsafe_allow_html=True)
                st.markdown("*Showing where issues cluster in your code — darker areas need more attention*")

                lines_count = len(source_code.split('\n')) if source_code else result.lines_of_code
                line_issues = {}
                for issue in filtered_issues:
                    ln = issue.line_number
                    if ln not in line_issues:
                        line_issues[ln] = 0
                    sev_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0.5}
                    line_issues[ln] += sev_weight.get(issue.severity.value, 1)

                # Create heatmap data
                chunk_size = max(1, lines_count // 20)
                heatmap_data = []
                for start in range(1, lines_count + 1, chunk_size):
                    end = min(start + chunk_size - 1, lines_count)
                    score = sum(line_issues.get(ln, 0) for ln in range(start, end + 1))
                    heatmap_data.append({"Lines": f"L{start}-{end}", "Risk": score})

                if heatmap_data:
                    hm_df = pd.DataFrame(heatmap_data)
                    fig_hm = go.Figure(data=[go.Bar(
                        x=hm_df['Lines'],
                        y=hm_df['Risk'],
                        marker=dict(
                            color=hm_df['Risk'],
                            colorscale=[[0, '#1a1f35'], [0.3, '#ff9800'], [0.6, '#ff5722'], [1, '#ff1744']],
                            line=dict(width=0),
                        ),
                        hovertemplate="<b>%{x}</b><br>Risk Score: %{y:.1f}<extra></extra>"
                    )])
                    fig_hm.update_layout(
                        title=dict(text="📍 Risk Distribution by Line Range",
                                 font=dict(size=16, color='#e8eaf6', family='Inter')),
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#9ea4c1', family='Inter'),
                        xaxis=dict(showgrid=False, color='#9ea4c1', title="Code Region"),
                        yaxis=dict(showgrid=True, gridcolor='rgba(42,48,80,0.5)', color='#9ea4c1', title="Risk Score"),
                        height=300,
                        margin=dict(t=50, b=40, l=40, r=20),
                        bargap=0.05,
                    )
                    st.plotly_chart(fig_hm, use_container_width=True)


        # ────────────────────────────────────────────────────
        # TAB 4: Generated Tests
        # ────────────────────────────────────────────────────
        with tab4:
            st.markdown('<div class="section-header"><h2>🧪 AI-Generated Test Cases</h2></div>', unsafe_allow_html=True)

            tests = st.session_state.generated_tests

            if tests:
                # Group by function
                test_groups = {}
                for test in tests:
                    if test.func_name not in test_groups:
                        test_groups[test.func_name] = []
                    test_groups[test.func_name].append(test)

                st.markdown(f"""
                <div class="ai-insight">
                    <div class="ai-insight-title">🧪 {len(tests)} Test Cases Generated</div>
                    <div class="ai-insight-body">
                        Covering {len(test_groups)} functions • Categories: Unit, Edge Case, Exception, Robustness
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Full test file
                all_test_code = '"""Auto-generated tests by BugIntel"""\nimport pytest\n\n'

                for func_name, func_tests in test_groups.items():
                    st.markdown(f"#### 🔧 Tests for `{func_name}()`")

                    for test in func_tests:
                        cat_badge = {
                            "unit": "🟢 Unit", "edge_case": "🟡 Edge Case",
                            "exception": "🔴 Exception", "robustness": "🟣 Robustness"
                        }.get(test.category, test.category)

                        with st.expander(f"{cat_badge} — `{test.test_name}`"):
                            st.markdown(f"*{test.description}*")
                            st.code(test.test_code, language="python")
                        all_test_code += test.test_code + "\n\n"

                st.markdown("---")
                st.download_button(
                    "📥 Download All Tests",
                    all_test_code,
                    f"test_{file_name}",
                    "text/plain",
                    use_container_width=True
                )

            else:
                st.markdown("""
                <div class="ai-insight">
                    <div class="ai-insight-title">🧪 No Tests Generated Yet</div>
                    <div class="ai-insight-body">
                        Click <b>🧪 Generate Tests</b> above to automatically create test cases for your code's functions.
                    </div>
                </div>
                """, unsafe_allow_html=True)


        # ────────────────────────────────────────────────────
        # TAB 5: Quality Gate & Enterprise Audit Report
        # ────────────────────────────────────────────────────
        with tab5:
            st.markdown('<div class="section-header"><h2>🛡️ Enterprise Quality Gate & Compliance</h2></div>', unsafe_allow_html=True)
            gate_res = QualityGate.evaluate(result, strict=st.session_state.get('strict_gate', False))
            st.session_state.quality_gate_result = gate_res

            # Status Banner
            st.markdown(f"""
            <div style="background: {gate_res.color}15; border: 2px solid {gate_res.color}; border-radius: 16px; padding: 1.5rem 2rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="font-size: 1.4rem; font-weight: 800; color: {gate_res.color};">
                        {gate_res.badge_icon} Quality Gate Status: {gate_res.status}
                    </div>
                    <div style="color: #9ea4c1; margin-top: 0.3rem; font-size: 0.95rem;">
                        {gate_res.summary_text}
                    </div>
                </div>
                <div style="font-size: 2.2rem; font-weight: 900; color: {gate_res.color};">
                    {result.risk_score} <span style="font-size: 1rem; color: #9ea4c1;">/ 10</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Gate criteria grid
            g_cols = st.columns(len(gate_res.conditions))
            for idx, cond in enumerate(gate_res.conditions):
                with g_cols[idx]:
                    st_color = "#34d399" if cond.passed else ("#fbbf24" if cond.is_warning else "#f87171")
                    st_icon = "✅" if cond.passed else ("⚠️" if cond.is_warning else "❌")
                    st.markdown(f"""
                    <div class="metric-card" style="border-top: 3px solid {st_color}; padding: 1.2rem;">
                        <div style="font-size: 1.2rem; margin-bottom: 0.3rem;">{st_icon}</div>
                        <div style="font-weight: 700; font-size: 0.95rem; color: #e8eaf6;">{cond.name}</div>
                        <div style="font-size: 1.4rem; font-weight: 800; color: {st_color}; margin: 0.4rem 0;">{cond.actual_value}</div>
                        <div style="font-size: 0.75rem; color: #9ea4c1;">Target: {cond.threshold}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("<br/>", unsafe_allow_html=True)
            st.markdown("### 📥 Export Executive Audit Report")
            st.markdown("Download enterprise compliance reports for your engineering team, stakeholders, or CI/CD pipelines.")

            html_report = AuditReportGenerator.generate_html_report(result, gate_res, file_name)
            md_report = AuditReportGenerator.generate_markdown_report(result, gate_res, file_name)

            rep_col1, rep_col2 = st.columns(2)
            with rep_col1:
                st.download_button(
                    "📄 Download Executive Audit Report (HTML)",
                    data=html_report,
                    file_name=f"audit_report_{file_name}.html",
                    mime="text/html",
                    use_container_width=True
                )
            with rep_col2:
                st.download_button(
                    "📝 Download Compliance Summary (Markdown)",
                    data=md_report,
                    file_name=f"audit_report_{file_name}.md",
                    mime="text/markdown",
                    use_container_width=True
                )

        # ────────────────────────────────────────────────────
        # TAB 6: Fix Sandbox & Delta Re-Analysis
        # ────────────────────────────────────────────────────
        with tab6:
            st.markdown('<div class="section-header"><h2>🔀 Interactive Fix Sandbox & Delta Re-Analysis</h2></div>', unsafe_allow_html=True)
            st.markdown("Tweak code, auto-apply fixes, and verify immediate defect reduction.")

            if not st.session_state.sandbox_code:
                st.session_state.sandbox_code = source_code

            sb_col1, sb_col2 = st.columns([1, 1])
            with sb_col1:
                st.markdown("#### ✏️ Sandbox Code Editor")
                edited_code = st.text_area(
                    "Edit code to test bug fixes:",
                    value=st.session_state.sandbox_code,
                    height=380,
                    key="sandbox_editor"
                )
                st.session_state.sandbox_code = edited_code

                sb_btn1, sb_btn2 = st.columns(2)
                with sb_btn1:
                    reanalyze = st.button("⚡ Re-Analyze Sandbox Code", use_container_width=True)
                with sb_btn2:
                    auto_patch = st.button("🪄 Auto-Patch Known Smells", use_container_width=True)

                if auto_patch:
                    import re as regex_mod
                    patched = edited_code
                    patched = regex_mod.sub(r"except\s*:", "except Exception as e:", patched)
                    patched = regex_mod.sub(r"def\s+(\w+)\s*\((.*?)=\s*\[\]\s*\):", r"def \1(\2=None):", patched)
                    patched = regex_mod.sub(r"def\s+(\w+)\s*\((.*?)=\s*\{\}\s*\):", r"def \1(\2=None):", patched)
                    st.session_state.sandbox_code = patched
                    st.rerun()

            with sb_col2:
                st.markdown("#### 📈 Delta Improvement Metrics")
                if reanalyze or st.session_state.sandbox_result:
                    if reanalyze:
                        sb_analyzer = StaticAnalyzer()
                        sb_res = sb_analyzer.analyze(st.session_state.sandbox_code, f"fixed_{file_name}")
                        st.session_state.sandbox_result = sb_res
                    else:
                        sb_res = st.session_state.sandbox_result

                    orig_issues = len(result.issues)
                    new_issues = len(sb_res.issues)
                    issue_delta = new_issues - orig_issues
                    risk_delta = round(sb_res.risk_score - result.risk_score, 1)

                    m1, m2 = st.columns(2)
                    with m1:
                        st.metric(
                            "Total Defects",
                            new_issues,
                            delta=f"{issue_delta} ({round(issue_delta/max(orig_issues,1)*100, 1)}%)",
                            delta_color="inverse"
                        )
                    with m2:
                        st.metric(
                            "Risk Score",
                            f"{sb_res.risk_score}/10",
                            delta=f"{risk_delta}",
                            delta_color="inverse"
                        )

                    st.markdown("---")
                    st.markdown("#### 🔍 Diff Inspection (Original vs Sandbox)")
                    orig_lines = source_code.splitlines(keepends=True)
                    new_lines = st.session_state.sandbox_code.splitlines(keepends=True)
                    diff = list(difflib.unified_diff(orig_lines, new_lines, fromfile="original.py", tofile="sandbox_fixed.py"))
                    if diff:
                        diff_text = "".join(diff)
                        st.code(diff_text, language="diff")
                    else:
                        st.info("No modifications detected between original and sandbox code.")
                else:
                    st.info("Edit your code on the left and click **⚡ Re-Analyze Sandbox Code** to measure the defect delta.")

        # ────────────────────────────────────────────────────
        # TAB 7: AI Insights
        # ────────────────────────────────────────────────────
        with tab7:
            st.markdown('<div class="section-header"><h2>🤖 AI-Powered Insights</h2></div>', unsafe_allow_html=True)

            ai = st.session_state.ai_analysis

            if ai and "error" not in ai:
                # Overall Assessment
                risk_badge_color = {
                    "LOW": "#34d399", "MEDIUM": "#ff9800", "HIGH": "#ff5722", "CRITICAL": "#ff1744"
                }.get(ai.get('risk_level', 'MEDIUM'), '#9ea4c1')

                st.markdown(f"""
                <div class="ai-insight" style="border-color: {risk_badge_color}40;">
                    <div class="ai-insight-title">📋 Overall Assessment 
                        <span class="issue-badge" style="background: {risk_badge_color}20; color: {risk_badge_color}; margin-left: 0.5rem;">
                            {ai.get('risk_level', 'N/A')} RISK
                        </span>
                    </div>
                    <div class="ai-insight-body">{ai.get('overall_assessment', 'No assessment available.')}</div>
                </div>
                """, unsafe_allow_html=True)

                # Top Concerns
                if ai.get('top_concerns'):
                    st.markdown("### ⚠️ Top Concerns")
                    for i, concern in enumerate(ai['top_concerns'], 1):
                        with st.expander(f"🔸 Concern {i}: {concern.get('title', 'Untitled')}", expanded=i <= 2):
                            st.markdown(f"**Why this matters:** {concern.get('explanation', 'N/A')}")
                            st.markdown(f"**Potential Impact:** {concern.get('impact', 'N/A')}")
                            st.markdown(f"**Recommendation:** {concern.get('recommendation', 'N/A')}")

                # Root Cause from AI
                if ai.get('root_cause_analysis'):
                    st.markdown("### 🔬 Deep Root Cause Analysis")
                    st.markdown(f"""
                    <div class="ai-insight">
                        <div class="ai-insight-body">{ai['root_cause_analysis']}</div>
                    </div>
                    """, unsafe_allow_html=True)

                # Priorities
                ai_col1, ai_col2 = st.columns(2)
                with ai_col1:
                    if ai.get('improvement_priorities'):
                        st.markdown("### 📊 Improvement Priorities")
                        for priority in ai['improvement_priorities']:
                            st.markdown(f"- {priority}")

                    if ai.get('security_notes'):
                        st.markdown("### 🔒 Security Notes")
                        st.warning(ai['security_notes'])

                with ai_col2:
                    if ai.get('positive_aspects'):
                        st.markdown("### ✅ Positive Aspects")
                        for pos in ai['positive_aspects']:
                            st.markdown(f"- ✅ {pos}")

                    if ai.get('test_recommendations'):
                        st.markdown("### 🧪 Test Recommendations")
                        st.info(ai['test_recommendations'])

            elif ai and "error" in ai:
                st.error(f"❌ {ai['error']}")
            else:
                st.markdown("""
                <div class="ai-insight">
                    <div class="ai-insight-title">🤖 AI Analysis Not Run Yet</div>
                    <div class="ai-insight-body">
                        Enter your <b>Gemini API key</b> in the sidebar and click <b>🤖 AI Deep Analysis</b> to get intelligent insights
                        including root cause analysis, security assessment, and improvement priorities.
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if not api_key:
                    st.markdown("""
                    <div class="ai-insight" style="border-color: rgba(251, 191, 36, 0.3);">
                        <div class="ai-insight-title" style="color: #fbbf24;">🔑 API Key Required</div>
                        <div class="ai-insight-body">
                            To use AI features, enter your Google Gemini API key in the sidebar.<br/>
                            Get a free API key at <a href="https://aistudio.google.com/apikey" target="_blank" style="color: #60a5fa;">aistudio.google.com/apikey</a>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)


        # ────────────────────────────────────────────────────
        # TAB 8: Chat with AI
        # ────────────────────────────────────────────────────
        with tab8:
            st.markdown('<div class="section-header"><h2>💬 Ask AI About Your Code</h2></div>', unsafe_allow_html=True)

            if not api_key:
                st.markdown("""
                <div class="ai-insight" style="border-color: rgba(251, 191, 36, 0.3);">
                    <div class="ai-insight-title" style="color: #fbbf24;">🔑 API Key Required</div>
                    <div class="ai-insight-body">Enter your Gemini API key in the sidebar to use the AI chat feature.</div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("Ask questions about your code, the detected issues, or get help with debugging.")

                # Quick question buttons
                st.markdown("**Quick Questions:**")
                q_col1, q_col2, q_col3 = st.columns(3)
                quick_q = None
                with q_col1:
                    if st.button("🔒 Security Review", use_container_width=True):
                        quick_q = "Perform a thorough security review of this code. What are the security vulnerabilities?"
                with q_col2:
                    if st.button("⚡ Performance Tips", use_container_width=True):
                        quick_q = "What are the performance issues in this code and how can I optimize it?"
                with q_col3:
                    if st.button("🏗️ Architecture Review", use_container_width=True):
                        quick_q = "Review the architecture and design patterns. What improvements would you suggest?"

                user_question = st.text_input(
                    "Your question:",
                    value=quick_q or "",
                    placeholder="e.g., Why is the mutable default argument a problem? How can I fix the SQL injection?"
                )

                if st.button("💬 Ask", disabled=not user_question) and user_question:
                    with st.spinner("🤖 Thinking..."):
                        response = chat_with_code(
                            st.session_state.source_code,
                            filtered_issues,
                            user_question,
                            api_key
                        )
                        st.session_state.chat_history.append({
                            'question': user_question,
                            'answer': response,
                            'timestamp': datetime.now().strftime("%H:%M:%S")
                        })

                # Display chat history
                if st.session_state.chat_history:
                    st.markdown("---")
                    for chat in reversed(st.session_state.chat_history):
                        st.markdown(f"""
                        <div style="background: rgba(96, 165, 250, 0.08); border: 1px solid rgba(96, 165, 250, 0.2); 
                             border-radius: 12px; padding: 1rem; margin-bottom: 0.5rem;">
                            <div style="color: #60a5fa; font-weight: 600; font-size: 0.9rem;">
                                🧑 You — {chat['timestamp']}
                            </div>
                            <div style="color: #e8eaf6; margin-top: 0.3rem;">{chat['question']}</div>
                        </div>
                        """, unsafe_allow_html=True)
                        st.markdown(chat['answer'])
                        st.markdown("---")

    else:
        # No analysis run yet — show welcome content
        st.markdown('<div class="section-header"><h2>🚀 Get Started</h2></div>', unsafe_allow_html=True)

        col_start1, col_start2, col_start3 = st.columns(3)

        with col_start1:
            st.markdown("""
            <div class="metric-card blue" style="padding: 2rem; text-align: left;">
                <div style="font-size: 2rem; margin-bottom: 0.8rem;">📝</div>
                <div style="font-size: 1.1rem; font-weight: 700; color: #e8eaf6; margin-bottom: 0.5rem;">Step 1: Input Code</div>
                <div style="color: #9ea4c1; font-size: 0.9rem; line-height: 1.5;">
                    Paste Python code, upload a .py file, or choose a sample project from the sidebar.
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_start2:
            st.markdown("""
            <div class="metric-card purple" style="padding: 2rem; text-align: left;">
                <div style="font-size: 2rem; margin-bottom: 0.8rem;">🔍</div>
                <div style="font-size: 1.1rem; font-weight: 700; color: #e8eaf6; margin-bottom: 0.5rem;">Step 2: Analyze</div>
                <div style="color: #9ea4c1; font-size: 0.9rem; line-height: 1.5;">
                    Click <b>🚀 Analyze Code</b> for static analysis or <b>🤖 AI Deep Analysis</b> for AI-powered insights.
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_start3:
            st.markdown("""
            <div class="metric-card green" style="padding: 2rem; text-align: left;">
                <div style="font-size: 2rem; margin-bottom: 0.8rem;">🛠️</div>
                <div style="font-size: 1.1rem; font-weight: 700; color: #e8eaf6; margin-bottom: 0.5rem;">Step 3: Fix & Test</div>
                <div style="color: #9ea4c1; font-size: 0.9rem; line-height: 1.5;">
                    Review issues, get AI fix suggestions, generate tests, and export reports.
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br/>", unsafe_allow_html=True)

        # Feature highlights
        st.markdown('<div class="section-header"><h2>✨ Platform Capabilities</h2></div>', unsafe_allow_html=True)

        feat_cols = st.columns(2)

        features = [
            ("🐛 Bug Detection", "19+ pattern detectors covering bugs, security vulnerabilities, code smells, and reliability issues using AST-based analysis."),
            ("🔒 Security Analysis", "Detects hardcoded secrets, SQL injection, eval/exec usage, and OWASP Top 10 risks with CWE mappings."),
            ("🔬 Root Cause Analysis", "Evidence-based explanations of detected problems with probable root causes and impact assessment."),
            ("🧪 Test Generation", "Automatically generates unit tests, edge-case tests, exception tests, and robustness tests for your functions."),
            ("🤖 AI Deep Analysis", "Google Gemini-powered deep analysis with intelligent insights, fix suggestions, and interactive Q&A."),
            ("📊 Rich Visualizations", "Interactive charts showing severity distribution, complexity analysis, risk gauges, and issue heatmaps."),
        ]

        for i, (title, desc) in enumerate(features):
            with feat_cols[i % 2]:
                st.markdown(f"""
                <div class="ai-insight" style="margin-bottom: 0.8rem;">
                    <div class="ai-insight-title">{title}</div>
                    <div class="ai-insight-body">{desc}</div>
                </div>
                """, unsafe_allow_html=True)


    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# WORKSPACE 2: MULTI-FILE & REPOSITORY SCANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
elif platform_mode == "📁 Multi-File Repository Scanner":
        st.markdown("""
        <div class="hero-banner">
            <div class="hero-title">📁 Repository & Multi-File Architecture Scanner</div>
            <div class="hero-subtitle">
                Cross-file defect discovery • Defect density ranking • Hotspot danger matrix • Full project quality assessment
            </div>
        </div>
        """, unsafe_allow_html=True)

        repo_files = {}
        if repo_input_method == "📦 Upload ZIP Archive":
            st.markdown('<div class="section-header"><h2>📦 Upload Project ZIP Archive</h2></div>', unsafe_allow_html=True)
            uploaded_zip = st.file_uploader("Upload .zip archive containing Python code:", type=["zip"])
            if uploaded_zip:
                scanner = RepositoryScanner()
                if st.button("🚀 Scan Entire Repository ZIP", use_container_width=True):
                    with st.spinner("📦 Extracting and analyzing repository files..."):
                        st.session_state.repo_audit = scanner.scan_zip(uploaded_zip.read())

        elif repo_input_method == "📂 Upload Multiple .py Files":
            st.markdown('<div class="section-header"><h2>📂 Upload Multiple Python Files</h2></div>', unsafe_allow_html=True)
            uploaded_files = st.file_uploader("Upload Python (.py) files:", type=["py"], accept_multiple_files=True)
            if uploaded_files:
                file_map = {f.name: f.read().decode("utf-8", errors="replace") for f in uploaded_files}
                if st.button("🚀 Scan Uploaded Files", use_container_width=True):
                    with st.spinner("🔍 Analyzing multi-file project..."):
                        scanner = RepositoryScanner()
                        st.session_state.repo_audit = scanner.scan_files(file_map)

        elif repo_input_method == "🧪 Load Sample Microservice":
            st.markdown('<div class="section-header"><h2>🧪 Microservice Sample Project (3 Services)</h2></div>', unsafe_allow_html=True)
            st.info("Demonstrates repository-wide cross-module analysis with services/order_service.py, auth/auth_manager.py, and etl/pipeline_worker.py.")
            if st.button("🚀 Analyze Sample Microservice Repository", use_container_width=True):
                with st.spinner("🔍 Running multi-file static analysis on microservice repository..."):
                    scanner = RepositoryScanner()
                    st.session_state.repo_audit = scanner.scan_files(SAMPLE_MULTI_PROJECT)

        repo_res = st.session_state.repo_audit

        if repo_res:
            st.markdown('<div class="section-header"><h2>📊 Repository Architecture & Health Overview</h2></div>', unsafe_allow_html=True)

            rcol1, rcol2, rcol3, rcol4, rcol5 = st.columns(5)
            with rcol1:
                st.markdown(f"""
                <div class="metric-card blue">
                    <div class="metric-icon">📁</div>
                    <div class="metric-value" style="color: var(--accent-blue);">{repo_res.total_files}</div>
                    <div class="metric-label">Files Analyzed</div>
                </div>
                """, unsafe_allow_html=True)
            with rcol2:
                st.markdown(f"""
                <div class="metric-card purple">
                    <div class="metric-icon">📏</div>
                    <div class="metric-value" style="color: var(--accent-purple);">{repo_res.total_loc}</div>
                    <div class="metric-label">Total LOC</div>
                </div>
                """, unsafe_allow_html=True)
            with rcol3:
                st.markdown(f"""
                <div class="metric-card orange">
                    <div class="metric-icon">🐛</div>
                    <div class="metric-value" style="color: #ff9800;">{repo_res.total_issues}</div>
                    <div class="metric-label">Total Defects</div>
                </div>
                """, unsafe_allow_html=True)
            with rcol4:
                st.markdown(f"""
                <div class="metric-card red">
                    <div class="metric-icon">🔴</div>
                    <div class="metric-value" style="color: #ff1744;">{repo_res.total_critical}</div>
                    <div class="metric-label">Critical Exploits</div>
                </div>
                """, unsafe_allow_html=True)
            with rcol5:
                st.markdown(f"""
                <div class="metric-card red">
                    <div class="metric-icon">🎯</div>
                    <div class="metric-value" style="color: {risk_color(repo_res.average_risk_score)};">{repo_res.average_risk_score}</div>
                    <div class="metric-label">Avg Risk Score</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br/>", unsafe_allow_html=True)

            # Hotspot Matrix Scatter Chart
            st.markdown("### 🗺️ Defect Hotspot Matrix (LOC vs Complexity vs Defect Density)")
            st.caption("Pinpoints danger zones across modules. Larger bubbles indicate higher defect concentration.")

            hotspot_data = []
            for summary in repo_res.file_summaries:
                hotspot_data.append({
                    "File": summary.file_path,
                    "LOC": summary.lines_of_code,
                    "Max Complexity": summary.max_complexity,
                    "Total Defects": summary.issue_count,
                    "Critical Flaws": summary.critical_count,
                    "Risk Score": summary.risk_score
                })
            df_hotspot = pd.DataFrame(hotspot_data)

            if not df_hotspot.empty:
                fig = px.scatter(
                    df_hotspot,
                    x="LOC",
                    y="Max Complexity",
                    size="Total Defects",
                    color="Risk Score",
                    hover_name="File",
                    color_continuous_scale="Reds",
                    size_max=45,
                    template="plotly_dark"
                )
                fig.update_layout(
                    plot_bgcolor='rgba(26, 31, 53, 0.6)',
                    paper_bgcolor='rgba(17, 24, 39, 0)',
                    font=dict(family="Inter", color="#e8eaf6"),
                    margin=dict(l=40, r=40, t=30, b=40)
                )
                st.plotly_chart(fig, use_container_width=True)

            # File Risk Ranking Table
            st.markdown("### 📋 File Risk & Defect Breakdown Table")
            st.dataframe(
                df_hotspot.sort_values(by=["Critical Flaws", "Risk Score"], ascending=False),
                use_container_width=True,
                hide_index=True
            )

            st.markdown("---")
            st.markdown("### 🔍 Inspect Individual File from Repository")
            selected_file = st.selectbox("Choose a file to load into the Single-File Inspector:", list(repo_res.file_sources.keys()))
            if st.button("🚀 Load File into Single-File Inspector", use_container_width=True):
                st.session_state.source_code = repo_res.file_sources[selected_file]
                st.session_state.analysis_result = repo_res.file_results[selected_file]
                st.success(f"✅ Loaded `{selected_file}`! Switch to the '🎯 Single File Code Inspector' workspace in the sidebar to view full tabs.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# WORKSPACE 3: OWASP SUPPLY-CHAIN & DEPENDENCIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
elif platform_mode == "📦 OWASP Supply-Chain & Dependencies":
        st.markdown("""
        <div class="hero-banner">
            <div class="hero-title">📦 OWASP 2025 Supply-Chain & Dependency Auditor</div>
            <div class="hero-subtitle">
                OWASP Top 10 A06 Compliance • CVE Advisory Feed • Typosquatting Guard • Software Bill of Materials (SBOM)
            </div>
        </div>
        """, unsafe_allow_html=True)

        req_content = ""
        if dep_input_method == "📝 Paste requirements.txt":
            st.markdown('<div class="section-header"><h2>📝 Paste requirements.txt Content</h2></div>', unsafe_allow_html=True)
            req_content = st.text_area(
                "Paste requirements.txt here:",
                height=200,
                placeholder="requests==2.25.1\nurllib3==1.26.15\npyyaml==5.3.1\nflask"
            )
        elif dep_input_method == "📁 Upload requirements.txt":
            st.markdown('<div class="section-header"><h2>📁 Upload requirements.txt File</h2></div>', unsafe_allow_html=True)
            uploaded_req = st.file_uploader("Upload requirements.txt:", type=["txt", "pip"])
            if uploaded_req:
                req_content = uploaded_req.read().decode("utf-8", errors="replace")
        elif dep_input_method == "🧪 Sample Legacy Stack":
            st.markdown('<div class="section-header"><h2>🧪 Sample Legacy Dependency Stack</h2></div>', unsafe_allow_html=True)
            st.info("Demonstrates known vulnerabilities in requests, urllib3, pyyaml, django, flask, cryptography, and unpinned packages.")
            req_content = SAMPLE_REQUIREMENTS

        if req_content:
            with st.expander("👁️ Preview Scanned Requirements", expanded=False):
                st.code(req_content, language="text")

        if st.button("🔒 Run Supply-Chain Security Audit", use_container_width=True, disabled=not req_content):
            with st.spinner("🛡️ Auditing dependencies against CVE vulnerability database and OWASP 2025 guidelines..."):
                dep_scanner = DependencyScanner()
                st.session_state.dep_audit = dep_scanner.scan(requirements_content=req_content)

        dep_res = st.session_state.dep_audit

        if dep_res:
            st.markdown('<div class="section-header"><h2>📊 Supply-Chain Security Dashboard</h2></div>', unsafe_allow_html=True)

            dcol1, dcol2, dcol3, dcol4 = st.columns(4)
            with dcol1:
                st.markdown(f"""
                <div class="metric-card blue">
                    <div class="metric-icon">📦</div>
                    <div class="metric-value" style="color: var(--accent-blue);">{dep_res.total_packages}</div>
                    <div class="metric-label">Packages Audited</div>
                </div>
                """, unsafe_allow_html=True)
            with dcol2:
                st.markdown(f"""
                <div class="metric-card orange">
                    <div class="metric-icon">⚠️</div>
                    <div class="metric-value" style="color: #ff9800;">{dep_res.vulnerable_packages}</div>
                    <div class="metric-label">Vulnerable Packages</div>
                </div>
                """, unsafe_allow_html=True)
            with dcol3:
                st.markdown(f"""
                <div class="metric-card red">
                    <div class="metric-icon">🔴</div>
                    <div class="metric-value" style="color: #ff1744;">{dep_res.critical_count + dep_res.high_count}</div>
                    <div class="metric-label">Critical / High CVEs</div>
                </div>
                """, unsafe_allow_html=True)
            with dcol4:
                st.markdown(f"""
                <div class="metric-card purple">
                    <div class="metric-icon">🔓</div>
                    <div class="metric-value" style="color: var(--accent-purple);">{dep_res.unpinned_count}</div>
                    <div class="metric-label">Unpinned Versions</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br/>", unsafe_allow_html=True)

            # Risk Banner
            risk_c = "#ff1744" if dep_res.supply_chain_risk_score >= 7.0 else ("#ff9800" if dep_res.supply_chain_risk_score >= 4.0 else "#10b981")
            st.markdown(f"""
            <div style="background: {risk_c}15; border: 2px solid {risk_c}; border-radius: 16px; padding: 1.5rem 2rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="font-size: 1.3rem; font-weight: 800; color: {risk_c};">
                        🛡️ OWASP 2025 Supply-Chain Risk Score: {dep_res.supply_chain_risk_score} / 10
                    </div>
                    <div style="color: #9ea4c1; margin-top: 0.3rem;">
                        {'Critical vulnerabilities detected in supply chain dependencies.' if dep_res.critical_count > 0 else 'Acceptable supply-chain risk profile.'}
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Active CVE Advisories Feed
            st.markdown("### 🚨 Active CVE Advisories & Typosquatting Alerts")
            all_vulns = []
            for dep in dep_res.dependencies:
                for v in dep.vulnerabilities:
                    all_vulns.append((dep.name, v))

            if all_vulns:
                for pkg_name, vuln in all_vulns:
                    s_color = "#ff1744" if vuln.severity == VulnerabilitySeverity.CRITICAL else "#ff5722"
                    st.markdown(f"""
                    <div class="issue-card {'critical' if vuln.severity == VulnerabilitySeverity.CRITICAL else 'high'}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div class="issue-title" style="margin-bottom: 0;">
                                🔴 <strong>{vuln.cve_id}</strong>: {vuln.title}
                            </div>
                            <span class="badge" style="background:{s_color}; color:#fff; font-weight:bold; padding: 4px 10px; border-radius: 6px;">
                                CVSS {vuln.cvss_score} ({vuln.severity.value})
                            </span>
                        </div>
                        <div class="issue-desc" style="margin-top: 0.5rem;">{vuln.description}</div>
                        <div class="issue-meta" style="margin-top: 0.8rem;">
                            <span class="issue-badge badge-high">Package: {pkg_name}</span>
                            <span class="issue-badge badge-category">Affected: {vuln.affected_spec}</span>
                            <span class="issue-badge badge-info">Fixed In: {vuln.fixed_in}</span>
                        </div>
                        <div style="margin-top: 0.8rem; background: rgba(0,0,0,0.3); padding: 0.7rem 1rem; border-radius: 8px; border-left: 3px solid #34d399;">
                            <strong>💡 Remediation:</strong> <code>{vuln.remediation}</code>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("✅ No known CVE vulnerabilities or malicious typosquatting candidates found in scanned dependencies.")

            # SBOM Table
            st.markdown("### 📋 Software Bill of Materials (SBOM) Register")
            sbom_rows = []
            for d in dep_res.dependencies:
                sbom_rows.append({
                    "Package": d.name,
                    "Specifier": d.specifier,
                    "Version Pinned": "✅ Yes" if d.is_pinned else "❌ Unpinned (Risk)",
                    "Vulnerabilities": len(d.vulnerabilities),
                    "Risk Rating": d.risk_level
                })
            st.dataframe(pd.DataFrame(sbom_rows), use_container_width=True, hide_index=True)

            # Secure Requirements Generation
            st.markdown("### 📥 Export Remediated requirements.txt")
            fixed_lines = []
            for d in dep_res.dependencies:
                if d.vulnerabilities:
                    safe_v = d.vulnerabilities[0].fixed_in.split("/")[0].strip()
                    fixed_lines.append(f"{d.name}>={safe_v}  # Remediated {d.vulnerabilities[0].cve_id}")
                elif not d.is_pinned:
                    fixed_lines.append(f"{d.name}==1.0.0  # Pinned for supply-chain stability")
                else:
                    fixed_lines.append(f"{d.name}{d.specifier}")
            fixed_req_text = "\n".join(fixed_lines)

            st.download_button(
                "📥 Download Secure Remediated requirements.txt",
                data=fixed_req_text,
                file_name="requirements_remediated.txt",
                mime="text/plain",
                use_container_width=True
            )


    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# FOOTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
st.markdown("""
<div class="footer">
    <div style="font-size: 1.2rem; margin-bottom: 0.3rem;">🔍 BugIntel</div>
    <div>AI-Powered Software Quality & Bug Intelligence Platform</div>
    <div style="margin-top: 0.5rem;">
        Built with Python • Streamlit • Plotly • Google Gemini AI
    </div>
</div>
""", unsafe_allow_html=True)
