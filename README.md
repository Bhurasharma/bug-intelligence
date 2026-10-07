# 🔍 BugIntel — AI-Powered Software Quality & Bug Intelligence Platform

An enterprise-grade platform combining static AST code analysis, AI-powered root cause analysis, automated test suite generation, SonarQube-style Quality Gates, multi-file repository scanning, and OWASP Top 10 (2025) supply-chain dependency auditing.

---

## 🧭 Platform Workspaces

BugIntel features three dedicated operational workspaces accessible via the sidebar switcher:

| Workspace | Description | Key Capabilities |
| :--- | :--- | :--- |
| **🎯 Single File Code Inspector** | In-depth module code analysis & quality gating | 30+ AST defect rules, 8 interactive tabs, Quality Gate evaluation, Fix Sandbox with live diff delta, automated test generator, Gemini AI insights & chat |
| **📁 Multi-File Repository Scanner** | Full repository architecture & multi-file inspection | ZIP archive or multi-file upload, project health score, Hotspot Danger Matrix (LOC vs Complexity), file defect density ranking |
| **📦 OWASP 2025 Supply-Chain Auditor** | Software supply chain & dependency security | Scans `requirements.txt` against CVE advisories, CVSS scores, typosquatting guard, Software Bill of Materials (SBOM), automated remediated requirements export |

---

## ✨ Core Feature Highlights

### 1. 🐛 Advanced AST Defect Engine (30+ Rules)
Detects issues across 6 key engineering dimensions without executing untrusted code:
- **Security (SEC001-SEC008)**: SQL injection, hardcoded secrets, eval/exec, insecure crypto (MD5/SHA1), insecure deserialization (pickle, unsafe yaml), command injection (`subprocess(shell=True)`, `os.system`), unverified SSL/TLS contexts, disabled certificate validation (`verify=False`).
- **Reliability (REL001-REL005)**: Bare except clauses, empty except handlers, mutable default arguments, unhandled HTTP timeouts (`requests` without `timeout`), mutating collections during iteration.
- **Bug & Logic (BUG001-BUG007)**: Infinite loops, equality comparison to `None`, `type()` comparison vs `isinstance`, duplicate dictionary keys, missing return paths.
- **Performance (PERF001-PERF003)**: Inefficient string concatenation in loops, excessive list lookups in nested loops.
- **Maintainability (MT001-MT005)**: Deeply nested blocks (>4 levels), excessive function arguments (>7 params), global statement abuse, wildcard imports (`from mod import *`).

### 2. 🛡️ Enterprise Quality Gate & Executive Reports
- SonarQube-style Pass / Warning / Fail evaluation based on Critical exploit counts, High severity caps, Risk scores, and Cyclomatic Complexity.
- **Executive Audit Report (HTML)**: Printable, styled compliance report suitable for PDF conversion, stakeholder reviews, and CI/CD audit logs.
- **Compliance Summary (Markdown)**: GitHub-ready markdown audit report.

### 3. 🔀 Interactive Fix Sandbox & Delta Re-Analysis
- Built-in code sandbox to modify code or auto-patch common smells with 1-click.
- Instant before/after comparison showing defect count delta (e.g. `27 → 3 (-88.9%)`), risk score drop, and unified side-by-side git diff.

### 4. 🗺️ Defect Hotspot Danger Matrix
- Multi-dimensional Plotly bubble chart plotting **Lines of Code (X)** vs **Cyclomatic Complexity (Y)** with bubble size mapped to **Defect Count** and color to **Risk Score**.
- Instantly isolates high-risk failure-prone modules across large codebases.

### 5. 📦 OWASP Top 10 (2025) Supply-Chain & CVE Scanner
- Addresses OWASP 2025 A06 (Software Supply Chain Risks).
- Evaluates packages for known CVEs, CVSS severity scores, and malicious typosquatting package names.
- Exports an enterprise **Software Bill of Materials (SBOM)** table and updated, remediated `requirements.txt`.

### 6. 🧪 Automated Test Suite Generator
- Generates `pytest` and `unittest` test suites covering standard unit tests, boundary edge cases, exception handling, and robustness fuzzing.

### 7. 🤖 Google Gemini AI Integration (Optional)
- AI Deep Analysis providing contextual architecture reviews, root cause breakdowns, and automated diff patches.
- Interactive code chat assistant for real-time debugging inquiries.
- *(Static analysis, Quality Gate, Sandbox, Repository Scanner, and SBOM Auditor function 100% offline without an API key).*

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the Platform
```bash
streamlit run app.py
```

### 3. Access the Dashboard
Open your browser to:
👉 **`http://localhost:8501`**

---

## 📂 Project Structure

```
Bug Finder/
├── app.py                      # Main Streamlit enterprise application
├── requirements.txt            # Python dependencies
├── README.md                   # Platform documentation
├── .streamlit/
│   └── config.toml             # Dark glassmorphic theme styling
├── analyzer/
│   ├── __init__.py             # Package exports
│   ├── static_analyzer.py      # AST static analyzer (30+ rules, risk scoring, complexity)
│   ├── quality_gate.py         # Sonar-style Quality Gate & Executive HTML report generator
│   ├── repository_scanner.py   # Multi-file & ZIP archive architecture scanner
│   ├── dependency_scanner.py   # OWASP 2025 supply chain & CVE vulnerability auditor
│   ├── test_generator.py       # Automated pytest/unittest test case generator
│   └── ai_engine.py            # Google Gemini AI deep analysis & chat integration
└── utils/
    ├── __init__.py             # Package init
    └── helpers.py              # Visual helpers, sample codes, sample requirements & microservice
```
