"""
Quality Gate & Executive Audit Report Generator
Evaluates enterprise software quality gates (Passed / Warning / Failed) and compiles
printable, audit-ready HTML & Markdown reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
from analyzer.static_analyzer import AnalysisResult, Severity, IssueCategory


@dataclass
class GateCondition:
    name: str
    threshold: str
    actual_value: str
    passed: bool
    is_warning: bool = False
    message: str = ""


@dataclass
class QualityGateResult:
    status: str  # "PASSED", "WARNING", "FAILED"
    color: str
    badge_icon: str
    conditions: List[GateCondition] = field(default_factory=list)
    summary_text: str = ""


class QualityGate:
    """Evaluates codebase against enterprise quality standards."""

    @staticmethod
    def evaluate(result: AnalysisResult, strict: bool = False) -> QualityGateResult:
        conditions = []
        critical_count = sum(1 for i in result.issues if i.severity == Severity.CRITICAL)
        high_count = sum(1 for i in result.issues if i.severity == Severity.HIGH)
        medium_count = sum(1 for i in result.issues if i.severity == Severity.MEDIUM)
        
        # Max complexity
        max_complexity = 0
        if result.complexity:
            max_complexity = max((v.get('complexity', 0) for v in result.complexity.values()), default=0)

        # 1. Critical Issues Gate
        crit_limit = 0
        crit_passed = critical_count <= crit_limit
        conditions.append(GateCondition(
            name="Zero Critical Vulnerabilities",
            threshold=f"<= {crit_limit}",
            actual_value=str(critical_count),
            passed=crit_passed,
            message="Zero tolerance for critical security exploits and syntax failures."
        ))

        # 2. High Severity Gate
        high_limit = 1 if strict else 3
        high_passed = high_count <= high_limit
        conditions.append(GateCondition(
            name="High Severity Defects",
            threshold=f"<= {high_limit}",
            actual_value=str(high_count),
            passed=high_passed,
            message="Limits reliability crashes, SQL injections, and data corruption risks."
        ))

        # 3. Overall Risk Score
        risk_limit = 5.0 if strict else 7.0
        risk_passed = result.risk_score <= risk_limit
        conditions.append(GateCondition(
            name="Code Risk Index",
            threshold=f"<= {risk_limit}",
            actual_value=f"{result.risk_score}/10",
            passed=risk_passed,
            message="Aggregated defect density and codebase maintainability score."
        ))

        # 4. Cyclomatic Complexity
        comp_limit = 12 if strict else 18
        comp_passed = max_complexity <= comp_limit
        conditions.append(GateCondition(
            name="Peak Cyclomatic Complexity",
            threshold=f"<= {comp_limit}",
            actual_value=str(max_complexity),
            passed=comp_passed,
            is_warning=not comp_passed and max_complexity <= comp_limit + 5,
            message="Functions with complexity > 15 are unmaintainable and regression-prone."
        ))

        # Determine overall status
        failed_conditions = [c for c in conditions if not c.passed and not c.is_warning]
        warning_conditions = [c for c in conditions if not c.passed and c.is_warning]

        if failed_conditions:
            status = "FAILED"
            color = "#ef4444"
            icon = "❌"
            summary = f"Quality gate failed on {len(failed_conditions)} critical condition(s). Deployment blocked."
        elif warning_conditions:
            status = "WARNING"
            color = "#f59e0b"
            icon = "⚠️"
            summary = "Quality gate passed with warnings. Manual engineering sign-off required."
        else:
            status = "PASSED"
            color = "#10b981"
            icon = "✅"
            summary = "All enterprise code quality standards satisfied. Approved for production build."

        return QualityGateResult(
            status=status,
            color=color,
            badge_icon=icon,
            conditions=conditions,
            summary_text=summary
        )


class AuditReportGenerator:
    """Generates professional executive audit reports in HTML and Markdown."""

    @staticmethod
    def generate_html_report(
        result: AnalysisResult,
        gate: QualityGateResult,
        file_name: str = "project.py",
        generated_tests: str = ""
    ) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build issues rows
        issues_rows = ""
        for idx, issue in enumerate(result.issues, 1):
            sev_color = {
                "Critical": "#dc2626",
                "High": "#ea580c",
                "Medium": "#d97706",
                "Low": "#2563eb",
                "Info": "#0891b2"
            }.get(issue.severity.value, "#64748b")

            cwe_tag = f"<span class='badge' style='background:#1e293b; color:#94a3b8;'>{issue.cwe_id}</span>" if issue.cwe_id else ""

            issues_rows += f"""
            <tr>
                <td><strong>#{idx}</strong></td>
                <td><span class='badge' style='background:{sev_color}; color:#fff;'>{issue.severity.value}</span></td>
                <td><strong>{issue.title}</strong><br/><small style='color:#64748b;'>{issue.description}</small></td>
                <td>Line {issue.line_number}</td>
                <td>{cwe_tag}</td>
                <td><code style='color:#0284c7;'>{issue.suggestion}</code></td>
            </tr>
            """

        # Build conditions rows
        gate_rows = ""
        for cond in gate.conditions:
            status_badge = "<span style='color:#10b981; font-weight:bold;'>✓ PASSED</span>" if cond.passed else "<span style='color:#ef4444; font-weight:bold;'>✗ FAILED</span>"
            gate_rows += f"""
            <tr>
                <td><strong>{cond.name}</strong></td>
                <td>{cond.threshold}</td>
                <td>{cond.actual_value}</td>
                <td>{status_badge}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>BugIntel Executive Quality Audit Report — {file_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #f8fafc;
            color: #0f172a;
            line-height: 1.5;
            padding: 40px;
            margin: 0 auto;
            max-width: 1100px;
        }}
        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            padding: 30px 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ margin: 0; font-size: 26px; }}
        .header p {{ margin: 5px 0 0 0; color: #94a3b8; font-size: 14px; }}
        .gate-stamp {{
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 20px;
            font-weight: 800;
            background: {gate.color};
            color: #ffffff;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }}
        .card {{
            background: #ffffff;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #e2e8f0;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .card .val {{ font-size: 32px; font-weight: 800; margin-bottom: 4px; }}
        .card .lbl {{ font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: 600; }}
        h2 {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-top: 36px; font-size: 20px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
        }}
        th {{ background: #f1f5f9; font-weight: 700; color: #475569; }}
        .badge {{ padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }}
        code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
        .footer {{ text-align: center; color: #94a3b8; font-size: 12px; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔍 BugIntel Enterprise Quality Audit</h1>
            <p>Target: <strong>{file_name}</strong> | Generated: {date_str}</p>
        </div>
        <div class="gate-stamp">{gate.badge_icon} {gate.status}</div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="val" style="color:#ef4444;">{result.risk_score}</div>
            <div class="lbl">Risk Score (0-10)</div>
        </div>
        <div class="card">
            <div class="val" style="color:#0284c7;">{len(result.issues)}</div>
            <div class="lbl">Total Defects</div>
        </div>
        <div class="card">
            <div class="val" style="color:#dc2626;">{sum(1 for i in result.issues if i.severity == Severity.CRITICAL)}</div>
            <div class="lbl">Critical Vulnerabilities</div>
        </div>
        <div class="card">
            <div class="val" style="color:#8b5cf6;">{result.lines_of_code}</div>
            <div class="lbl">Lines of Code</div>
        </div>
    </div>

    <h2>🛡️ Quality Gate Criteria Evaluation</h2>
    <table>
        <thead>
            <tr><th>Condition</th><th>Threshold</th><th>Actual</th><th>Gate Status</th></tr>
        </thead>
        <tbody>
            {gate_rows}
        </tbody>
    </table>

    <h2>📋 Detailed Defect & Vulnerability Register</h2>
    <table>
        <thead>
            <tr><th>ID</th><th>Severity</th><th>Defect & Details</th><th>Location</th><th>Standard</th><th>Remediation</th></tr>
        </thead>
        <tbody>
            {issues_rows}
        </tbody>
    </table>

    <div class="footer">
        Generated by BugIntel AI Code Quality Platform — OWASP Top 10 & Enterprise Static Analysis
    </div>
</body>
</html>
"""
        return html

    @staticmethod
    def generate_markdown_report(result: AnalysisResult, gate: QualityGateResult, file_name: str) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# 🔍 BugIntel Quality Audit Report",
            f"**File:** `{file_name}` | **Generated:** {date_str} | **Gate Status:** {gate.badge_icon} **{gate.status}**",
            "",
            "## 📊 Executive Summary",
            f"- **Overall Risk Score:** {result.risk_score}/10",
            f"- **Total Detected Defects:** {len(result.issues)}",
            f"- **Critical Vulnerabilities:** {sum(1 for i in result.issues if i.severity == Severity.CRITICAL)}",
            f"- **Lines of Code:** {result.lines_of_code}",
            f"- **Gate Evaluation:** {gate.summary_text}",
            "",
            "## 🛡️ Quality Gate Evaluation",
            "| Rule | Threshold | Measured Value | Result |",
            "| :--- | :--- | :--- | :--- |"
        ]
        for c in gate.conditions:
            st = "✅ PASSED" if c.passed else "❌ FAILED"
            lines.append(f"| {c.name} | {c.threshold} | {c.actual_value} | {st} |")

        lines.extend([
            "",
            "## 🐛 Defect Register",
            "| # | Severity | Category | Title | Line | Remediation |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |"
        ])
        for idx, i in enumerate(result.issues, 1):
            lines.append(f"| {idx} | {i.severity.value} | {i.category.value} | {i.title} | Line {i.line_number} | {i.suggestion} |")

        return "\n".join(lines)
