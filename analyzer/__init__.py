# analyzer/__init__.py
"""Code analysis engine for Bug Intelligence Platform."""

from .static_analyzer import StaticAnalyzer, Severity, IssueCategory, Issue, AnalysisResult
from .test_generator import TestGenerator
from .ai_engine import get_ai_analysis, get_fix_suggestion, chat_with_code
from .dependency_scanner import DependencyScanner, DependencyAuditResult
from .quality_gate import QualityGate, AuditReportGenerator, QualityGateResult
from .repository_scanner import RepositoryScanner, RepositoryAuditResult

__all__ = [
    "StaticAnalyzer",
    "Severity",
    "IssueCategory",
    "Issue",
    "AnalysisResult",
    "TestGenerator",
    "get_ai_analysis",
    "get_fix_suggestion",
    "chat_with_code",
    "DependencyScanner",
    "DependencyAuditResult",
    "QualityGate",
    "AuditReportGenerator",
    "QualityGateResult",
    "RepositoryScanner",
    "RepositoryAuditResult",
]
