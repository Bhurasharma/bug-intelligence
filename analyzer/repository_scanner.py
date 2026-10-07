"""
Repository & Multi-File Scanner Module
Supports scanning entire directories, multi-file uploads, and ZIP archives.
Calculates repository-wide health score, cross-file import graph, and hot-spot rankings.
"""

import os
import zipfile
import io
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from analyzer.static_analyzer import StaticAnalyzer, AnalysisResult, Severity


@dataclass
class FileAuditSummary:
    file_path: str
    lines_of_code: int
    issue_count: int
    critical_count: int
    high_count: int
    risk_score: float
    max_complexity: int
    result: AnalysisResult


@dataclass
class RepositoryAuditResult:
    total_files: int = 0
    total_loc: int = 0
    total_issues: int = 0
    total_critical: int = 0
    total_high: int = 0
    average_risk_score: float = 0.0
    highest_risk_file: str = ""
    file_summaries: List[FileAuditSummary] = field(default_factory=list)
    import_graph: Dict[str, List[str]] = field(default_factory=dict)
    file_results: Dict[str, AnalysisResult] = field(default_factory=dict)
    file_sources: Dict[str, str] = field(default_factory=dict)


class RepositoryScanner:
    """Scans multi-file Python projects and archives."""

    def __init__(self):
        self.analyzer = StaticAnalyzer()

    def scan_files(self, file_dict: Dict[str, str]) -> RepositoryAuditResult:
        """
        Scans a dictionary mapping file_path -> file_content.
        """
        repo_result = RepositoryAuditResult()
        repo_result.file_sources = file_dict

        total_risk = 0.0

        for path, code in file_dict.items():
            # Analyze each file
            analysis = self.analyzer.analyze(code, file_path=path)
            repo_result.file_results[path] = analysis

            crit = sum(1 for i in analysis.issues if i.severity == Severity.CRITICAL)
            high = sum(1 for i in analysis.issues if i.severity == Severity.HIGH)
            max_comp = max((v.get('complexity', 0) for v in analysis.complexity.values()), default=1)

            summary = FileAuditSummary(
                file_path=path,
                lines_of_code=analysis.lines_of_code,
                issue_count=len(analysis.issues),
                critical_count=crit,
                high_count=high,
                risk_score=analysis.risk_score,
                max_complexity=max_comp,
                result=analysis
            )
            repo_result.file_summaries.append(summary)

            repo_result.total_files += 1
            repo_result.total_loc += analysis.lines_of_code
            repo_result.total_issues += len(analysis.issues)
            repo_result.total_critical += crit
            repo_result.total_high += high
            total_risk += analysis.risk_score

            # Build simple import graph
            imports = []
            for line in code.splitlines():
                line = line.strip()
                if line.startswith("import ") or line.startswith("from "):
                    imports.append(line.split()[1].split(".")[0])
            repo_result.import_graph[path] = list(set(imports))

        if repo_result.total_files > 0:
            repo_result.average_risk_score = round(total_risk / repo_result.total_files, 1)

        # Sort files by risk score descending
        repo_result.file_summaries.sort(key=lambda x: (x.critical_count, x.risk_score), reverse=True)
        if repo_result.file_summaries:
            repo_result.highest_risk_file = repo_result.file_summaries[0].file_path

        return repo_result

    def scan_zip(self, zip_bytes: bytes) -> RepositoryAuditResult:
        """Extracts and scans all python files in a ZIP archive."""
        files = {}
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for name in z.namelist():
                # Filter out non-python or internal files
                if name.endswith(".py") and not any(part in name for part in ["__pycache__", ".git", "venv", ".env", "egg-info"]):
                    try:
                        content = z.read(name).decode("utf-8", errors="replace")
                        files[name] = content
                    except Exception:
                        pass
        return self.scan_files(files)
