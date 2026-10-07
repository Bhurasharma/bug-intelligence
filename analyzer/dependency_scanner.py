"""
Dependency & Supply-Chain Security Scanner
Aligns with OWASP Top 10 (2025) - A06: Software Supply Chain & Vulnerable Dependencies.
Detects vulnerable libraries, outdated versions, typosquatting, unpinned dependencies, and security advisories.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


class VulnerabilitySeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class Vulnerability:
    cve_id: str
    package: str
    affected_spec: str
    fixed_in: str
    severity: VulnerabilitySeverity
    title: str
    description: str
    remediation: str
    cvss_score: float = 7.5


@dataclass
class DependencyItem:
    name: str
    specifier: str
    pinned_version: Optional[str]
    is_pinned: bool
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    license: str = "MIT"
    risk_level: str = "Low"


@dataclass
class DependencyAuditResult:
    dependencies: List[DependencyItem] = field(default_factory=list)
    total_packages: int = 0
    vulnerable_packages: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    supply_chain_risk_score: float = 0.0
    unpinned_count: int = 0
    recommendations: List[str] = field(default_factory=list)


# Known Python Vulnerability Database (Advisories & CVEs)
KNOWN_VULNERABILITIES = [
    {
        "package": "requests",
        "bad_versions": ["<2.31.0", "<=2.30.0", "<=2.28.0", "<=2.25.0"],
        "cve": "CVE-2023-32681",
        "severity": VulnerabilitySeverity.HIGH,
        "title": "Proxy-Authorization Header Leak to HTTPS Destination",
        "description": "Requests leaks Proxy-Authorization headers to destination servers when following HTTPS redirects.",
        "fixed_in": "2.31.0",
        "cvss": 7.5,
        "remediation": "Upgrade `requests` to >= 2.31.0 in requirements.txt"
    },
    {
        "package": "urllib3",
        "bad_versions": ["<2.0.7", "<1.26.18", "<=1.26.15"],
        "cve": "CVE-2023-45803",
        "severity": VulnerabilitySeverity.HIGH,
        "title": "Cookie and Auth Header Leak on Redirect",
        "description": "urllib3 does not remove HTTP request bodies and credentials during 303 See Other redirects.",
        "fixed_in": "2.0.7 / 1.26.18",
        "cvss": 7.8,
        "remediation": "Upgrade `urllib3` to >= 2.0.7 or 1.26.18"
    },
    {
        "package": "flask",
        "bad_versions": ["<2.2.5", "<=2.0.3", "<=1.1.4"],
        "cve": "CVE-2023-30861",
        "severity": VulnerabilitySeverity.HIGH,
        "title": "Session Cookie Disclosure via Cache Poisoning",
        "description": "Flask session cookies lack proper Cache-Control response headers allowing proxy caching.",
        "fixed_in": "2.2.5 / 2.3.2",
        "cvss": 7.5,
        "remediation": "Upgrade `flask` to >= 2.2.5"
    },
    {
        "package": "django",
        "bad_versions": ["<4.2.8", "<=4.1.13", "<=3.2.23", "<=4.0.0"],
        "cve": "CVE-2023-46695",
        "severity": VulnerabilitySeverity.CRITICAL,
        "title": "Potential Denial of Service via Username Regex",
        "description": "NFKC normalization in django.contrib.auth.forms allows unbounded CPU consumption via ReDoS.",
        "fixed_in": "4.2.8 / 3.2.24",
        "cvss": 9.1,
        "remediation": "Upgrade `django` to >= 4.2.8 or 5.0+"
    },
    {
        "package": "cryptography",
        "bad_versions": ["<41.0.6", "<=40.0.2", "<=39.0.0", "<=3.4.8"],
        "cve": "CVE-2023-49083",
        "severity": VulnerabilitySeverity.CRITICAL,
        "title": "NULL Pointer Dereference in PKCS7 Certificate Parsing",
        "description": "Calling load_pem_pkcs7_certificates with malformed certificates leads to remote crash or DoS.",
        "fixed_in": "41.0.6",
        "cvss": 9.3,
        "remediation": "Upgrade `cryptography` to >= 41.0.6"
    },
    {
        "package": "pyyaml",
        "bad_versions": ["<5.4", "<=5.3.1", "<=5.1"],
        "cve": "CVE-2020-14343",
        "severity": VulnerabilitySeverity.CRITICAL,
        "title": "Arbitrary Code Execution via Insecure Deserialization",
        "description": "Insecure default loader allows arbitrary Python code execution through custom tags.",
        "fixed_in": "5.4 / 6.0",
        "cvss": 9.8,
        "remediation": "Upgrade `pyyaml` to >= 6.0 and enforce `yaml.safe_load()`"
    },
    {
        "package": "pillow",
        "bad_versions": ["<10.2.0", "<=10.0.1", "<=9.5.0"],
        "cve": "CVE-2023-50447",
        "severity": VulnerabilitySeverity.HIGH,
        "title": "Arbitrary Code Execution via ImageMath.eval",
        "description": "Environment variable and built-in function leak permits command execution.",
        "fixed_in": "10.2.0",
        "cvss": 8.1,
        "remediation": "Upgrade `pillow` to >= 10.2.0"
    },
    {
        "package": "jinja2",
        "bad_versions": ["<3.1.3", "<=3.0.3", "<=2.11.3"],
        "cve": "CVE-2024-22195",
        "severity": VulnerabilitySeverity.MEDIUM,
        "title": "Server-Side Template Injection (SSTI) / XSS in xmlattr filter",
        "description": "xmlattr filter allows key attribute values with special characters, resulting in attribute injection.",
        "fixed_in": "3.1.3",
        "cvss": 6.1,
        "remediation": "Upgrade `jinja2` to >= 3.1.3"
    },
    {
        "package": "werkzeug",
        "bad_versions": ["<3.0.3", "<=2.3.8", "<=2.2.2"],
        "cve": "CVE-2024-34069",
        "severity": VulnerabilitySeverity.HIGH,
        "title": "Remote Code Execution via Debugger PIN Brute-force",
        "description": "Debugger console PIN algorithm insufficient to prevent automated local brute-force attacks.",
        "fixed_in": "3.0.3",
        "cvss": 7.5,
        "remediation": "Upgrade `werkzeug` to >= 3.0.3 and disable debugger in production"
    },
    {
        "package": "numpy",
        "bad_versions": ["<1.22.0", "<=1.21.5"],
        "cve": "CVE-2021-41496",
        "severity": VulnerabilitySeverity.MEDIUM,
        "title": "Buffer Overflow in array_from_pyobj",
        "description": "Buffer overflow issue in numpy allows remote attackers to cause a denial of service.",
        "fixed_in": "1.22.0",
        "cvss": 6.5,
        "remediation": "Upgrade `numpy` to >= 1.22.0"
    },
    {
        "package": "sqlparse",
        "bad_versions": ["<0.5.0", "<=0.4.4"],
        "cve": "CVE-2024-4340",
        "severity": VulnerabilitySeverity.HIGH,
        "title": "Recursion Depth Limit Bypass / DoS via Nested SQL",
        "description": "Parsing heavily nested comments or brackets causes unchecked stack recursion exhaustion.",
        "fixed_in": "0.5.0",
        "cvss": 7.5,
        "remediation": "Upgrade `sqlparse` to >= 0.5.0"
    },
]

# Common typosquatting targets in the Python ecosystem
POPULAR_PACKAGES = {
    "requests": ["reqeusts", "requets", "request-py", "python-requests"],
    "urllib3": ["urllib-3", "urlib3", "urllib4"],
    "numpy": ["nummpy", "num-py", "numpyy"],
    "colorama": ["colourama", "color-ama"],
    "cryptography": ["cryptografy", "crypto-graphy"],
    "pandas": ["panda", "pan-das", "python-pandas"],
    "flask": ["flsk", "pyflask"],
    "django": ["djagno", "dj-ango"],
    "pydantic": ["py-dantic", "pydantc"],
}


class DependencyScanner:
    """Scans Python dependencies and requirements for vulnerabilities and supply-chain threats."""

    def parse_requirements_content(self, content: str) -> List[Tuple[str, str, Optional[str]]]:
        """
        Parses requirements.txt lines.
        Returns list of (package_name, raw_specifier, pinned_version_if_any).
        """
        parsed = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-i"):
                continue

            # Remove inline comments
            line = line.split("#")[0].strip()

            # Match standard pip specs: package==1.2.3, package>=1.2.0, package~=1.0, etc.
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*)?$", line)
            if match:
                pkg = match.group(1).lower().replace("_", "-")
                spec = match.group(2).strip() if match.group(2) else ""
                pinned_ver = None

                # Extract exact version if pinned with ==
                pin_match = re.search(r"==\s*([0-9a-zA-Z\.\-]+)", spec)
                if pin_match:
                    pinned_ver = pin_match.group(1)

                parsed.append((pkg, spec, pinned_ver))
        return parsed

    def extract_imports_from_code(self, source_code: str) -> List[str]:
        """Extracts top-level module names imported in python code."""
        modules = set()
        for line in source_code.splitlines():
            line = line.strip()
            # import foo, bar
            m1 = re.match(r"^import\s+([a-zA-Z0-9_,\s]+)", line)
            if m1:
                parts = m1.group(1).split(",")
                for p in parts:
                    clean = p.strip().split()[0].split(".")[0]
                    if clean:
                        modules.add(clean.lower())
            # from foo import bar
            m2 = re.match(r"^from\s+([a-zA-Z0-9_\.]+)\s+import", line)
            if m2:
                clean = m2.group(1).split(".")[0]
                if clean:
                    modules.add(clean.lower())
        return sorted(list(modules))

    def scan(self, requirements_content: str = "", source_code: str = "") -> DependencyAuditResult:
        """Runs full supply chain and dependency security analysis."""
        audit = DependencyAuditResult()
        dep_items: Dict[str, DependencyItem] = {}

        # 1. Parse requirements if supplied
        if requirements_content:
            raw_deps = self.parse_requirements_content(requirements_content)
            for pkg, spec, pinned in raw_deps:
                is_pinned = bool(pinned)
                dep_items[pkg] = DependencyItem(
                    name=pkg,
                    specifier=spec or "unpinned",
                    pinned_version=pinned,
                    is_pinned=is_pinned
                )
        elif source_code:
            # Fall back to extracting imported packages
            imported = self.extract_imports_from_code(source_code)
            # Filter standard library
            stdlib = {
                "os", "sys", "re", "math", "json", "time", "datetime", "ast",
                "collections", "itertools", "functools", "pathlib", "typing",
                "random", "urllib", "sqlite3", "io", "subprocess", "logging",
                "dataclasses", "enum", "textwrap", "hashlib", "shutil", "tempfile",
                "unittest", "threading", "multiprocessing", "socket", "ssl", "copy"
            }
            for mod in imported:
                if mod not in stdlib:
                    pkg_name = mod.replace("_", "-")
                    dep_items[pkg_name] = DependencyItem(
                        name=pkg_name,
                        specifier="imported (inferred)",
                        pinned_version=None,
                        is_pinned=False
                    )

        # 2. Check for known CVEs
        for pkg_name, item in dep_items.items():
            for vuln_db in KNOWN_VULNERABILITIES:
                if vuln_db["package"] == pkg_name:
                    # Check version match or assume potential match if unpinned
                    match = False
                    if not item.is_pinned:
                        # Unpinned means high probability of pulling vulnerable version or breaking changes
                        match = True
                    elif item.pinned_version:
                        # Simple prefix / heuristic check
                        ver = item.pinned_version
                        for bad in vuln_db["bad_versions"]:
                            clean_bad = bad.lstrip("<=>")
                            if ver.startswith(clean_bad.split(".")[0]):
                                match = True
                                break

                    if match:
                        vuln = Vulnerability(
                            cve_id=vuln_db["cve"],
                            package=pkg_name,
                            affected_spec=", ".join(vuln_db["bad_versions"]),
                            fixed_in=vuln_db["fixed_in"],
                            severity=vuln_db["severity"],
                            title=vuln_db["title"],
                            description=vuln_db["description"],
                            remediation=vuln_db["remediation"],
                            cvss_score=vuln_db["cvss"]
                        )
                        item.vulnerabilities.append(vuln)

            # Check Typosquatting
            for canon, typos in POPULAR_PACKAGES.items():
                if pkg_name in typos:
                    vuln = Vulnerability(
                        cve_id="TYPOSQUAT-ALERT",
                        package=pkg_name,
                        affected_spec="all",
                        fixed_in=canon,
                        severity=VulnerabilitySeverity.CRITICAL,
                        title=f"Potential Malicious Typosquatting Package: {pkg_name}",
                        description=f"Package name '{pkg_name}' closely mimics trusted library '{canon}'. Attackers publish typosquat packages to execute arbitrary reverse shells during pip install.",
                        remediation=f"Replace `{pkg_name}` immediately with genuine package `{canon}`.",
                        cvss_score=9.8
                    )
                    item.vulnerabilities.append(vuln)

            # Assign risk level
            if any(v.severity == VulnerabilitySeverity.CRITICAL for v in item.vulnerabilities):
                item.risk_level = "Critical"
            elif any(v.severity == VulnerabilitySeverity.HIGH for v in item.vulnerabilities):
                item.risk_level = "High"
            elif any(v.severity == VulnerabilitySeverity.MEDIUM for v in item.vulnerabilities):
                item.risk_level = "Medium"
            elif not item.is_pinned:
                item.risk_level = "Medium"
            else:
                item.risk_level = "Low"

        audit.dependencies = list(dep_items.values())
        audit.total_packages = len(audit.dependencies)
        audit.unpinned_count = sum(1 for d in audit.dependencies if not d.is_pinned)

        # Aggregate counts
        for d in audit.dependencies:
            if d.vulnerabilities:
                audit.vulnerable_packages += 1
                for v in d.vulnerabilities:
                    audit.total_vulnerabilities += 1
                    if v.severity == VulnerabilitySeverity.CRITICAL:
                        audit.critical_count += 1
                    elif v.severity == VulnerabilitySeverity.HIGH:
                        audit.high_count += 1
                    elif v.severity == VulnerabilitySeverity.MEDIUM:
                        audit.medium_count += 1

        # Calculate Supply-Chain Risk Score (0 - 10)
        base = 0.0
        base += audit.critical_count * 3.5
        base += audit.high_count * 2.0
        base += audit.medium_count * 0.8
        base += audit.unpinned_count * 0.5
        audit.supply_chain_risk_score = min(10.0, round(base, 1))

        # Recommendations
        if audit.critical_count > 0:
            audit.recommendations.append("URGENT: Remediate critical CVEs & potential typosquat packages immediately before deploying.")
        if audit.unpinned_count > 0:
            audit.recommendations.append(f"Pin {audit.unpinned_count} unpinned dependencies to exact versions (e.g. `package==1.2.3`) to prevent supply-chain drift & unexpected breaking releases.")
        if audit.high_count > 0:
            audit.recommendations.append("Update high-severity transitive networking & serialization dependencies (e.g. requests, urllib3, pyyaml).")
        if not audit.recommendations:
            audit.recommendations.append("All scanned dependencies meet baseline OWASP supply-chain hygiene standards.")

        return audit
