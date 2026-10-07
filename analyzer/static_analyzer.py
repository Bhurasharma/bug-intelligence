"""
Static Code Analyzer Module
Performs AST-based analysis to detect potential bugs, code smells, and risky patterns.
"""

import ast
import re
import textwrap
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class IssueCategory(Enum):
    BUG = "Bug"
    CODE_SMELL = "Code Smell"
    SECURITY = "Security"
    PERFORMANCE = "Performance"
    MAINTAINABILITY = "Maintainability"
    RELIABILITY = "Reliability"


@dataclass
class Issue:
    """Represents a detected code issue."""
    id: str
    title: str
    description: str
    category: IssueCategory
    severity: Severity
    file_path: str
    line_number: int
    end_line: Optional[int] = None
    code_snippet: str = ""
    suggestion: str = ""
    confidence: float = 0.0
    cwe_id: Optional[str] = None
    rule_id: str = ""
    root_cause: str = ""
    fix_example: str = ""


@dataclass
class AnalysisResult:
    """Complete analysis result for a source file."""
    file_path: str
    issues: List[Issue] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    risk_score: float = 0.0
    lines_of_code: int = 0
    complexity: dict = field(default_factory=dict)


class StaticAnalyzer:
    """AST-based static code analyzer for Python source files."""

    def __init__(self):
        self.issue_counter = 0

    def _next_id(self) -> str:
        self.issue_counter += 1
        return f"BUG-{self.issue_counter:04d}"

    def analyze(self, source_code: str, file_path: str = "<input>") -> AnalysisResult:
        """Run full static analysis on Python source code."""
        result = AnalysisResult(file_path=file_path)
        lines = source_code.split('\n')
        result.lines_of_code = len([l for l in lines if l.strip() and not l.strip().startswith('#')])

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            result.issues.append(Issue(
                id=self._next_id(),
                title="Syntax Error",
                description=f"File contains a syntax error: {e.msg}",
                category=IssueCategory.BUG,
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=e.lineno or 1,
                code_snippet=lines[e.lineno - 1] if e.lineno and e.lineno <= len(lines) else "",
                suggestion="Fix the syntax error before further analysis.",
                confidence=1.0,
                rule_id="SYN001",
                root_cause=f"Python parser encountered unexpected token: {e.msg}"
            ))
            result.risk_score = 10.0
            return result

        # Run all detectors
        result.issues.extend(self._detect_bare_except(tree, lines, file_path))
        result.issues.extend(self._detect_mutable_defaults(tree, lines, file_path))
        result.issues.extend(self._detect_unused_variables(tree, lines, file_path))
        result.issues.extend(self._detect_shadowed_builtins(tree, lines, file_path))
        result.issues.extend(self._detect_unreachable_code(tree, lines, file_path))
        result.issues.extend(self._detect_empty_except(tree, lines, file_path))
        result.issues.extend(self._detect_hardcoded_secrets(lines, file_path))
        result.issues.extend(self._detect_sql_injection(tree, lines, file_path))
        result.issues.extend(self._detect_infinite_loops(tree, lines, file_path))
        result.issues.extend(self._detect_type_comparison(tree, lines, file_path))
        result.issues.extend(self._detect_global_usage(tree, lines, file_path))
        result.issues.extend(self._detect_nested_complexity(tree, lines, file_path))
        result.issues.extend(self._detect_resource_leaks(tree, lines, file_path))
        result.issues.extend(self._detect_assertion_in_production(tree, lines, file_path))
        result.issues.extend(self._detect_eval_exec(tree, lines, file_path))
        result.issues.extend(self._detect_deprecated_patterns(tree, lines, file_path))
        result.issues.extend(self._detect_comparison_issues(tree, lines, file_path))
        result.issues.extend(self._detect_missing_return(tree, lines, file_path))
        result.issues.extend(self._detect_broad_imports(tree, lines, file_path))
        result.issues.extend(self._detect_insecure_crypto(tree, lines, file_path))
        result.issues.extend(self._detect_insecure_deserialization(tree, lines, file_path))
        result.issues.extend(self._detect_command_injection(tree, lines, file_path))
        result.issues.extend(self._detect_unverified_ssl(tree, lines, file_path))
        result.issues.extend(self._detect_http_without_timeout(tree, lines, file_path))
        result.issues.extend(self._detect_mutation_during_iteration(tree, lines, file_path))
        result.issues.extend(self._detect_string_concat_in_loop(tree, lines, file_path))
        result.issues.extend(self._detect_duplicate_dict_keys(tree, lines, file_path))
        result.issues.extend(self._detect_excessive_arguments(tree, lines, file_path))

        # Calculate metrics
        result.metrics = self._calculate_metrics(tree, source_code)
        result.complexity = self._calculate_complexity(tree)
        result.risk_score = self._calculate_risk_score(result)

        return result

    def _get_snippet(self, lines: list, lineno: int, context: int = 2) -> str:
        start = max(0, lineno - context - 1)
        end = min(len(lines), lineno + context)
        snippet_lines = []
        for i in range(start, end):
            marker = "→ " if i == lineno - 1 else "  "
            snippet_lines.append(f"{marker}{i+1:4d} | {lines[i]}")
        return '\n'.join(snippet_lines)

    def _detect_bare_except(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                issues.append(Issue(
                    id=self._next_id(),
                    title="Bare except clause",
                    description="Using a bare `except:` catches all exceptions including SystemExit and KeyboardInterrupt, which can hide real errors and make debugging extremely difficult.",
                    category=IssueCategory.RELIABILITY,
                    severity=Severity.HIGH,
                    file_path=fp,
                    line_number=node.lineno,
                    code_snippet=self._get_snippet(lines, node.lineno),
                    suggestion="Catch specific exceptions: `except (ValueError, TypeError) as e:` or at minimum `except Exception as e:`",
                    confidence=0.95,
                    cwe_id="CWE-396",
                    rule_id="REL001",
                    root_cause="Bare except catches all exception types including system-level exceptions that should propagate.",
                    fix_example="# Before:\ntry:\n    risky_op()\nexcept:\n    pass\n\n# After:\ntry:\n    risky_op()\nexcept (ValueError, IOError) as e:\n    logger.error(f'Operation failed: {e}')"
                ))
        return issues

    def _detect_mutable_defaults(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        mtype = type(default).__name__.lower()
                        issues.append(Issue(
                            id=self._next_id(),
                            title="Mutable default argument",
                            description=f"Function `{node.name}` uses a mutable {mtype} as a default argument. This object is shared across all calls, causing unexpected behavior.",
                            category=IssueCategory.BUG,
                            severity=Severity.HIGH,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion=f"Use `None` as default and create the {mtype} inside the function body.",
                            confidence=0.98,
                            cwe_id="CWE-1188",
                            rule_id="BUG001",
                            root_cause=f"Python evaluates default arguments once at function definition time. A mutable {mtype} default is shared across all invocations.",
                            fix_example=f"# Before:\ndef func(items=[]):\n    items.append(1)\n    return items\n\n# After:\ndef func(items=None):\n    if items is None:\n        items = []\n    items.append(1)\n    return items"
                        ))
        return issues

    def _detect_unused_variables(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assigned = {}
                used = set()
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name) and not target.id.startswith('_'):
                                assigned[target.id] = child.lineno
                    elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                        used.add(child.id)
                for var, lineno in assigned.items():
                    if var not in used and var not in ('self', 'cls'):
                        issues.append(Issue(
                            id=self._next_id(),
                            title=f"Unused variable `{var}`",
                            description=f"Variable `{var}` is assigned in function `{node.name}` but never used. This may indicate dead code or a logic error.",
                            category=IssueCategory.CODE_SMELL,
                            severity=Severity.LOW,
                            file_path=fp,
                            line_number=lineno,
                            code_snippet=self._get_snippet(lines, lineno),
                            suggestion=f"Remove the unused variable or prefix with underscore `_{var}` to indicate it's intentionally unused.",
                            confidence=0.75,
                            rule_id="CS001",
                            root_cause="Variable was assigned but never referenced later in the scope."
                        ))
        return issues

    def _detect_shadowed_builtins(self, tree, lines, fp) -> List[Issue]:
        issues = []
        builtins_set = {'list', 'dict', 'set', 'str', 'int', 'float', 'bool', 'tuple',
                        'type', 'id', 'input', 'print', 'len', 'range', 'map', 'filter',
                        'zip', 'sum', 'min', 'max', 'abs', 'open', 'file', 'hash',
                        'format', 'object', 'iter', 'next', 'sorted', 'reversed',
                        'enumerate', 'all', 'any', 'chr', 'ord', 'hex', 'bin', 'oct'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in builtins_set:
                        issues.append(Issue(
                            id=self._next_id(),
                            title=f"Shadowed built-in `{target.id}`",
                            description=f"Variable `{target.id}` shadows the Python built-in `{target.id}()`. This can cause hard-to-find bugs when the built-in is needed later.",
                            category=IssueCategory.BUG,
                            severity=Severity.MEDIUM,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion=f"Rename the variable to avoid shadowing: e.g., `{target.id}_value`, `my_{target.id}`, or `_{target.id}`.",
                            confidence=0.85,
                            cwe_id="CWE-710",
                            rule_id="BUG002",
                            root_cause=f"Assignment overwrites the built-in `{target.id}` in the local/global scope."
                        ))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    if arg.arg in builtins_set:
                        issues.append(Issue(
                            id=self._next_id(),
                            title=f"Parameter shadows built-in `{arg.arg}`",
                            description=f"Function parameter `{arg.arg}` in `{node.name}` shadows the Python built-in `{arg.arg}()`.",
                            category=IssueCategory.BUG,
                            severity=Severity.MEDIUM,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion=f"Rename the parameter to avoid shadowing.",
                            confidence=0.85,
                            rule_id="BUG003",
                            root_cause=f"Function parameter name collides with Python built-in `{arg.arg}`."
                        ))
        return issues

    def _detect_unreachable_code(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
                for i, stmt in enumerate(body):
                    if isinstance(stmt, ast.Return) and i < len(body) - 1:
                        next_stmt = body[i + 1]
                        issues.append(Issue(
                            id=self._next_id(),
                            title="Unreachable code after return",
                            description=f"Code after `return` statement in function `{node.name}` will never execute.",
                            category=IssueCategory.BUG,
                            severity=Severity.MEDIUM,
                            file_path=fp,
                            line_number=next_stmt.lineno,
                            code_snippet=self._get_snippet(lines, next_stmt.lineno),
                            suggestion="Remove the unreachable code or restructure the function logic.",
                            confidence=0.92,
                            cwe_id="CWE-561",
                            rule_id="BUG004",
                            root_cause="A return statement exits the function; subsequent statements are dead code."
                        ))
                        break
        return issues

    def _detect_empty_except(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    issues.append(Issue(
                        id=self._next_id(),
                        title="Exception silently swallowed",
                        description="Exception is caught and silently ignored with `pass`. Errors will go unnoticed, making debugging very difficult.",
                        category=IssueCategory.RELIABILITY,
                        severity=Severity.HIGH,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion="At minimum, log the exception: `except Exception as e: logger.warning(f'Handled: {e}')`",
                        confidence=0.90,
                        cwe_id="CWE-390",
                        rule_id="REL002",
                        root_cause="Empty except block prevents error propagation and hides failures.",
                        fix_example="# Before:\ntry:\n    process()\nexcept Exception:\n    pass\n\n# After:\ntry:\n    process()\nexcept Exception as e:\n    logger.warning(f'Non-critical error: {e}')"
                    ))
        return issues

    def _detect_hardcoded_secrets(self, lines, fp) -> List[Issue]:
        issues = []
        secret_patterns = [
            (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', "password"),
            (r'(?i)(api_key|apikey|api_secret)\s*=\s*["\'][^"\']+["\']', "API key"),
            (r'(?i)(secret_key|secret)\s*=\s*["\'][^"\']+["\']', "secret key"),
            (r'(?i)(token|auth_token|access_token)\s*=\s*["\'][a-zA-Z0-9_\-\.]{10,}["\']', "token"),
            (r'(?i)(aws_access_key_id)\s*=\s*["\']AKIA[A-Z0-9]{16}["\']', "AWS access key"),
        ]
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
                continue
            for pattern, secret_type in secret_patterns:
                if re.search(pattern, line):
                    # Skip if it's a placeholder or env variable lookup
                    if any(x in line.lower() for x in ['os.environ', 'getenv', 'placeholder', 'xxx', 'changeme', 'your_', '<', '>']):
                        continue
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Hardcoded {secret_type} detected",
                        description=f"A {secret_type} appears to be hardcoded in the source code. This is a serious security risk if the code is shared or committed to version control.",
                        category=IssueCategory.SECURITY,
                        severity=Severity.CRITICAL,
                        file_path=fp,
                        line_number=i + 1,
                        code_snippet=self._get_snippet(lines, i + 1),
                        suggestion=f"Move the {secret_type} to environment variables or a secrets manager: `os.environ.get('{secret_type.upper()}')`",
                        confidence=0.80,
                        cwe_id="CWE-798",
                        rule_id="SEC001",
                        root_cause=f"Sensitive {secret_type} stored directly in source code instead of secure configuration."
                    ))
                    break
        return issues

    def _detect_sql_injection(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
                    for arg in node.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                            issues.append(Issue(
                                id=self._next_id(),
                                title="Potential SQL injection vulnerability",
                                description="SQL query is constructed using string formatting (`%`). This is vulnerable to SQL injection attacks.",
                                category=IssueCategory.SECURITY,
                                severity=Severity.CRITICAL,
                                file_path=fp,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno),
                                suggestion="Use parameterized queries: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`",
                                confidence=0.88,
                                cwe_id="CWE-89",
                                rule_id="SEC002",
                                root_cause="User input directly concatenated into SQL query string without sanitization."
                            ))
                        elif isinstance(arg, ast.JoinedStr):
                            issues.append(Issue(
                                id=self._next_id(),
                                title="Potential SQL injection via f-string",
                                description="SQL query is constructed using f-string formatting. This is vulnerable to SQL injection attacks.",
                                category=IssueCategory.SECURITY,
                                severity=Severity.CRITICAL,
                                file_path=fp,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno),
                                suggestion="Use parameterized queries instead of f-strings in SQL statements.",
                                confidence=0.88,
                                cwe_id="CWE-89",
                                rule_id="SEC003",
                                root_cause="F-string interpolation in SQL allows injection of malicious SQL code."
                            ))
        return issues

    def _detect_infinite_loops(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    has_break = False
                    has_return = False
                    for child in ast.walk(node):
                        if isinstance(child, ast.Break):
                            has_break = True
                        if isinstance(child, ast.Return):
                            has_return = True
                    if not has_break and not has_return:
                        issues.append(Issue(
                            id=self._next_id(),
                            title="Potential infinite loop",
                            description="`while True` loop without a `break` or `return` statement may run indefinitely.",
                            category=IssueCategory.BUG,
                            severity=Severity.HIGH,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion="Add a break condition or use a bounded loop with a maximum iteration count.",
                            confidence=0.82,
                            cwe_id="CWE-835",
                            rule_id="BUG005",
                            root_cause="While True loop has no exit path (break/return) to terminate."
                        ))
        return issues

    def _detect_type_comparison(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for op in node.ops:
                    if isinstance(op, (ast.Eq, ast.NotEq)):
                        comparators = [node.left] + node.comparators
                        for comp in comparators:
                            if isinstance(comp, ast.Call) and isinstance(comp.func, ast.Name) and comp.func.id == 'type':
                                issues.append(Issue(
                                    id=self._next_id(),
                                    title="Direct type comparison",
                                    description="Using `type()` for comparison doesn't account for inheritance. Use `isinstance()` instead.",
                                    category=IssueCategory.CODE_SMELL,
                                    severity=Severity.MEDIUM,
                                    file_path=fp,
                                    line_number=node.lineno,
                                    code_snippet=self._get_snippet(lines, node.lineno),
                                    suggestion="Replace `type(x) == SomeType` with `isinstance(x, SomeType)`.",
                                    confidence=0.88,
                                    rule_id="CS002",
                                    root_cause="type() comparison breaks with inheritance; isinstance() handles subclasses correctly."
                                ))
                                break
        return issues

    def _detect_global_usage(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                issues.append(Issue(
                    id=self._next_id(),
                    title="Global variable usage",
                    description=f"Function uses `global` keyword for variables: `{', '.join(node.names)}`. Global mutable state makes code harder to test, debug, and reason about.",
                    category=IssueCategory.MAINTAINABILITY,
                    severity=Severity.MEDIUM,
                    file_path=fp,
                    line_number=node.lineno,
                    code_snippet=self._get_snippet(lines, node.lineno),
                    suggestion="Pass values as function parameters and return results instead of using global state.",
                    confidence=0.80,
                    rule_id="MT001",
                    root_cause="Global mutable state creates hidden dependencies between functions."
                ))
        return issues

    def _detect_nested_complexity(self, tree, lines, fp) -> List[Issue]:
        issues = []

        class NestingVisitor(ast.NodeVisitor):
            def __init__(self):
                self.depth = 0
                self.max_depth = 0
                self.issues_list = []

            def _enter_nesting(self, node):
                self.depth += 1
                if self.depth >= 4:
                    self.issues_list.append((node.lineno, self.depth))
                self.generic_visit(node)
                self.depth -= 1

            visit_If = _enter_nesting
            visit_For = _enter_nesting
            visit_While = _enter_nesting
            visit_With = _enter_nesting
            visit_Try = _enter_nesting

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visitor = NestingVisitor()
                visitor.visit(node)
                for lineno, depth in visitor.issues_list:
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Deeply nested code (depth {depth})",
                        description=f"Code in function `{node.name}` has nesting depth of {depth}. Deep nesting hurts readability and is often a sign of logic that should be refactored.",
                        category=IssueCategory.MAINTAINABILITY,
                        severity=Severity.MEDIUM if depth < 5 else Severity.HIGH,
                        file_path=fp,
                        line_number=lineno,
                        code_snippet=self._get_snippet(lines, lineno),
                        suggestion="Consider early returns, guard clauses, or extracting nested logic into helper functions.",
                        confidence=0.85,
                        rule_id="MT002",
                        root_cause=f"Control flow nesting depth of {depth} exceeds recommended maximum of 3."
                    ))
                    break  # Report once per function
        return issues

    def _detect_resource_leaks(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        if isinstance(node.value.func, ast.Name) and node.value.func.id == 'open':
                            # Check if inside a with statement
                            parent_is_with = False
                            for parent in ast.walk(tree):
                                if isinstance(parent, ast.With):
                                    for item in parent.items:
                                        if isinstance(item.context_expr, ast.Call):
                                            if isinstance(item.context_expr.func, ast.Name) and item.context_expr.func.id == 'open':
                                                parent_is_with = True
                            if not parent_is_with:
                                issues.append(Issue(
                                    id=self._next_id(),
                                    title="Potential resource leak",
                                    description=f"File opened with `open()` and assigned to `{target.id}` without using a `with` statement. The file may not be properly closed if an exception occurs.",
                                    category=IssueCategory.RELIABILITY,
                                    severity=Severity.MEDIUM,
                                    file_path=fp,
                                    line_number=node.lineno,
                                    code_snippet=self._get_snippet(lines, node.lineno),
                                    suggestion="Use a context manager: `with open(...) as f:`",
                                    confidence=0.80,
                                    cwe_id="CWE-404",
                                    rule_id="REL003",
                                    root_cause="File handle not managed by context manager; may leak if exception prevents explicit close().",
                                    fix_example="# Before:\nf = open('data.txt', 'r')\ndata = f.read()\nf.close()\n\n# After:\nwith open('data.txt', 'r') as f:\n    data = f.read()"
                                ))
        return issues

    def _detect_assertion_in_production(self, tree, lines, fp) -> List[Issue]:
        issues = []
        assert_count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                assert_count += 1
        if assert_count > 3:
            issues.append(Issue(
                id=self._next_id(),
                title="Heavy use of assert statements",
                description=f"File contains {assert_count} assert statements. Asserts are stripped when Python runs with `-O` flag, so they should not be used for input validation or security checks.",
                category=IssueCategory.RELIABILITY,
                severity=Severity.MEDIUM,
                file_path=fp,
                line_number=1,
                code_snippet="",
                suggestion="Use explicit validation with `if`/`raise` for production checks. Reserve `assert` for development-time invariants.",
                confidence=0.70,
                cwe_id="CWE-617",
                rule_id="REL004",
                root_cause="Assert statements are removed in optimized mode (-O), potentially disabling validation."
            ))
        return issues

    def _detect_eval_exec(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ('eval', 'exec'):
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Use of `{node.func.id}()` — code injection risk",
                        description=f"`{node.func.id}()` executes arbitrary code. If user input reaches this call, it enables Remote Code Execution (RCE).",
                        category=IssueCategory.SECURITY,
                        severity=Severity.CRITICAL,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion=f"Replace `{node.func.id}()` with safer alternatives: `ast.literal_eval()` for data, or explicit parsing for expressions.",
                        confidence=0.92,
                        cwe_id="CWE-95",
                        rule_id="SEC004",
                        root_cause=f"`{node.func.id}()` can execute arbitrary Python code, including malicious payloads."
                    ))
        return issues

    def _detect_deprecated_patterns(self, tree, lines, fp) -> List[Issue]:
        issues = []
        deprecated_modules = {
            'imp': 'importlib',
            'optparse': 'argparse',
            'formatter': 'None (removed in 3.10)',
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in deprecated_modules:
                        issues.append(Issue(
                            id=self._next_id(),
                            title=f"Deprecated module `{alias.name}`",
                            description=f"Module `{alias.name}` is deprecated. Use `{deprecated_modules[alias.name]}` instead.",
                            category=IssueCategory.MAINTAINABILITY,
                            severity=Severity.LOW,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion=f"Replace `import {alias.name}` with `import {deprecated_modules[alias.name]}`.",
                            confidence=0.95,
                            rule_id="MT003",
                            root_cause=f"Module `{alias.name}` is deprecated and may be removed in future Python versions."
                        ))
        return issues

    def _detect_comparison_issues(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for i, (op, comparator) in enumerate(zip(node.ops, node.comparators)):
                    if isinstance(op, (ast.Eq, ast.NotEq)):
                        if isinstance(comparator, ast.Constant) and comparator.value is None:
                            issues.append(Issue(
                                id=self._next_id(),
                                title="Comparison to None using == or !=",
                                description="Comparing to `None` using `==` or `!=` instead of `is` or `is not`. PEP 8 recommends identity checks for singletons.",
                                category=IssueCategory.CODE_SMELL,
                                severity=Severity.LOW,
                                file_path=fp,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno),
                                suggestion="Use `x is None` or `x is not None` instead.",
                                confidence=0.92,
                                rule_id="CS003",
                                root_cause="None is a singleton; `==` invokes __eq__ which may give incorrect results."
                            ))
                        elif isinstance(comparator, ast.Constant) and isinstance(comparator.value, bool):
                            issues.append(Issue(
                                id=self._next_id(),
                                title="Comparison to boolean literal",
                                description="Explicitly comparing to `True` or `False` is redundant. Use the value directly or negate with `not`.",
                                category=IssueCategory.CODE_SMELL,
                                severity=Severity.LOW,
                                file_path=fp,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno),
                                suggestion="Replace `if x == True:` with `if x:` and `if x == False:` with `if not x:`.",
                                confidence=0.90,
                                rule_id="CS004",
                                root_cause="Boolean comparison is verbose and can mask type-conversion bugs."
                            ))
        return issues

    def _detect_missing_return(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith('_') or node.name in ('__init__', '__del__', '__enter__', '__exit__',
                                                                 'setUp', 'tearDown', 'setup', 'teardown'):
                    continue
                has_return_value = False
                has_bare_return = False
                for child in ast.walk(node):
                    if isinstance(child, ast.Return):
                        if child.value is not None:
                            has_return_value = True
                        else:
                            has_bare_return = True
                if has_return_value and has_bare_return:
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Inconsistent return in `{node.name}`",
                        description=f"Function `{node.name}` has some return paths with values and others without. This causes `None` to be returned on some paths, which may be unexpected.",
                        category=IssueCategory.BUG,
                        severity=Severity.MEDIUM,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion="Ensure all return paths return a value, or explicitly return None where intended.",
                        confidence=0.78,
                        cwe_id="CWE-394",
                        rule_id="BUG006",
                        root_cause="Mixed return types make the function's contract ambiguous and error-prone."
                    ))
        return issues

    def _detect_broad_imports(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == '*':
                        issues.append(Issue(
                            id=self._next_id(),
                            title=f"Wildcard import from `{node.module}`",
                            description=f"Using `from {node.module} import *` imports all names, polluting the namespace and making it unclear where names come from.",
                            category=IssueCategory.MAINTAINABILITY,
                            severity=Severity.MEDIUM,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion=f"Import specific names: `from {node.module} import name1, name2`",
                            confidence=0.95,
                            rule_id="MT004",
                            root_cause="Wildcard imports make dependency tracking impossible and can shadow existing names."
                        ))
        return issues

    def _detect_insecure_crypto(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                
                if func_name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1"):
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Insecure cryptographic hash: {func_name}",
                        description=f"{func_name} is cryptographically broken and vulnerable to collision and preimage attacks.",
                        category=IssueCategory.SECURITY,
                        severity=Severity.HIGH,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion="Use modern collision-resistant algorithms: `hashlib.sha256()`, `hashlib.sha512()`, or `bcrypt`/`argon2` for passwords.",
                        confidence=0.95,
                        cwe_id="CWE-327",
                        rule_id="SEC003",
                        root_cause="Legacy hashing functions (MD5, SHA1) have proven collision attacks and must not be used for security-critical contexts.",
                        fix_example="# Before:\nhashlib.md5(password.encode()).hexdigest()\n\n# After:\nhashlib.sha256(data.encode()).hexdigest()  # For integrity"
                    ))
        return issues

    def _detect_insecure_deserialization(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_repr = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    call_repr = f"{node.func.value.id}.{node.func.attr}"
                
                if call_repr in ("pickle.loads", "pickle.load", "_pickle.loads", "marshal.loads", "shelve.open"):
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Insecure deserialization: {call_repr}",
                        description=f"`{call_repr}` can execute arbitrary bytecode during deserialization, allowing remote code execution (RCE) if data is user-controlled.",
                        category=IssueCategory.SECURITY,
                        severity=Severity.CRITICAL,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion="Use safe serialization formats like JSON (`json.loads`), Protocol Buffers, or HMAC-signed tokens.",
                        confidence=0.98,
                        cwe_id="CWE-502",
                        rule_id="SEC004",
                        root_cause="Python's pickle format is Turing-complete during unpacking via __reduce__.",
                        fix_example="# Before:\ndata = pickle.loads(raw_input)\n\n# After:\nimport json\ndata = json.loads(raw_input)"
                    ))
                elif call_repr == "yaml.load":
                    is_safe = False
                    for kw in node.keywords:
                        if kw.arg == "Loader" and "Safe" in getattr(kw.value, 'id', ''):
                            is_safe = True
                            break
                    if not is_safe:
                        issues.append(Issue(
                            id=self._next_id(),
                            title="Unsafe YAML loading: yaml.load without SafeLoader",
                            description="`yaml.load()` without SafeLoader allows arbitrary Python object instantiation and code execution.",
                            category=IssueCategory.SECURITY,
                            severity=Severity.CRITICAL,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion="Use `yaml.safe_load(stream)` instead of `yaml.load()`.",
                            confidence=0.95,
                            cwe_id="CWE-502",
                            rule_id="SEC004B",
                            root_cause="PyYAML full loader parses python object tags by default unless safe_load is used.",
                            fix_example="# Before:\nyaml.load(content)\n\n# After:\nyaml.safe_load(content)"
                        ))
        return issues

    def _detect_command_injection(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_str = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    call_str = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func, ast.Name):
                    call_str = node.func.id

                if call_str in ("os.system", "os.popen", "posix.system"):
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Command injection risk: {call_str}",
                        description=f"`{call_str}` invokes an OS shell directly. If arguments include untrusted input, attackers can execute arbitrary shell commands.",
                        category=IssueCategory.SECURITY,
                        severity=Severity.CRITICAL,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion="Use `subprocess.run(['cmd', arg1], shell=False, check=True)` with argument lists instead of raw shell strings.",
                        confidence=0.95,
                        cwe_id="CWE-78",
                        rule_id="SEC005",
                        root_cause="Passing unescaped string to system shell allows command chaining via semicolons, pipes, and backticks.",
                        fix_example="# Before:\nos.system(f'ping {host}')\n\n# After:\nimport subprocess\nsubprocess.run(['ping', host], shell=False, check=True)"
                    ))
                elif call_str.startswith("subprocess."):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            issues.append(Issue(
                                id=self._next_id(),
                                title="subprocess invoked with shell=True",
                                description="Running subprocess commands with `shell=True` bypasses argument escaping and opens the application to command injection.",
                                category=IssueCategory.SECURITY,
                                severity=Severity.HIGH,
                                file_path=fp,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno),
                                suggestion="Pass command as a list and set `shell=False`.",
                                confidence=0.92,
                                cwe_id="CWE-78",
                                rule_id="SEC005B",
                                root_cause="Shell=True spawns /bin/sh or cmd.exe to interpret arguments.",
                                fix_example="# Before:\nsubprocess.run(cmd, shell=True)\n\n# After:\nsubprocess.run(cmd.split(), shell=False)"
                            ))
        return issues

    def _detect_unverified_ssl(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_str = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    call_str = f"{node.func.value.id}.{node.func.attr}"
                
                if "create_unverified_context" in call_str:
                    issues.append(Issue(
                        id=self._next_id(),
                        title="Unverified SSL/TLS context created",
                        description="Disabling SSL certificate verification allows Man-In-The-Middle (MITM) attacks and credential theft.",
                        category=IssueCategory.SECURITY,
                        severity=Severity.HIGH,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion="Use `ssl.create_default_context()` with verified root certificates.",
                        confidence=0.95,
                        cwe_id="CWE-295",
                        rule_id="SEC006",
                        root_cause="Disabling certificate trust chain verification negates transport layer security.",
                        fix_example="# Before:\nssl._create_unverified_context()\n\n# After:\nssl.create_default_context()"
                    ))
                for kw in getattr(node, 'keywords', []):
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        issues.append(Issue(
                            id=self._next_id(),
                            title="SSL certificate validation disabled (verify=False)",
                            description="Setting `verify=False` in HTTP requests skips TLS certificate validation, making traffic interceptable.",
                            category=IssueCategory.SECURITY,
                            severity=Severity.HIGH,
                            file_path=fp,
                            line_number=node.lineno,
                            code_snippet=self._get_snippet(lines, node.lineno),
                            suggestion="Remove `verify=False` or pass a trusted CA bundle path.",
                            confidence=0.95,
                            cwe_id="CWE-295",
                            rule_id="SEC006B",
                            root_cause="Bypassing certificate validation exposes communications to proxy eavesdropping.",
                            fix_example="# Before:\nrequests.get(url, verify=False)\n\n# After:\nrequests.get(url, verify=True)"
                        ))
        return issues

    def _detect_http_without_timeout(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ("requests", "http_client") and node.func.attr in ("get", "post", "put", "delete", "patch"):
                        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                        if not has_timeout:
                            issues.append(Issue(
                                id=self._next_id(),
                                title=f"HTTP request without timeout: {node.func.value.id}.{node.func.attr}",
                                description="Requests without explicit timeouts can hang indefinitely if the remote server fails to respond, exhausting worker threads and causing application Denial of Service.",
                                category=IssueCategory.RELIABILITY,
                                severity=Severity.MEDIUM,
                                file_path=fp,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno),
                                suggestion="Always specify a timeout parameter: `requests.get(url, timeout=10.0)`",
                                confidence=0.90,
                                cwe_id="CWE-400",
                                rule_id="REL004",
                                root_cause="Requests library defaults to blocking forever until the socket connection closes.",
                                fix_example="# Before:\nresponse = requests.get(api_url)\n\n# After:\nresponse = requests.get(api_url, timeout=(3.05, 15.0))"
                            ))
        return issues

    def _detect_mutation_during_iteration(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Name):
                iter_target = node.iter.id
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        if isinstance(child.func.value, ast.Name) and child.func.value.id == iter_target:
                            if child.func.attr in ("remove", "pop", "append", "extend", "clear"):
                                issues.append(Issue(
                                    id=self._next_id(),
                                    title=f"Modifying collection `{iter_target}` while iterating over it",
                                    description=f"Calling `.{child.func.attr}()` on `{iter_target}` while looping over it modifies the internal index pointer, leading to skipped elements or undefined iteration behavior.",
                                    category=IssueCategory.BUG,
                                    severity=Severity.HIGH,
                                    file_path=fp,
                                    line_number=child.lineno,
                                    code_snippet=self._get_snippet(lines, child.lineno),
                                    suggestion=f"Iterate over a shallow copy (`for item in {iter_target}.copy():`) or use a list comprehension.",
                                    confidence=0.92,
                                    cwe_id="CWE-664",
                                    rule_id="REL005",
                                    root_cause="In-place mutation invalidates the active iterator's position offset.",
                                    fix_example=f"# Before:\nfor item in {iter_target}:\n    {iter_target}.{child.func.attr}(item)\n\n# After:\n{iter_target} = [item for item in {iter_target} if not condition]"
                                ))
        return issues

    def _detect_string_concat_in_loop(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                        if isinstance(child.target, ast.Name):
                            name = child.target.id.lower()
                            if any(k in name for k in ("str", "text", "html", "msg", "out", "buf", "query")):
                                issues.append(Issue(
                                    id=self._next_id(),
                                    title=f"Repeated string concatenation in loop (`{child.target.id} += ...`)",
                                    description=f"Strings are immutable in Python. Concatenating in a loop causes O(n²) memory allocations and degrades performance with large inputs.",
                                    category=IssueCategory.PERFORMANCE,
                                    severity=Severity.MEDIUM,
                                    file_path=fp,
                                    line_number=child.lineno,
                                    code_snippet=self._get_snippet(lines, child.lineno),
                                    suggestion="Append fragments to a list and use `''.join(fragments)` outside the loop.",
                                    confidence=0.85,
                                    rule_id="PERF003",
                                    root_cause="Repeated reallocations of immutable string buffers across iterations.",
                                    fix_example="# Before:\nout = ''\nfor x in items: out += str(x)\n\n# After:\nout = ''.join(str(x) for x in items)"
                                ))
        return issues

    def _detect_duplicate_dict_keys(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                seen_keys = set()
                for key_node in node.keys:
                    if isinstance(key_node, ast.Constant):
                        key_val = str(key_node.value)
                        if key_val in seen_keys:
                            issues.append(Issue(
                                id=self._next_id(),
                                title=f"Duplicate dictionary key: '{key_val}'",
                                description=f"The key '{key_val}' is defined multiple times in the same dictionary literal. Later entries overwrite earlier entries, causing subtle bugs.",
                                category=IssueCategory.BUG,
                                severity=Severity.MEDIUM,
                                file_path=fp,
                                line_number=key_node.lineno,
                                code_snippet=self._get_snippet(lines, key_node.lineno),
                                suggestion="Remove or rename the duplicate dictionary key.",
                                confidence=0.98,
                                rule_id="BUG007",
                                root_cause="Dictionary keys must be unique. Duplicate keys silently override prior values.",
                                fix_example=f"# Before:\n{{'{key_val}': 1, '{key_val}': 2}}\n\n# After:\n{{'{key_val}_v1': 1, '{key_val}_v2': 2}}"
                            ))
                        else:
                            seen_keys.add(key_val)
        return issues

    def _detect_excessive_arguments(self, tree, lines, fp) -> List[Issue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
                if len(args) > 7:
                    issues.append(Issue(
                        id=self._next_id(),
                        title=f"Function `{node.name}` has excessive arguments ({len(args)})",
                        description=f"Functions with more than 7 arguments violate clean code principles and are error-prone to invoke correctly.",
                        category=IssueCategory.MAINTAINABILITY,
                        severity=Severity.LOW,
                        file_path=fp,
                        line_number=node.lineno,
                        code_snippet=self._get_snippet(lines, node.lineno),
                        suggestion="Group related arguments into a dataclass, dictionary, or configuration object.",
                        confidence=0.90,
                        rule_id="MT005",
                        root_cause="High parameter count indicates low cohesion and violation of Single Responsibility Principle."
                    ))
        return issues

    def _calculate_metrics(self, tree, source_code: str) -> dict:
        """Calculate code metrics."""
        lines = source_code.split('\n')
        total_lines = len(lines)
        blank_lines = sum(1 for l in lines if not l.strip())
        comment_lines = sum(1 for l in lines if l.strip().startswith('#'))
        code_lines = total_lines - blank_lines - comment_lines

        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]

        return {
            'total_lines': total_lines,
            'code_lines': code_lines,
            'blank_lines': blank_lines,
            'comment_lines': comment_lines,
            'comment_ratio': round(comment_lines / max(code_lines, 1) * 100, 1),
            'num_functions': len(functions),
            'num_classes': len(classes),
            'num_imports': len(imports),
            'avg_function_length': round(
                sum(self._func_length(f) for f in functions) / max(len(functions), 1), 1
            ),
        }

    def _func_length(self, func_node) -> int:
        if hasattr(func_node, 'end_lineno') and func_node.end_lineno:
            return func_node.end_lineno - func_node.lineno + 1
        return len(func_node.body)

    def _calculate_complexity(self, tree) -> dict:
        """Calculate cyclomatic complexity for each function."""
        results = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = 1
                for child in ast.walk(node):
                    if isinstance(child, (ast.If, ast.IfExp)):
                        complexity += 1
                    elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                        complexity += 1
                    elif isinstance(child, ast.ExceptHandler):
                        complexity += 1
                    elif isinstance(child, ast.BoolOp):
                        complexity += len(child.values) - 1
                    elif isinstance(child, ast.Assert):
                        complexity += 1
                results[node.name] = {
                    'complexity': complexity,
                    'line': node.lineno,
                    'rating': 'A' if complexity <= 5 else 'B' if complexity <= 10 else 'C' if complexity <= 15 else 'D' if complexity <= 20 else 'F'
                }
        return results

    def _calculate_risk_score(self, result: AnalysisResult) -> float:
        """Calculate overall risk score (0-10) based on issues and metrics."""
        if not result.issues:
            return 0.5

        severity_weights = {
            Severity.CRITICAL: 3.0,
            Severity.HIGH: 2.0,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }

        weighted_sum = sum(
            severity_weights.get(issue.severity, 0.5) * issue.confidence
            for issue in result.issues
        )

        loc = max(result.lines_of_code, 1)
        density = weighted_sum / (loc / 100)

        score = min(10.0, density * 1.5)
        return round(score, 1)
