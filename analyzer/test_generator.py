"""
Test Generator Module
Generates test cases for Python functions using templates and heuristics.
"""

import ast
import textwrap
from typing import List, Optional


class TestCase:
    """Represents a generated test case."""
    def __init__(self, func_name: str, test_name: str, test_code: str,
                 category: str = "unit", description: str = ""):
        self.func_name = func_name
        self.test_name = test_name
        self.test_code = test_code
        self.category = category
        self.description = description


class TestGenerator:
    """Generates test cases for Python functions."""

    def generate_tests(self, source_code: str, file_path: str = "<input>") -> List[TestCase]:
        """Generate test cases for all functions in the source code."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        tests = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith('_') and node.name != '__init__':
                    continue
                tests.extend(self._generate_for_function(node, source_code))
        return tests

    def _generate_for_function(self, func: ast.FunctionDef, source_code: str) -> List[TestCase]:
        """Generate test cases for a single function."""
        tests = []
        func_name = func.name
        args = self._extract_args(func)
        has_return = self._has_return(func)
        raises = self._extract_exceptions(func)

        # Basic invocation test
        tests.append(self._gen_basic_test(func_name, args, has_return))

        # Edge case tests
        tests.extend(self._gen_edge_case_tests(func_name, args))

        # Exception tests
        for exc in raises:
            tests.append(self._gen_exception_test(func_name, args, exc))

        # None input test
        if args:
            tests.append(self._gen_none_input_test(func_name, args))

        # Type error test
        if args:
            tests.append(self._gen_type_error_test(func_name, args))

        return tests

    def _extract_args(self, func: ast.FunctionDef) -> list:
        """Extract function arguments."""
        args = []
        for arg in func.args.args:
            if arg.arg in ('self', 'cls'):
                continue
            annotation = None
            if arg.annotation:
                if isinstance(arg.annotation, ast.Name):
                    annotation = arg.annotation.id
                elif isinstance(arg.annotation, ast.Constant):
                    annotation = str(arg.annotation.value)
            args.append({'name': arg.arg, 'type': annotation})
        return args

    def _has_return(self, func: ast.FunctionDef) -> bool:
        for node in ast.walk(func):
            if isinstance(node, ast.Return) and node.value is not None:
                return True
        return False

    def _extract_exceptions(self, func: ast.FunctionDef) -> list:
        exceptions = []
        for node in ast.walk(func):
            if isinstance(node, ast.Raise):
                if node.exc:
                    if isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name):
                        exceptions.append(node.exc.func.id)
                    elif isinstance(node.exc, ast.Name):
                        exceptions.append(node.exc.id)
        return list(set(exceptions))

    def _sample_value(self, type_hint: Optional[str]) -> str:
        type_map = {
            'str': '"test_input"',
            'int': '42',
            'float': '3.14',
            'bool': 'True',
            'list': '[1, 2, 3]',
            'dict': '{"key": "value"}',
            'set': '{1, 2, 3}',
            'tuple': '(1, 2, 3)',
            'bytes': 'b"test"',
        }
        return type_map.get(type_hint, '"test_value"')

    def _gen_basic_test(self, func_name: str, args: list, has_return: bool) -> TestCase:
        arg_values = ', '.join(self._sample_value(a['type']) for a in args)
        if has_return:
            code = textwrap.dedent(f"""\
                def test_{func_name}_basic():
                    \"\"\"Test basic invocation of {func_name}.\"\"\"
                    result = {func_name}({arg_values})
                    assert result is not None, "Function should return a value"
            """)
        else:
            code = textwrap.dedent(f"""\
                def test_{func_name}_basic():
                    \"\"\"Test basic invocation of {func_name} completes without error.\"\"\"
                    # Should not raise any exception
                    {func_name}({arg_values})
            """)
        return TestCase(func_name, f"test_{func_name}_basic", code, "unit",
                       f"Basic smoke test for {func_name}")

    def _gen_edge_case_tests(self, func_name: str, args: list) -> List[TestCase]:
        tests = []
        for arg in args:
            if arg['type'] in ('str', None):
                code = textwrap.dedent(f"""\
                    def test_{func_name}_empty_string_{arg['name']}():
                        \"\"\"Test {func_name} with empty string for {arg['name']}.\"\"\"
                        try:
                            result = {func_name}({self._build_args_with_override(args, arg['name'], '""')})
                            # Verify the function handles empty input gracefully
                        except (ValueError, TypeError) as e:
                            pass  # Expected for invalid input
                """)
                tests.append(TestCase(func_name, f"test_{func_name}_empty_{arg['name']}", code,
                                    "edge_case", f"Empty string test for parameter {arg['name']}"))

            if arg['type'] in ('int', 'float', None):
                code = textwrap.dedent(f"""\
                    def test_{func_name}_negative_{arg['name']}():
                        \"\"\"Test {func_name} with negative value for {arg['name']}.\"\"\"
                        try:
                            result = {func_name}({self._build_args_with_override(args, arg['name'], '-1')})
                        except (ValueError, TypeError) as e:
                            pass  # Expected for invalid input
                """)
                tests.append(TestCase(func_name, f"test_{func_name}_negative_{arg['name']}", code,
                                    "edge_case", f"Negative value test for parameter {arg['name']}"))

            if arg['type'] in ('list', None):
                code = textwrap.dedent(f"""\
                    def test_{func_name}_empty_list_{arg['name']}():
                        \"\"\"Test {func_name} with empty list for {arg['name']}.\"\"\"
                        try:
                            result = {func_name}({self._build_args_with_override(args, arg['name'], '[]')})
                        except (ValueError, IndexError) as e:
                            pass  # Expected for empty collection
                """)
                tests.append(TestCase(func_name, f"test_{func_name}_empty_list_{arg['name']}", code,
                                    "edge_case", f"Empty list test for parameter {arg['name']}"))
        return tests

    def _gen_exception_test(self, func_name: str, args: list, exception: str) -> TestCase:
        arg_values = ', '.join(self._sample_value(a['type']) for a in args)
        code = textwrap.dedent(f"""\
            def test_{func_name}_raises_{exception.lower()}():
                \"\"\"Test that {func_name} raises {exception} for invalid input.\"\"\"
                import pytest
                with pytest.raises({exception}):
                    {func_name}({arg_values})  # Provide input that triggers {exception}
        """)
        return TestCase(func_name, f"test_{func_name}_raises_{exception.lower()}", code,
                       "exception", f"Test {exception} is raised for invalid input")

    def _gen_none_input_test(self, func_name: str, args: list) -> TestCase:
        none_args = ', '.join('None' for _ in args)
        code = textwrap.dedent(f"""\
            def test_{func_name}_none_input():
                \"\"\"Test {func_name} behavior with None inputs.\"\"\"
                try:
                    result = {func_name}({none_args})
                except (TypeError, ValueError, AttributeError) as e:
                    pass  # Expected when None is not a valid input
        """)
        return TestCase(func_name, f"test_{func_name}_none_input", code,
                       "robustness", f"Test {func_name} handles None input gracefully")

    def _gen_type_error_test(self, func_name: str, args: list) -> TestCase:
        wrong_args = ', '.join('object()' for _ in args)
        code = textwrap.dedent(f"""\
            def test_{func_name}_invalid_type():
                \"\"\"Test {func_name} with completely wrong argument types.\"\"\"
                try:
                    result = {func_name}({wrong_args})
                except (TypeError, AttributeError, ValueError) as e:
                    pass  # Expected for wrong types
        """)
        return TestCase(func_name, f"test_{func_name}_invalid_type", code,
                       "robustness", f"Test {func_name} rejects invalid types")

    def _build_args_with_override(self, args: list, target: str, value: str) -> str:
        parts = []
        for a in args:
            if a['name'] == target:
                parts.append(value)
            else:
                parts.append(self._sample_value(a['type']))
        return ', '.join(parts)
