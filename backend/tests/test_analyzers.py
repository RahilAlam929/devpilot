"""
Tests for the expanded regex rule set and the Python AST-based analyser.

Covers:
  - Hardcoded secrets (expanded keyword list)
  - Python: broad exception / bare except / debug print / assert
  - Python: eval(), exec(), shell=True, SQL injection patterns, weak crypto,
            pickle.loads, yaml.load, logging secrets
  - JS/TS:  eval(), dangerouslySetInnerHTML, document.write, innerHTML=,
            console.log, debugger, hardcoded localhost URL
  - Java:   catch(Exception), printStackTrace, SQL concatenation, System.out.println
  - Go:     ignored error with _, fmt.Println, hardcoded credential
  - Universal: TODO/FIXME/HACK/XXX info marker
  - AST:    unused imports, missing return annotations, mutable default args,
            bare raise outside except block
  - analyze_file and analyze_repository smoke tests
"""

import os
import tempfile
from pathlib import Path
from typing import List

import pytest

from app.services.scan_engine.analyzers import (
    ALLOWED_EXTENSIONS,
    FindingResult,
    IGNORED_DIRS,
    RULES,
    analyze_file,
    analyze_repository,
    should_scan,
)
from app.services.scan_engine.ast_analyzer import (
    ASTFinding,
    analyze_ast,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _titles(findings: List[FindingResult]) -> List[str]:
    return [f.title for f in findings]


def _write_tmp(suffix: str, content: str) -> tuple[Path, Path]:
    """Create a temp directory containing one file with *content*. Returns (root, path)."""
    tmpdir = Path(tempfile.mkdtemp())
    path = tmpdir / f"test_file{suffix}"
    path.write_text(content, encoding="utf-8")
    return tmpdir, path


# ---------------------------------------------------------------------------
# should_scan helper
# ---------------------------------------------------------------------------


class TestShouldScan:
    def test_python_file_allowed(self, tmp_path):
        f = tmp_path / "foo.py"
        f.write_text("")
        assert should_scan(f)

    def test_markdown_file_excluded(self, tmp_path):
        f = tmp_path / "README.md"
        f.write_text("")
        assert not should_scan(f)

    def test_file_in_ignored_dir(self, tmp_path):
        d = tmp_path / "node_modules"
        d.mkdir()
        f = d / "foo.js"
        f.write_text("")
        assert not should_scan(f)

    def test_file_in_venv_excluded(self, tmp_path):
        d = tmp_path / ".venv"
        d.mkdir()
        f = d / "app.py"
        f.write_text("")
        assert not should_scan(f)

    def test_directory_not_a_file(self, tmp_path):
        assert not should_scan(tmp_path)


# ---------------------------------------------------------------------------
# Universal rule — TODO/FIXME/HACK/XXX
# ---------------------------------------------------------------------------


class TestUniversalMarkers:
    @pytest.mark.parametrize("keyword", ["TODO", "FIXME", "HACK", "XXX"])
    def test_marker_detected(self, tmp_path, keyword):
        root, path = _write_tmp(".py", f"# {keyword}: fix this later\n")
        findings = analyze_file(root, path)
        assert any("Unfinished-work marker" in f.title for f in findings)

    def test_marker_case_insensitive(self, tmp_path):
        root, path = _write_tmp(".py", "# todo: lower-case\n")
        findings = analyze_file(root, path)
        assert any("Unfinished-work marker" in f.title for f in findings)

    def test_marker_in_js(self, tmp_path):
        root, path = _write_tmp(".js", "// TODO refactor this\n")
        findings = analyze_file(root, path)
        assert any("Unfinished-work marker" in f.title for f in findings)

    def test_no_false_positive(self, tmp_path):
        root, path = _write_tmp(".py", "x = 1  # regular comment\n")
        findings = analyze_file(root, path)
        assert not any("Unfinished-work marker" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Hardcoded secrets (all languages)
# ---------------------------------------------------------------------------


class TestHardcodedSecrets:
    @pytest.mark.parametrize("keyword", [
        "API_KEY", "SECRET_KEY", "ACCESS_TOKEN", "PASSWORD",
        "PRIVATE_KEY", "AUTH_TOKEN", "CLIENT_SECRET", "ENCRYPTION_KEY",
        "DB_PASSWORD", "DATABASE_PASSWORD",
    ])
    def test_secret_keyword_detected(self, tmp_path, keyword):
        root, path = _write_tmp(".py", f'{keyword} = "supersecret123"\n')
        findings = analyze_file(root, path)
        assert any("hardcoded secret" in f.title.lower() for f in findings), \
            f"Expected hardcoded secret finding for keyword '{keyword}'"

    def test_secret_in_js_detected(self, tmp_path):
        root, path = _write_tmp(".js", 'const API_KEY = "abc123"\n')
        findings = analyze_file(root, path)
        assert any("hardcoded secret" in f.title.lower() for f in findings)

    def test_short_value_not_flagged(self, tmp_path):
        # Values shorter than 4 chars are not flagged (too likely to be placeholders)
        root, path = _write_tmp(".py", 'API_KEY = "ab"\n')
        findings = analyze_file(root, path)
        assert not any("hardcoded secret" in f.title.lower() for f in findings)

    def test_secret_assigned_to_env_var_reference_not_flagged(self, tmp_path):
        # The pattern looks for string literals, not variable references.
        root, path = _write_tmp(".py", 'API_KEY = os.environ.get("API_KEY")\n')
        findings = analyze_file(root, path)
        assert not any("hardcoded secret" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Python-specific rules
# ---------------------------------------------------------------------------


class TestPythonRules:
    def test_broad_except_detected(self, tmp_path):
        root, path = _write_tmp(".py", "try:\n    pass\nexcept Exception:\n    pass\n")
        findings = analyze_file(root, path)
        assert any("Broad exception" in f.title for f in findings)

    def test_bare_except_detected(self, tmp_path):
        root, path = _write_tmp(".py", "try:\n    pass\nexcept:\n    pass\n")
        findings = analyze_file(root, path)
        assert any("Bare except" in f.title for f in findings)

    def test_print_statement_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'print("debug value")\n')
        findings = analyze_file(root, path)
        assert any("print statement" in f.title.lower() for f in findings)

    def test_assert_in_production_detected(self, tmp_path):
        root, path = _write_tmp(".py", "assert x > 0\n")
        findings = analyze_file(root, path)
        assert any("Assert statement" in f.title for f in findings)

    def test_eval_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'result = eval(user_input)\n')
        findings = analyze_file(root, path)
        assert any("eval()" in f.title for f in findings)

    def test_exec_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'exec(code)\n')
        findings = analyze_file(root, path)
        assert any("exec()" in f.title for f in findings)

    def test_subprocess_shell_true_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'subprocess.run(cmd, shell=True)\n')
        findings = analyze_file(root, path)
        assert any("shell=True" in f.title for f in findings)

    def test_subprocess_shell_false_not_flagged(self, tmp_path):
        root, path = _write_tmp(".py", 'subprocess.run(["ls", "-la"], shell=False)\n')
        findings = analyze_file(root, path)
        assert not any("shell=True" in f.title for f in findings)

    def test_sql_string_interpolation_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n')
        findings = analyze_file(root, path)
        assert any("SQL injection" in f.title for f in findings)

    def test_sql_fstring_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'db.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
        findings = analyze_file(root, path)
        assert any("SQL injection" in f.title for f in findings)

    def test_md5_weak_crypto_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'hashlib.md5(data)\n')
        findings = analyze_file(root, path)
        assert any("Weak cryptographic" in f.title for f in findings)

    def test_sha1_weak_crypto_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'hashlib.sha1(data)\n')
        findings = analyze_file(root, path)
        assert any("Weak cryptographic" in f.title for f in findings)

    def test_sha256_not_flagged(self, tmp_path):
        root, path = _write_tmp(".py", 'hashlib.sha256(data)\n')
        findings = analyze_file(root, path)
        assert not any("Weak cryptographic" in f.title for f in findings)

    def test_pickle_loads_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'data = pickle.loads(raw)\n')
        findings = analyze_file(root, path)
        assert any("pickle" in f.title.lower() for f in findings)

    def test_yaml_load_without_loader_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'config = yaml.load(stream)\n')
        findings = analyze_file(root, path)
        assert any("yaml.load" in f.title.lower() for f in findings)

    def test_yaml_safe_load_not_flagged(self, tmp_path):
        root, path = _write_tmp(".py", 'config = yaml.safe_load(stream)\n')
        findings = analyze_file(root, path)
        assert not any("yaml.load" in f.title.lower() for f in findings)

    def test_logging_secret_detected(self, tmp_path):
        root, path = _write_tmp(".py", 'logging.info("password=%s", password)\n')
        findings = analyze_file(root, path)
        assert any("logged" in f.title.lower() or "secret" in f.title.lower() for f in findings)

    def test_rules_not_applied_to_non_python(self, tmp_path):
        """Python-specific rules must not fire on .js files."""
        root, path = _write_tmp(".js", "except Exception:\n")
        findings = analyze_file(root, path)
        assert not any("Broad exception" in f.title for f in findings)
        assert not any("Bare except" in f.title for f in findings)


# ---------------------------------------------------------------------------
# JavaScript / TypeScript rules
# ---------------------------------------------------------------------------


class TestJsTsRules:
    @pytest.mark.parametrize("ext", [".js", ".jsx", ".ts", ".tsx"])
    def test_eval_detected(self, tmp_path, ext):
        root, path = _write_tmp(ext, "const r = eval(userInput);\n")
        findings = analyze_file(root, path)
        assert any("eval()" in f.title for f in findings)

    def test_dangerous_set_inner_html_detected(self, tmp_path):
        root, path = _write_tmp(".tsx", "<div dangerouslySetInnerHTML={{__html: html}} />\n")
        findings = analyze_file(root, path)
        assert any("dangerouslySetInnerHTML" in f.title for f in findings)

    def test_document_write_detected(self, tmp_path):
        root, path = _write_tmp(".js", "document.write('<script>' + code + '</script>');\n")
        findings = analyze_file(root, path)
        assert any("document.write" in f.title for f in findings)

    def test_inner_html_assignment_detected(self, tmp_path):
        root, path = _write_tmp(".js", "el.innerHTML = userHtml;\n")
        findings = analyze_file(root, path)
        assert any("innerHTML" in f.title for f in findings)

    def test_console_log_detected(self, tmp_path):
        root, path = _write_tmp(".ts", "console.log('debug', data);\n")
        findings = analyze_file(root, path)
        assert any("console" in f.title.lower() for f in findings)

    def test_debugger_statement_detected(self, tmp_path):
        root, path = _write_tmp(".js", "debugger;\n")
        findings = analyze_file(root, path)
        assert any("debugger" in f.title.lower() for f in findings)

    def test_hardcoded_localhost_url_detected(self, tmp_path):
        root, path = _write_tmp(".ts", 'const API = "http://localhost:8000";\n')
        findings = analyze_file(root, path)
        assert any("localhost" in f.title.lower() for f in findings)

    def test_js_rules_not_applied_to_python(self, tmp_path):
        """JS/TS rules must not fire on .py files."""
        root, path = _write_tmp(".py", "# console.log('test')\n")
        findings = analyze_file(root, path)
        assert not any("console" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Java rules
# ---------------------------------------------------------------------------


class TestJavaRules:
    def test_broad_exception_catch_detected(self, tmp_path):
        root, path = _write_tmp(".java", "catch (Exception e) {\n    e.printStackTrace();\n}\n")
        findings = analyze_file(root, path)
        assert any("Broad exception catch" in f.title for f in findings)

    def test_print_stack_trace_detected(self, tmp_path):
        root, path = _write_tmp(".java", "e.printStackTrace();\n")
        findings = analyze_file(root, path)
        assert any("printStackTrace" in f.title for f in findings)

    def test_sql_concatenation_detected(self, tmp_path):
        root, path = _write_tmp(".java", '"SELECT * FROM users WHERE id = " + userId\n')
        findings = analyze_file(root, path)
        assert any("SQL injection" in f.title for f in findings)

    def test_system_out_println_detected(self, tmp_path):
        root, path = _write_tmp(".java", 'System.out.println("debug");\n')
        findings = analyze_file(root, path)
        assert any("System.out.println" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Go rules
# ---------------------------------------------------------------------------


class TestGoRules:
    def test_ignored_error_detected(self, tmp_path):
        root, path = _write_tmp(".go", "result, _ := doSomething()\n")
        findings = analyze_file(root, path)
        assert any("Error return ignored" in f.title for f in findings)

    def test_fmt_println_detected(self, tmp_path):
        root, path = _write_tmp(".go", 'fmt.Println("hello")\n')
        findings = analyze_file(root, path)
        assert any("fmt.Println" in f.title for f in findings)

    def test_hardcoded_credential_detected(self, tmp_path):
        root, path = _write_tmp(".go", 'password := "supersecret"\n')
        findings = analyze_file(root, path)
        assert any("hardcoded credential" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------


class TestSeverityLevels:
    def test_hardcoded_secret_is_high(self, tmp_path):
        root, path = _write_tmp(".py", 'API_KEY = "longvalue123"\n')
        findings = analyze_file(root, path)
        secret_findings = [f for f in findings if "hardcoded secret" in f.title.lower()]
        assert secret_findings
        assert all(f.severity == "high" for f in secret_findings)

    def test_broad_except_is_medium(self, tmp_path):
        root, path = _write_tmp(".py", "try:\n    pass\nexcept Exception:\n    pass\n")
        findings = analyze_file(root, path)
        broad = [f for f in findings if "Broad exception" in f.title]
        assert broad
        assert all(f.severity == "medium" for f in broad)

    def test_print_is_low(self, tmp_path):
        root, path = _write_tmp(".py", 'print("x")\n')
        findings = analyze_file(root, path)
        prints = [f for f in findings if "print statement" in f.title.lower()]
        assert prints
        assert all(f.severity == "low" for f in prints)

    def test_todo_is_info(self, tmp_path):
        root, path = _write_tmp(".py", "# TODO: fix this\n")
        findings = analyze_file(root, path)
        todos = [f for f in findings if "Unfinished-work" in f.title]
        assert todos
        assert all(f.severity == "info" for f in todos)


# ---------------------------------------------------------------------------
# analyze_repository smoke test
# ---------------------------------------------------------------------------


class TestAnalyzeRepository:
    def test_multiple_file_types(self, tmp_path):
        (tmp_path / "app.py").write_text('API_KEY = "secret123"\nprint("x")\n')
        (tmp_path / "app.js").write_text("eval(userCode);\n")
        (tmp_path / "App.java").write_text('System.out.println("debug");\n')

        findings = analyze_repository(tmp_path)
        titles = _titles(findings)
        assert any("hardcoded secret" in t.lower() for t in titles)
        assert any("print statement" in t.lower() for t in titles)
        assert any("eval()" in t for t in titles)
        assert any("System.out.println" in t for t in titles)

    def test_ignored_dirs_not_scanned(self, tmp_path):
        node_mod = tmp_path / "node_modules"
        node_mod.mkdir()
        (node_mod / "lib.js").write_text('eval("bad");\n')

        findings = analyze_repository(tmp_path)
        assert not findings  # nothing outside ignored dirs

    def test_finding_has_correct_file_path(self, tmp_path):
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "auth.py").write_text('PASSWORD = "hardcodedpassword"\n')

        findings = analyze_repository(tmp_path)
        secret_findings = [f for f in findings if "hardcoded secret" in f.title.lower()]
        assert secret_findings
        assert all("src/auth.py" in f.file_path for f in secret_findings)

    def test_finding_has_correct_line_number(self, tmp_path):
        content = "# line 1\n# line 2\neval(code)\n# line 4\n"
        (tmp_path / "script.py").write_text(content)
        findings = analyze_repository(tmp_path)
        eval_findings = [f for f in findings if "eval()" in f.title]
        assert eval_findings
        assert eval_findings[0].line_number == 3


# ---------------------------------------------------------------------------
# AST analyser: unused imports
# ---------------------------------------------------------------------------


class TestASTUnusedImports:
    def test_unused_import_detected(self):
        src = "import os\nimport sys\n\nx = os.getcwd()\n"
        findings = analyze_ast(src)
        titles = [f.title for f in findings]
        assert "Unused import" in titles
        unused_descs = [f.description for f in findings if f.title == "Unused import"]
        assert any("sys" in d for d in unused_descs)

    def test_used_import_not_flagged(self):
        src = "import os\n\nx = os.getcwd()\n"
        findings = analyze_ast(src)
        assert not any(f.title == "Unused import" for f in findings)

    def test_from_import_unused(self):
        src = "from pathlib import Path, PurePath\n\np = Path('.')\n"
        findings = analyze_ast(src)
        unused = [f for f in findings if f.title == "Unused import"]
        assert unused
        assert any("PurePath" in f.description for f in unused)

    def test_all_exports_considered_used(self):
        """Names in __all__ must not be reported as unused."""
        src = (
            "from .utils import helper\n"
            "\n"
            "__all__ = ['helper']\n"
        )
        findings = analyze_ast(src)
        assert not any(f.title == "Unused import" for f in findings)

    def test_underscore_alias_not_flagged(self):
        """import X as _X is intentionally unused."""
        src = "import sys as _sys\n\nx = 1\n"
        findings = analyze_ast(src)
        assert not any(f.title == "Unused import" for f in findings)

    def test_star_import_not_flagged(self):
        """from module import * cannot be tracked statically."""
        src = "from os.path import *\n\nresult = join('a', 'b')\n"
        findings = analyze_ast(src)
        assert not any(f.title == "Unused import" for f in findings)

    def test_attribute_usage_counts_as_used(self):
        """import os; os.path.join() — 'os' is used via attribute chain."""
        src = "import os\n\nx = os.path.join('a', 'b')\n"
        findings = analyze_ast(src)
        assert not any(f.title == "Unused import" for f in findings)


# ---------------------------------------------------------------------------
# AST analyser: missing return type annotations
# ---------------------------------------------------------------------------


class TestASTMissingReturnAnnotations:
    def test_missing_annotation_on_public_fn(self):
        src = "def my_func(x, y):\n    return x + y\n"
        findings = analyze_ast(src)
        ann = [f for f in findings if "return type annotation" in f.title.lower()]
        assert ann
        assert any("my_func" in f.description for f in ann)

    def test_annotated_function_not_flagged(self):
        src = "def my_func(x: int) -> int:\n    return x\n"
        findings = analyze_ast(src)
        assert not any("return type annotation" in f.title.lower() for f in findings)

    def test_private_function_not_flagged(self):
        src = "def _helper(x):\n    return x\n"
        findings = analyze_ast(src)
        assert not any("return type annotation" in f.title.lower() for f in findings)

    def test_dunder_method_not_flagged(self):
        src = "class Foo:\n    def __init__(self):\n        pass\n"
        findings = analyze_ast(src)
        assert not any("return type annotation" in f.title.lower() for f in findings)

    def test_public_method_missing_annotation(self):
        src = "class Foo:\n    def bar(self, x):\n        return x\n"
        findings = analyze_ast(src)
        ann = [f for f in findings if "return type annotation" in f.title.lower()]
        assert ann
        assert any("bar" in f.description for f in ann)

    def test_annotated_method_not_flagged(self):
        src = "class Foo:\n    def bar(self) -> str:\n        return 'hello'\n"
        findings = analyze_ast(src)
        assert not any("return type annotation" in f.title.lower() for f in findings)

    def test_async_function_checked(self):
        src = "async def fetch(url):\n    pass\n"
        findings = analyze_ast(src)
        ann = [f for f in findings if "return type annotation" in f.title.lower()]
        assert ann


# ---------------------------------------------------------------------------
# AST analyser: mutable default arguments
# ---------------------------------------------------------------------------


class TestASTMutableDefaults:
    def test_list_default_detected(self):
        src = "def foo(items=[]):\n    pass\n"
        findings = analyze_ast(src)
        mut = [f for f in findings if "Mutable default" in f.title]
        assert mut
        assert any("items" in f.description for f in mut)

    def test_dict_default_detected(self):
        src = "def foo(opts={}):\n    pass\n"
        findings = analyze_ast(src)
        assert any("Mutable default" in f.title for f in findings)

    def test_set_default_detected(self):
        src = "def foo(s=set()):\n    pass\n"
        findings = analyze_ast(src)
        assert any("Mutable default" in f.title for f in findings)

    def test_list_call_default_detected(self):
        src = "def foo(items=list()):\n    pass\n"
        findings = analyze_ast(src)
        assert any("Mutable default" in f.title for f in findings)

    def test_dict_call_default_detected(self):
        src = "def foo(d=dict()):\n    pass\n"
        findings = analyze_ast(src)
        assert any("Mutable default" in f.title for f in findings)

    def test_none_default_not_flagged(self):
        src = "def foo(items=None):\n    pass\n"
        findings = analyze_ast(src)
        assert not any("Mutable default" in f.title for f in findings)

    def test_immutable_defaults_not_flagged(self):
        src = "def foo(x=0, y='hello', z=True):\n    pass\n"
        findings = analyze_ast(src)
        assert not any("Mutable default" in f.title for f in findings)

    def test_tuple_default_not_flagged(self):
        """Tuples are immutable — not a mutable default bug."""
        src = "def foo(t=(1, 2, 3)):\n    pass\n"
        findings = analyze_ast(src)
        assert not any("Mutable default" in f.title for f in findings)

    def test_kwonly_mutable_default_detected(self):
        src = "def foo(*, opts={}):\n    pass\n"
        findings = analyze_ast(src)
        assert any("Mutable default" in f.title for f in findings)

    def test_severity_is_medium(self):
        src = "def foo(items=[]):\n    pass\n"
        findings = analyze_ast(src)
        mut = [f for f in findings if "Mutable default" in f.title]
        assert mut
        assert all(f.severity == "medium" for f in mut)


# ---------------------------------------------------------------------------
# AST analyser: bare raise outside except
# ---------------------------------------------------------------------------


class TestASTBareRaise:
    def test_bare_raise_outside_except_detected(self):
        src = "raise\n"
        findings = analyze_ast(src)
        bare = [f for f in findings if "Bare raise" in f.title]
        assert bare

    def test_bare_raise_inside_except_not_flagged(self):
        src = "try:\n    pass\nexcept ValueError:\n    raise\n"
        findings = analyze_ast(src)
        assert not any("Bare raise" in f.title for f in findings)

    def test_raise_with_exception_not_flagged(self):
        src = "raise ValueError('oops')\n"
        findings = analyze_ast(src)
        assert not any("Bare raise" in f.title for f in findings)

    def test_bare_raise_in_function_outside_except(self):
        src = "def foo():\n    raise\n"
        findings = analyze_ast(src)
        bare = [f for f in findings if "Bare raise" in f.title]
        assert bare

    def test_bare_raise_in_nested_except_not_flagged(self):
        src = (
            "try:\n"
            "    try:\n"
            "        pass\n"
            "    except TypeError:\n"
            "        raise\n"
            "except ValueError:\n"
            "    pass\n"
        )
        findings = analyze_ast(src)
        assert not any("Bare raise" in f.title for f in findings)

    def test_severity_is_medium(self):
        src = "raise\n"
        findings = analyze_ast(src)
        bare = [f for f in findings if "Bare raise" in f.title]
        assert bare
        assert all(f.severity == "medium" for f in bare)


# ---------------------------------------------------------------------------
# AST analyser: syntax errors handled gracefully
# ---------------------------------------------------------------------------


class TestASTSyntaxError:
    def test_syntax_error_returns_empty(self):
        src = "def broken(\n"
        findings = analyze_ast(src)
        assert findings == []


# ---------------------------------------------------------------------------
# Integration: AST findings surfaced through analyze_file
# ---------------------------------------------------------------------------


class TestASTIntegration:
    def test_ast_findings_in_analyze_file(self, tmp_path):
        """analyze_file must include AST findings for .py files."""
        root, path = _write_tmp(".py", "import os\nimport sys\n\nx = os.getcwd()\n")
        findings = analyze_file(root, path)
        titles = _titles(findings)
        assert "Unused import" in titles

    def test_ast_not_run_for_non_python(self, tmp_path):
        """AST analysis must not run for .js files (no Python AST)."""
        root, path = _write_tmp(".js", "import os\n")
        findings = analyze_file(root, path)
        assert not any(f.title == "Unused import" for f in findings)


# ---------------------------------------------------------------------------
# Regression: null bytes / binary files must not crash the scanner
# ---------------------------------------------------------------------------


class TestBinaryFileHandling:
    """
    Binary .py files (or .py files containing null bytes) must be skipped
    gracefully.  Before the fix, ast.parse raised ValueError on null bytes,
    which propagated up and caused the entire scan to be marked 'failed'.
    """

    def test_binary_py_file_does_not_crash_analyze_file(self, tmp_path):
        """analyze_file must return an empty list, not raise, for a binary .py file."""
        root = tmp_path
        bad = root / "binary.py"
        bad.write_bytes(bytes(range(256)))  # 0x00–0xFF, contains null bytes
        findings = analyze_file(root, bad)
        assert isinstance(findings, list)  # no exception raised

    def test_null_byte_py_file_does_not_crash_analyze_file(self, tmp_path):
        """A .py file that contains a null byte mid-source must be skipped."""
        root = tmp_path
        bad = root / "nullbyte.py"
        bad.write_bytes(b"x = 1\x00\ny = 2\n")
        findings = analyze_file(root, bad)
        assert isinstance(findings, list)

    def test_binary_py_file_does_not_crash_analyze_repository(self, tmp_path):
        """analyze_repository must finish cleanly even when binary .py files exist."""
        # Put a legit file alongside the binary one so there IS something to scan.
        (tmp_path / "good.py").write_text('print("hello")\n', encoding="utf-8")
        (tmp_path / "binary.py").write_bytes(bytes(range(256)))

        findings = analyze_repository(tmp_path)
        # The legit file contributes at least one finding (print statement).
        assert any(f.file_path.endswith("good.py") for f in findings)
        # No finding should reference the binary file (it was skipped).
        assert not any(f.file_path.endswith("binary.py") for f in findings)

    def test_analyze_repository_single_rglob(self, tmp_path):
        """
        analyze_repository must collect files in one pass.
        Verified indirectly: a fresh tmp directory with one Python file
        must produce findings only for that file (no duplicates from a
        second rglob run merging duplicate paths).
        """
        (tmp_path / "app.py").write_text('print("x")\n', encoding="utf-8")
        findings = analyze_repository(tmp_path)
        print_findings = [f for f in findings if "print statement" in f.title.lower()]
        # Exactly one finding expected — deduplication check.
        assert len(print_findings) == 1

    def test_ast_syntax_error_does_not_crash(self, tmp_path):
        """A .py file with invalid Python syntax must be skipped by AST analysis."""
        root = tmp_path
        bad = root / "broken.py"
        bad.write_text("def broken(\n", encoding="utf-8")  # incomplete syntax
        findings = analyze_file(root, bad)
        assert isinstance(findings, list)
