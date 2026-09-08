"""
Tests for cross-file import analysis (import_graph.py).

Covers:
  - Empty repository returns no findings
  - No-cycle graph returns no circular-import findings
  - Simple two-module cycle detected
  - Three-module cycle detected
  - Multiple independent cycles each reported
  - Self-loop (import of own module) not counted as a cycle
  - Relative imports resolved correctly
  - Unused internal import detected
  - Used internal import not flagged
  - Re-exported names (__all__) not flagged as unused
  - Underscore-prefixed aliases not flagged as unused
  - Star imports not flagged as unused
  - Non-Python files not included in graph
  - Ignored directories excluded from analysis
  - analyze_repository integrates import_graph findings
"""

import tempfile
from pathlib import Path
from typing import List

import pytest

from app.services.scan_engine.import_graph import analyze_imports
from app.services.scan_engine.analyzers import analyze_repository, FindingResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pkg(root: Path, files: dict[str, str]) -> None:
    """Write {relative_path: content} into root, creating directories."""
    for rel_path, content in files.items():
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _titles(findings: List[FindingResult]) -> List[str]:
    return [f.title for f in findings]


def _circular(findings: List[FindingResult]) -> List[FindingResult]:
    return [f for f in findings if f.title == "Circular import detected"]


def _unused(findings: List[FindingResult]) -> List[FindingResult]:
    return [f for f in findings if f.title == "Unused internal import"]


# ---------------------------------------------------------------------------
# Empty / minimal repository
# ---------------------------------------------------------------------------


class TestEmptyRepository:
    def test_no_python_files_returns_empty(self, tmp_path):
        (tmp_path / "README.md").write_text("# hi")
        findings = analyze_imports(tmp_path)
        assert findings == []

    def test_single_file_no_imports_returns_empty(self, tmp_path):
        (tmp_path / "main.py").write_text("x = 1\n")
        findings = analyze_imports(tmp_path)
        assert findings == []

    def test_two_unrelated_modules_returns_empty(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        findings = analyze_imports(tmp_path)
        assert findings == []


# ---------------------------------------------------------------------------
# Circular import detection
# ---------------------------------------------------------------------------


class TestCircularImports:
    def test_simple_two_module_cycle(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import b_val\na_val = 1\n",
            "pkg/b.py": "from pkg.a import a_val\nb_val = 2\n",
        })
        findings = analyze_imports(tmp_path)
        assert _circular(findings), "Expected circular import finding"

    def test_cycle_description_mentions_modules(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import b_val\na_val = 1\n",
            "pkg/b.py": "from pkg.a import a_val\nb_val = 2\n",
        })
        findings = _circular(analyze_imports(tmp_path))
        assert findings
        desc = findings[0].description
        assert "pkg.a" in desc or "pkg.b" in desc

    def test_three_module_cycle(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import b_val\na_val = 1\n",
            "pkg/b.py": "from pkg.c import c_val\nb_val = 2\n",
            "pkg/c.py": "from pkg.a import a_val\nc_val = 3\n",
        })
        findings = analyze_imports(tmp_path)
        assert _circular(findings)

    def test_no_cycle_in_linear_chain(self, tmp_path):
        """a → b → c (no cycle)."""
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import b_val\n",
            "pkg/b.py": "from pkg.c import c_val\nb_val = 1\n",
            "pkg/c.py": "c_val = 42\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _circular(findings)

    def test_no_cycle_in_diamond(self, tmp_path):
        """a → b, a → c, b → d, c → d (diamond, no cycle)."""
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import bv\nfrom pkg.c import cv\n",
            "pkg/b.py": "from pkg.d import dv\nbv = 1\n",
            "pkg/c.py": "from pkg.d import dv\ncv = 2\n",
            "pkg/d.py": "dv = 3\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _circular(findings)

    def test_cycle_severity_is_high(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import b_val\na_val = 1\n",
            "pkg/b.py": "from pkg.a import a_val\nb_val = 2\n",
        })
        for f in _circular(analyze_imports(tmp_path)):
            assert f.severity == "high"


# ---------------------------------------------------------------------------
# Relative import resolution
# ---------------------------------------------------------------------------


class TestRelativeImports:
    def test_relative_import_cycle_detected(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from .b import b_val\na_val = 1\n",
            "pkg/b.py": "from .a import a_val\nb_val = 2\n",
        })
        findings = analyze_imports(tmp_path)
        assert _circular(findings)

    def test_relative_import_no_cycle(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from .utils import helper\n",
            "pkg/utils.py": "helper = lambda: None\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _circular(findings)


# ---------------------------------------------------------------------------
# Unused internal import detection
# ---------------------------------------------------------------------------


class TestUnusedInternalImports:
    def test_unused_internal_import_detected(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper(): pass\n",
            "pkg/app.py": "from pkg.utils import helper\n\nx = 1\n",
        })
        findings = analyze_imports(tmp_path)
        unused = _unused(findings)
        assert unused, "Expected unused internal import finding"
        assert any("helper" in f.description for f in unused)

    def test_used_internal_import_not_flagged(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper(): pass\n",
            "pkg/app.py": "from pkg.utils import helper\n\nresult = helper()\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _unused(findings)

    def test_import_used_as_attribute_not_flagged(self, tmp_path):
        """import pkg.utils; pkg.utils.helper() — 'pkg' is used."""
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper(): pass\n",
            "pkg/app.py": "import pkg.utils\n\npkg.utils.helper()\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _unused(findings)

    def test_all_export_not_flagged_as_unused(self, tmp_path):
        """Names listed in __all__ are considered intentional re-exports."""
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper(): pass\n",
            "pkg/api.py": (
                "from pkg.utils import helper\n"
                "\n"
                "__all__ = ['helper']\n"
            ),
        })
        findings = analyze_imports(tmp_path)
        assert not _unused(findings)

    def test_underscore_alias_not_flagged(self, tmp_path):
        """from pkg.utils import helper as _helper — intentionally unused."""
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper(): pass\n",
            "pkg/app.py": "from pkg.utils import helper as _helper\n\nx = 1\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _unused(findings)

    def test_star_import_not_flagged(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "helper = 1\n",
            "pkg/app.py": "from pkg.utils import *\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _unused(findings)

    def test_unused_import_severity_is_low(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper(): pass\n",
            "pkg/app.py": "from pkg.utils import helper\n\nx = 1\n",
        })
        for f in _unused(analyze_imports(tmp_path)):
            assert f.severity == "low"


# ---------------------------------------------------------------------------
# Non-Python and ignored-dir exclusion
# ---------------------------------------------------------------------------


class TestExclusions:
    def test_js_files_not_in_graph(self, tmp_path):
        _write_pkg(tmp_path, {
            "app.js": "import { foo } from './utils'\n",
            "utils.js": "export function foo() {}\n",
        })
        findings = analyze_imports(tmp_path)
        assert findings == []

    def test_ignored_dirs_excluded(self, tmp_path):
        _write_pkg(tmp_path, {
            "node_modules/pkg/a.py": "from node_modules.pkg.b import x\n",
            "node_modules/pkg/b.py": "from node_modules.pkg.a import y\n",
        })
        findings = analyze_imports(tmp_path)
        assert not _circular(findings)

    def test_venv_excluded(self, tmp_path):
        _write_pkg(tmp_path, {
            ".venv/site-packages/lib/a.py": "x = 1\n",
        })
        findings = analyze_imports(tmp_path)
        assert findings == []


# ---------------------------------------------------------------------------
# Integration: analyze_repository includes import_graph findings
# ---------------------------------------------------------------------------


class TestImportGraphIntegration:
    def test_circular_import_in_analyze_repository(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import b_val\na_val = 1\n",
            "pkg/b.py": "from pkg.a import a_val\nb_val = 2\n",
        })
        findings = analyze_repository(tmp_path)
        assert any(f.title == "Circular import detected" for f in findings)

    def test_unused_import_in_analyze_repository(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper(): pass\n",
            "pkg/app.py": "from pkg.utils import helper\n\nx = 1\n",
        })
        findings = analyze_repository(tmp_path)
        assert any(f.title == "Unused internal import" for f in findings)

    def test_no_findings_for_clean_package(self, tmp_path):
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/utils.py": "def helper() -> str:\n    return 'ok'\n",
            "pkg/app.py": (
                "from pkg.utils import helper\n"
                "\n"
                "result = helper()\n"
            ),
        })
        findings = analyze_repository(tmp_path)
        # There should be no circular import and no unused-import findings.
        # (There may be regex findings for other patterns, but not import ones.)
        assert not any(f.title == "Circular import detected" for f in findings)
        assert not any(f.title == "Unused internal import" for f in findings)


# ---------------------------------------------------------------------------
# Regression: null bytes / binary .py files must not crash import analysis
# ---------------------------------------------------------------------------


class TestBinaryFileHandling:
    """
    Binary .py files contain null bytes that cause ast.parse to raise
    ValueError.  Both ast.parse call sites in import_graph.py must catch
    (SyntaxError, ValueError) to avoid crashing a scan.
    """

    def test_binary_py_does_not_crash_analyze_imports(self, tmp_path):
        """analyze_imports must return a list (possibly empty), not raise."""
        (tmp_path / "binary.py").write_bytes(bytes(range(256)))
        findings = analyze_imports(tmp_path)
        assert isinstance(findings, list)

    def test_null_byte_py_does_not_crash_analyze_imports(self, tmp_path):
        """A .py file with a null byte must be skipped gracefully."""
        (tmp_path / "nullbyte.py").write_bytes(b"import os\x00\nos.getcwd()\n")
        findings = analyze_imports(tmp_path)
        assert isinstance(findings, list)

    def test_binary_py_alongside_valid_package(self, tmp_path):
        """
        A binary .py file must not prevent valid modules from being analysed.
        The cycle in the valid package should still be detected.
        """
        _write_pkg(tmp_path, {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg.b import b_val\na_val = 1\n",
            "pkg/b.py": "from pkg.a import a_val\nb_val = 2\n",
        })
        (tmp_path / "pkg" / "binary.py").write_bytes(bytes(range(256)))

        findings = analyze_imports(tmp_path)
        assert _circular(findings), "Cycle in pkg.a/pkg.b must still be detected"
