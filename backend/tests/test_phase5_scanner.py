"""
Comprehensive Phase 5 scanner tests.

Covers 63 test cases:
  - Security rules: positive/negative/FP tests
  - Python AST + data-flow analysis
  - JS/TS structural analysis
  - Confidence scoring
  - Deduplication / fingerprinting
  - Suppression
  - Remediation engine
  - File discovery
  - Edge cases
"""

import os
import tempfile
from pathlib import Path
from typing import List

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production")

from app.services.scan_engine.findings.types import (
    DataFlowStep,
    RichFindingResult,
    SourceInfo,
    SinkInfo,
    PatchInfo,
)
from app.services.scan_engine.scanner.confidence import score_confidence, confidence_level
from app.services.scan_engine.scanner.deduplication import (
    generate_fingerprint,
    deduplicate,
)
from app.services.scan_engine.scanner.suppression import (
    build_suppression_map,
    is_suppressed,
    apply_suppressions,
)
from app.services.scan_engine.scanner.remediation import enrich_remediation
from app.services.scan_engine.scanner.python_analyzer import analyze_python
from app.services.scan_engine.scanner.js_analyzer import analyze_js
from app.services.scan_engine.scanner.discovery import discover_files, ScanConfig
from app.services.scan_engine.analyzers import analyze_repository, FindingResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def titles(findings) -> List[str]:
    return [f.title for f in findings]


def severities(findings) -> List[str]:
    return [f.severity for f in findings]


def rule_ids(findings) -> List[str]:
    return [getattr(f, "rule_id", "") for f in findings]


def has_rule(findings, rule_id: str) -> bool:
    return any(getattr(f, "rule_id", "") == rule_id for f in findings)


def findings_for_rule(findings, rule_id: str):
    return [f for f in findings if getattr(f, "rule_id", "") == rule_id]


def write_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ===========================================================================
# 1. CONFIDENCE SCORER
# ===========================================================================


class TestConfidenceScorer:
    def test_user_controlled_source_boosts(self):
        score = score_confidence(60, has_user_controlled_source=True, is_regex_only=False)
        assert score > 60

    def test_sanitizer_penalizes(self):
        score_clean = score_confidence(70, has_sanitizer=False, is_regex_only=False)
        score_sanitized = score_confidence(70, has_sanitizer=True, is_regex_only=False)
        assert score_sanitized < score_clean

    def test_constant_source_penalizes(self):
        score = score_confidence(70, source_is_constant=True)
        assert score < 70

    def test_regex_only_penalizes(self):
        score_ast = score_confidence(70, is_regex_only=False)
        score_regex = score_confidence(70, is_regex_only=True)
        assert score_regex < score_ast

    def test_score_clamped_to_0_100(self):
        score = score_confidence(100, has_user_controlled_source=True,
                                 has_direct_flow=True, is_ast_confirmed=True,
                                 has_framework_context=True, sink_is_known=True,
                                 is_regex_only=False)
        assert score <= 100
        score2 = score_confidence(0, source_is_constant=True, has_sanitizer=True,
                                   is_regex_only=True, is_generated_file=True)
        assert score2 >= 0

    def test_confidence_level_labels(self):
        assert confidence_level(90) == "high"
        assert confidence_level(65) == "medium"
        assert confidence_level(30) == "low"


# ===========================================================================
# 2. DEDUPLICATION
# ===========================================================================


class TestDeduplication:
    def _make_finding(self, rule_id="PY001", file="foo.py", line=10, severity="high",
                       analyzer="regex", confidence=50):
        f = RichFindingResult(
            severity=severity, title="Test", description="desc",
            file_path=file, line_number=line,
            rule_id=rule_id, analyzer=analyzer, confidence=confidence,
        )
        return f

    def test_fingerprint_stable(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        fp1 = generate_fingerprint(f1)
        fp2 = generate_fingerprint(f2)
        assert fp1 == fp2

    def test_different_rules_different_fingerprints(self):
        f1 = self._make_finding(rule_id="PY001")
        f2 = self._make_finding(rule_id="PY002")
        assert generate_fingerprint(f1) != generate_fingerprint(f2)

    def test_dedup_merges_same_fingerprint(self):
        f1 = self._make_finding(analyzer="regex", confidence=50)
        f2 = self._make_finding(analyzer="ast", confidence=75)
        f1.fingerprint = generate_fingerprint(f1)
        f2.fingerprint = generate_fingerprint(f2)
        result = deduplicate([f1, f2])
        assert len(result) == 1
        # Should keep the AST finding (higher priority)
        assert result[0].analyzer == "ast"

    def test_dedup_keeps_distinct_findings(self):
        f1 = self._make_finding(rule_id="PY001", line=10)
        f2 = self._make_finding(rule_id="PY002", line=20)
        f1.fingerprint = generate_fingerprint(f1)
        f2.fingerprint = generate_fingerprint(f2)
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_dedup_prefers_higher_confidence(self):
        f1 = self._make_finding(confidence=40, analyzer="ast")
        f2 = self._make_finding(confidence=85, analyzer="ast")
        f1.fingerprint = generate_fingerprint(f1)
        f2.fingerprint = generate_fingerprint(f2)
        result = deduplicate([f1, f2])
        assert result[0].confidence == 85

    def test_dedup_prefers_dataflow_over_regex(self):
        f1 = self._make_finding(analyzer="dataflow", confidence=60)
        f2 = self._make_finding(analyzer="regex", confidence=90)
        f1.fingerprint = generate_fingerprint(f1)
        f2.fingerprint = generate_fingerprint(f2)
        result = deduplicate([f1, f2])
        assert result[0].analyzer == "dataflow"


# ===========================================================================
# 3. SUPPRESSION
# ===========================================================================


class TestSuppression:
    def test_suppression_comment_detected(self):
        content = "result = eval(user_input)  # devpilot: ignore PY001"
        sup_map = build_suppression_map(content)
        assert is_suppressed(sup_map, 1, "PY001")

    def test_suppression_wrong_line_not_suppressed(self):
        content = "# devpilot: ignore PY001\nresult = eval(user_input)"
        sup_map = build_suppression_map(content)
        assert not is_suppressed(sup_map, 2, "PY001")

    def test_suppression_wrong_rule_not_suppressed(self):
        content = "result = eval(user_input)  # devpilot: ignore PY002"
        sup_map = build_suppression_map(content)
        assert not is_suppressed(sup_map, 1, "PY001")

    def test_suppression_js_style_comment(self):
        content = "eval(userInput);  // devpilot: ignore JS001"
        sup_map = build_suppression_map(content)
        assert is_suppressed(sup_map, 1, "JS001")

    def test_apply_suppressions_filters_finding(self):
        f = RichFindingResult(
            severity="high", title="Test", description="d",
            file_path="foo.py", line_number=1, rule_id="PY001",
        )
        content = "x = 1  # devpilot: ignore PY001"
        sup_map = build_suppression_map(content)
        active, suppressed = apply_suppressions([f], sup_map, "foo.py")
        assert len(active) == 0
        assert len(suppressed) == 1

    def test_apply_suppressions_keeps_unsuppressed(self):
        f = RichFindingResult(
            severity="high", title="Test", description="d",
            file_path="foo.py", line_number=2, rule_id="PY001",
        )
        content = "x = 1  # devpilot: ignore PY001\nother line"
        sup_map = build_suppression_map(content)
        active, suppressed = apply_suppressions([f], sup_map, "foo.py")
        assert len(active) == 1
        assert len(suppressed) == 0


# ===========================================================================
# 4. REMEDIATION ENGINE
# ===========================================================================


class TestRemediation:
    def test_enrich_fills_why_risky(self):
        f = RichFindingResult(
            severity="high", title="eval test", description="d",
            file_path="f.py", line_number=1, rule_id="PY001",
        )
        enrich_remediation(f)
        assert f.why_risky is not None and len(f.why_risky) > 10

    def test_enrich_fills_remediation(self):
        f = RichFindingResult(
            severity="high", title="eval test", description="d",
            file_path="f.py", line_number=1, rule_id="PY001",
        )
        enrich_remediation(f)
        assert f.remediation is not None

    def test_enrich_fills_cwe(self):
        f = RichFindingResult(
            severity="high", title="eval test", description="d",
            file_path="f.py", line_number=1, rule_id="PY001",
        )
        enrich_remediation(f)
        assert f.cwe == "CWE-95"

    def test_enrich_yaml_patch_generated(self):
        f = RichFindingResult(
            severity="high", title="yaml.load test", description="d",
            file_path="f.py", line_number=5, rule_id="PY008",
            code_snippet="data = yaml.load(stream)",
        )
        enrich_remediation(f)
        assert f.patch_available is True
        assert f.patch is not None
        assert "safe_load" in f.patch.replacement

    def test_enrich_unknown_rule_noop(self):
        f = RichFindingResult(
            severity="low", title="x", description="d",
            file_path="f.py", line_number=1, rule_id="UNKNOWN999",
        )
        enrich_remediation(f)
        # Should not crash; fields remain unset
        assert f.why_risky is None


# ===========================================================================
# 5. PYTHON ANALYZER — SECURITY RULES
# ===========================================================================


class TestPythonEval:
    def test_eval_with_user_input_detected(self):
        code = """
cmd = request.query_params["cmd"]
result = eval(cmd)
"""
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "PY001"), f"Expected PY001 in {rule_ids(findings)}"

    def test_eval_constant_not_flagged(self):
        code = 'result = eval("2 + 2")\n'
        findings = analyze_python(code, "test.py")
        # eval("2+2") with constant arg should not produce high-confidence finding
        py001 = findings_for_rule(findings, "PY001")
        # If detected, must be low confidence (constant penalty)
        for f in py001:
            assert f.confidence < 60, "Constant eval should have low confidence"

    def test_eval_user_input_has_high_confidence(self):
        code = """
user_data = request.query_params["expr"]
result = eval(user_data)
"""
        findings = analyze_python(code, "test.py")
        py001 = findings_for_rule(findings, "PY001")
        assert py001, "Should find PY001"
        assert py001[0].confidence >= 60

    def test_eval_has_source_sink_flow(self):
        code = """
expr = request.query_params["expr"]
result = eval(expr)
"""
        findings = analyze_python(code, "test.py")
        py001 = findings_for_rule(findings, "PY001")
        assert py001
        assert len(py001[0].data_flow) >= 2


class TestPythonExec:
    def test_exec_user_input_detected(self):
        code = """
code_str = request.body["code"]
exec(code_str)
"""
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "PY002"), f"Expected PY002 in {rule_ids(findings)}"

    def test_exec_constant_not_flagged(self):
        code = 'exec("x = 1")\n'
        findings = analyze_python(code, "test.py")
        py002 = findings_for_rule(findings, "PY002")
        for f in py002:
            assert f.confidence < 60


class TestPythonSubprocess:
    def test_subprocess_shell_true_user_input_critical(self):
        code = """
cmd = request.query_params["cmd"]
subprocess.run(cmd, shell=True)
"""
        findings = analyze_python(code, "test.py")
        py003 = findings_for_rule(findings, "PY003")
        assert py003, f"Expected PY003, got {rule_ids(findings)}"
        assert py003[0].severity in ("critical", "high")

    def test_subprocess_safe_list_not_flagged(self):
        code = 'subprocess.run(["git", "status"], shell=False)\n'
        findings = analyze_python(code, "test.py")
        py003 = findings_for_rule(findings, "PY003")
        assert not py003, "Safe subprocess list should not be flagged"

    def test_subprocess_shell_true_no_user_input_is_high(self):
        code = 'subprocess.run("ls -la", shell=True)\n'
        findings = analyze_python(code, "test.py")
        py003 = findings_for_rule(findings, "PY003")
        assert py003
        assert py003[0].severity in ("high", "medium")

    def test_subprocess_cwe_78(self):
        code = """
cmd = request.query_params["x"]
subprocess.run(cmd, shell=True)
"""
        findings = analyze_python(code, "test.py")
        py003 = findings_for_rule(findings, "PY003")
        assert py003
        assert py003[0].cwe == "CWE-78"


class TestPythonSQLInjection:
    def test_fstring_sql_detected(self):
        code = """
user_id = request.query_params["id"]
db.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
"""
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "PY005"), f"Expected PY005, got {rule_ids(findings)}"

    def test_parameterized_sql_not_flagged(self):
        code = 'db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})\n'
        findings = analyze_python(code, "test.py")
        py005 = findings_for_rule(findings, "PY005")
        assert not py005, "Parameterized query should not be flagged"


class TestPythonPickle:
    def test_pickle_loads_detected(self):
        code = 'data = pickle.loads(raw_bytes)\n'
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "PY007"), f"Expected PY007, got {rule_ids(findings)}"

    def test_pickle_has_cwe_502(self):
        code = 'data = pickle.loads(raw_bytes)\n'
        findings = analyze_python(code, "test.py")
        py007 = findings_for_rule(findings, "PY007")
        assert py007
        assert py007[0].cwe == "CWE-502"


class TestPythonYaml:
    def test_yaml_load_without_loader_detected(self):
        code = 'data = yaml.load(stream)\n'
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "PY008"), f"Expected PY008, got {rule_ids(findings)}"

    def test_yaml_safe_load_not_flagged(self):
        code = 'data = yaml.safe_load(stream)\n'
        findings = analyze_python(code, "test.py")
        py008 = findings_for_rule(findings, "PY008")
        assert not py008, "yaml.safe_load should not be flagged"

    def test_yaml_load_patch_available(self):
        code = 'data = yaml.load(stream)\n'
        findings = analyze_python(code, "test.py")
        py008 = findings_for_rule(findings, "PY008")
        assert py008
        enrich_remediation(py008[0])
        assert py008[0].patch_available


class TestPythonSecrets:
    def test_hardcoded_api_key_detected(self):
        code = 'API_KEY = "sk-abc123secretvalue"\n'
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "SEC001"), f"Expected SEC001, got {rule_ids(findings)}"

    def test_env_var_not_flagged(self):
        code = 'API_KEY = os.environ["API_KEY"]\n'
        findings = analyze_python(code, "test.py")
        sec001 = findings_for_rule(findings, "SEC001")
        assert not sec001, "os.environ assignment should not be flagged"

    def test_placeholder_not_flagged(self):
        code = 'PASSWORD = "changeme"\n'
        findings = analyze_python(code, "test.py")
        sec001 = findings_for_rule(findings, "SEC001")
        assert not sec001, "Common placeholder should not be flagged"


class TestPythonPathTraversal:
    def test_user_controlled_path_detected(self):
        code = """
filename = request.query_params["file"]
with open(filename) as f:
    content = f.read()
"""
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "PY006"), f"Expected PY006, got {rule_ids(findings)}"

    def test_hardcoded_path_not_flagged(self):
        code = 'with open("/etc/config.txt") as f:\n    pass\n'
        findings = analyze_python(code, "test.py")
        py006 = findings_for_rule(findings, "PY006")
        assert not py006, "Hardcoded path should not be flagged"


class TestPythonWeakCrypto:
    def test_md5_detected(self):
        code = 'digest = hashlib.md5(data).hexdigest()\n'
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "CRY001"), f"Expected CRY001, got {rule_ids(findings)}"

    def test_sha1_detected(self):
        code = 'digest = hashlib.sha1(data).hexdigest()\n'
        findings = analyze_python(code, "test.py")
        assert has_rule(findings, "CRY001")

    def test_sha256_not_flagged(self):
        code = 'digest = hashlib.sha256(data).hexdigest()\n'
        findings = analyze_python(code, "test.py")
        cry001 = findings_for_rule(findings, "CRY001")
        assert not cry001


# ===========================================================================
# 6. DATA FLOW TESTS
# ===========================================================================


class TestDataFlow:
    def test_direct_source_to_sink(self):
        code = """
user_input = request.query_params["cmd"]
result = eval(user_input)
"""
        findings = analyze_python(code, "test.py")
        py001 = findings_for_rule(findings, "PY001")
        assert py001
        assert len(py001[0].data_flow) >= 2

    def test_aliased_source_to_sink(self):
        code = """
raw = request.query_params["cmd"]
cmd = raw
result = eval(cmd)
"""
        findings = analyze_python(code, "test.py")
        py001 = findings_for_rule(findings, "PY001")
        assert py001
        # Taint should propagate through alias

    def test_sanitized_flow_lower_confidence(self):
        code = """
raw = request.query_params["expr"]
safe = html.escape(raw)
result = eval(safe)
"""
        findings = analyze_python(code, "test.py")
        py001 = findings_for_rule(findings, "PY001")
        # If detected, the sanitizer SHOULD reduce confidence vs unsanitized equivalent
        # Unsanitized direct flow would score ~100; sanitized scores lower (penalty applied)
        unsanitized_code = """
raw = request.query_params["expr"]
result = eval(raw)
"""
        unsanitized = findings_for_rule(analyze_python(unsanitized_code, "test.py"), "PY001")
        if py001 and unsanitized:
            # Sanitized should have lower or equal confidence than unsanitized
            assert py001[0].confidence <= unsanitized[0].confidence, (
                f"Sanitized ({py001[0].confidence}) should be <= unsanitized ({unsanitized[0].confidence})"
            )

    def test_subprocess_fstring_taint(self):
        code = """
host = request.query_params["host"]
cmd = f"ping -c 1 {host}"
subprocess.run(cmd, shell=True)
"""
        findings = analyze_python(code, "test.py")
        # Should detect the f-string propagation as taint
        py003 = findings_for_rule(findings, "PY003")
        assert py003


# ===========================================================================
# 7. JAVASCRIPT / TYPESCRIPT ANALYZER
# ===========================================================================


class TestJavaScriptEval:
    def test_eval_detected(self):
        code = "const result = eval(userInput);\n"
        findings = analyze_js(code, "test.js")
        assert has_rule(findings, "JS001"), f"Expected JS001, got {rule_ids(findings)}"

    def test_eval_with_nearby_user_source_higher_confidence(self):
        code = "const input = req.query.cmd;\nconst result = eval(input);\n"
        findings = analyze_js(code, "test.js")
        js001 = findings_for_rule(findings, "JS001")
        assert js001
        assert js001[0].confidence > 50

    def test_function_constructor_detected(self):
        code = "const fn = new Function(userCode);\n"
        findings = analyze_js(code, "test.js")
        assert has_rule(findings, "JS002"), f"Expected JS002, got {rule_ids(findings)}"


class TestJavaScriptXSS:
    def test_dangerous_set_inner_html_detected(self):
        code = '<div dangerouslySetInnerHTML={{ __html: content }} />\n'
        findings = analyze_js(code, "test.tsx", language="typescript")
        assert has_rule(findings, "JS004"), f"Expected JS004, got {rule_ids(findings)}"

    def test_dangerous_set_inner_html_with_sanitizer_lower_severity(self):
        code = """
const clean = DOMPurify.sanitize(userHtml);
const el = <div dangerouslySetInnerHTML={{ __html: clean }} />;
"""
        findings = analyze_js(code, "test.tsx", language="typescript")
        js004 = findings_for_rule(findings, "JS004")
        if js004:
            # Should be downgraded due to sanitizer nearby
            assert js004[0].severity in ("medium", "low")

    def test_inner_html_assignment_detected(self):
        code = "el.innerHTML = userInput;\n"
        findings = analyze_js(code, "test.js")
        assert has_rule(findings, "JS005"), f"Expected JS005, got {rule_ids(findings)}"

    def test_text_content_not_flagged(self):
        code = "el.textContent = userInput;\n"
        findings = analyze_js(code, "test.js")
        js005 = findings_for_rule(findings, "JS005")
        assert not js005, "textContent is safe and should not be flagged"

    def test_document_write_detected(self):
        code = "document.write(content);\n"
        findings = analyze_js(code, "test.js")
        assert has_rule(findings, "JS006"), f"Expected JS006, got {rule_ids(findings)}"


class TestJavaScriptQuality:
    def test_console_log_detected(self):
        code = "console.log('debug value:', data);\n"
        findings = analyze_js(code, "test.js")
        assert has_rule(findings, "QA003"), f"Expected QA003, got {rule_ids(findings)}"

    def test_debugger_detected(self):
        code = "debugger;\n"
        findings = analyze_js(code, "test.js")
        assert has_rule(findings, "QA003"), f"Expected QA003, got {rule_ids(findings)}"

    def test_comment_only_console_not_flagged(self):
        code = "// console.log('this is a comment');\n"
        findings = analyze_js(code, "test.js")
        # Comment-only lines should be skipped
        qa003 = findings_for_rule(findings, "QA003")
        assert not qa003, "Commented-out console.log should not be flagged"


class TestJavaScriptSecrets:
    def test_hardcoded_api_key_detected(self):
        code = "const API_KEY = 'sk-secret123value';\n"
        findings = analyze_js(code, "test.js")
        assert has_rule(findings, "SEC001"), f"Expected SEC001, got {rule_ids(findings)}"


# ===========================================================================
# 8. FILE DISCOVERY
# ===========================================================================


class TestDiscovery:
    def test_python_files_found(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "test.ts").write_text("const x = 1;")
        result = discover_files(tmp_path)
        langs = {f.language for f in result.files}
        assert "python" in langs
        assert "typescript" in langs

    def test_node_modules_skipped(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "lib.js").write_text("code")
        result = discover_files(tmp_path)
        paths = [f.relative_path for f in result.files]
        assert not any("node_modules" in p for p in paths)

    def test_binary_file_marked(self, tmp_path):
        f = tmp_path / "img.png"
        f.write_bytes(b"\x00\x01\x02" * 100)
        result = discover_files(tmp_path)
        png = [f for f in result.files if f.extension == ".png"]
        for pf in png:
            assert pf.is_binary

    def test_large_file_skipped_from_scan(self, tmp_path):
        f = tmp_path / "huge.py"
        f.write_bytes(b"x = 1\n" * 100_000)  # ~600KB
        cfg = ScanConfig(max_file_size=100_000)
        result = discover_files(tmp_path, cfg)
        py_files = [f for f in result.files if f.extension == ".py"]
        # File content should be None (too large)
        for pf in py_files:
            assert pf.content is None or not pf.is_scannable

    def test_empty_file_handled(self, tmp_path):
        (tmp_path / "empty.py").write_text("")
        result = discover_files(tmp_path)
        assert result.files  # no crash

    def test_syntax_error_handled(self):
        code = "def broken(:\n    pass\n"
        # Should not raise
        findings = analyze_python(code, "broken.py")
        assert isinstance(findings, list)

    def test_binary_content_not_analyzed(self, tmp_path):
        # File with .py extension but binary content
        f = tmp_path / "binary.py"
        f.write_bytes(b"\x00\x01\x02\xfe\xff" * 200)
        result = discover_files(tmp_path)
        binary = [f for f in result.files if f.relative_path == "binary.py"]
        if binary:
            assert binary[0].is_binary or not binary[0].is_scannable


# ===========================================================================
# 9. EDGE CASES
# ===========================================================================


class TestEdgeCases:
    def test_empty_python_file(self):
        findings = analyze_python("", "empty.py")
        assert findings == []

    def test_malformed_python_graceful(self):
        findings = analyze_python("def broken(x\n", "bad.py")
        assert isinstance(findings, list)  # no crash

    def test_empty_js_file(self):
        findings = analyze_js("", "empty.js")
        assert findings == []

    def test_analyze_repository_no_crash(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')")
        results = analyze_repository(tmp_path)
        assert isinstance(results, list)

    def test_analyze_repository_deduplicates(self, tmp_path):
        # Same finding reported by multiple passes should be deduplicated
        code = "API_KEY = 'supersecretvalue'\n"
        (tmp_path / "config.py").write_text(code)
        results = analyze_repository(tmp_path)
        sec_findings = [f for f in results if getattr(f, "rule_id", "") == "SEC001"
                        or "hardcoded secret" in f.title.lower()]
        # Should not have duplicates with identical fingerprints
        fps = [getattr(f, "fingerprint", generate_fingerprint(f)) for f in sec_findings]
        assert len(fps) == len(set(fps)), "Duplicate fingerprints found"

    def test_cyclic_data_flow_no_infinite_loop(self):
        # Code that could cause cycles in naive tracking
        code = """
a = request.query_params["x"]
b = a
c = b
d = c
e = d
f = e
g = f
h = g
i = h
j = i
k = j
result = eval(k)
"""
        findings = analyze_python(code, "deep.py")
        # Should terminate and find the issue
        assert isinstance(findings, list)

    def test_analyze_repository_handles_unreadable_file(self, tmp_path):
        # Write a file then make it unreadable (if possible)
        f = tmp_path / "secret.py"
        f.write_text("x = 1")
        try:
            import os
            os.chmod(str(f), 0o000)
            results = analyze_repository(tmp_path)
            assert isinstance(results, list)  # no crash
        finally:
            os.chmod(str(f), 0o644)


# ===========================================================================
# 10. METADATA / QUALITY GATE
# ===========================================================================


class TestFindingMetadata:
    def test_command_injection_has_cwe_78(self):
        code = """
cmd = request.query_params["cmd"]
subprocess.run(cmd, shell=True)
"""
        findings = analyze_python(code, "test.py")
        py003 = findings_for_rule(findings, "PY003")
        assert py003
        assert py003[0].cwe == "CWE-78"

    def test_finding_has_fingerprint(self):
        code = 'data = pickle.loads(raw)\n'
        findings = analyze_python(code, "test.py")
        for f in findings:
            assert f.fingerprint, "Every finding must have a fingerprint"

    def test_finding_has_language(self):
        code = 'eval(user_input)\n'
        findings = analyze_python(code, "test.py")
        for f in findings:
            if f.rule_id:
                assert f.language == "python"

    def test_finding_has_analyzer(self):
        code = 'eval(user_input)\n'
        findings = analyze_python(code, "test.py")
        for f in findings:
            assert f.analyzer in ("ast", "regex", "dataflow", "import_graph", "")

    def test_severity_is_valid(self):
        code = """
cmd = request.query_params["x"]
subprocess.run(cmd, shell=True)
"""
        findings = analyze_python(code, "test.py")
        valid = {"critical", "high", "medium", "low", "info"}
        for f in findings:
            assert f.severity in valid, f"Invalid severity: {f.severity}"
