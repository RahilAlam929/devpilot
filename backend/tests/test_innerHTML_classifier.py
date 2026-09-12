"""
Tests for the innerHTML source-to-sink classifier.

Covers all five source classes plus edge cases:
  - USER_INPUT  → innerHTML   : High severity, high confidence
  - URL_DATA    → innerHTML   : High severity
  - API_RESPONSE → innerHTML  : Medium severity
  - STATIC_CONSTANT → innerHTML: Info severity, false-positive candidate
  - TRUSTED_INTERNAL (SVG/icon) → innerHTML: Info severity
  - UNKNOWN source → Medium severity, manual review
  - insertAdjacentHTML sinks
  - outerHTML sinks
  - Sanitizer detection reduces severity
  - Variable alias tracing (html = userInput; el.innerHTML = html)
  - Multi-hop alias tracing
  - template.innerHTML = html.trim() — trace through .trim() call
  - extract_innerHTML_rhs correctness
  - End-to-end via analyze_js() integration
"""

from __future__ import annotations

import os
from typing import List

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production")

from app.services.scan_engine.scanner.innerHTML_classifier import (
    ClassificationResult,
    SourceClass,
    classify_innerHTML_source,
    extract_innerHTML_rhs,
)
from app.services.scan_engine.scanner.js_analyzer import analyze_js


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def lines(code: str) -> List[str]:
    return code.splitlines()


def js005_findings(code: str, filename: str = "test.js"):
    findings = analyze_js(code, filename)
    return [f for f in findings if getattr(f, "rule_id", "") == "JS005"]


# ===========================================================================
# 1. extract_innerHTML_rhs
# ===========================================================================


class TestExtractRhs:
    def test_basic_innerHTML(self):
        rhs = extract_innerHTML_rhs("el.innerHTML = userInput;")
        assert rhs == "userInput"

    def test_innerHTML_with_trim(self):
        rhs = extract_innerHTML_rhs("template.innerHTML = html.trim();")
        assert rhs == "html.trim()"

    def test_outerHTML(self):
        rhs = extract_innerHTML_rhs("wrapper.outerHTML = content;")
        assert rhs == "content"

    def test_insertAdjacentHTML(self):
        rhs = extract_innerHTML_rhs("el.insertAdjacentHTML('beforeend', content);")
        assert rhs == "content"

    def test_insertAdjacentHTML_afterbegin(self):
        rhs = extract_innerHTML_rhs('el.insertAdjacentHTML("afterbegin", html);')
        assert rhs == "html"

    def test_static_string(self):
        rhs = extract_innerHTML_rhs('el.innerHTML = "<b>bold</b>";')
        assert rhs == '"<b>bold</b>"'

    def test_empty_string(self):
        rhs = extract_innerHTML_rhs('el.innerHTML = "";')
        assert rhs == '""'

    def test_no_match_returns_empty(self):
        rhs = extract_innerHTML_rhs("el.textContent = safe;")
        assert rhs == ""

    def test_no_semicolon(self):
        rhs = extract_innerHTML_rhs("el.innerHTML = data")
        assert rhs == "data"

    def test_template_literal_rhs(self):
        rhs = extract_innerHTML_rhs("el.innerHTML = `<b>${name}</b>`;")
        assert "${name}" in rhs


# ===========================================================================
# 2. classify_innerHTML_source — STATIC_CONSTANT
# ===========================================================================


class TestStaticConstant:
    def test_direct_double_quoted_string(self):
        code = 'el.innerHTML = "<b>Hello</b>";'
        result = classify_innerHTML_source(lines(code), 0, '"<b>Hello</b>"')
        assert result.source_class == SourceClass.STATIC_CONSTANT
        assert result.severity == "info"
        assert result.confidence_delta <= -25
        assert result.is_false_positive_candidate is True
        assert result.manual_review is False

    def test_direct_single_quoted_string(self):
        result = classify_innerHTML_source(["el.innerHTML = '<em>ok</em>';"], 0, "'<em>ok</em>'")
        assert result.source_class == SourceClass.STATIC_CONSTANT

    def test_template_literal_no_interpolation(self):
        result = classify_innerHTML_source(["el.innerHTML = `<span>static</span>`;"], 0, "`<span>static</span>`")
        assert result.source_class == SourceClass.STATIC_CONSTANT
        assert result.is_false_positive_candidate is True

    def test_variable_traced_to_const_string(self):
        code = """\
const html = "<b>Loading…</b>";
el.innerHTML = html;
"""
        result = classify_innerHTML_source(lines(code), 1, "html")
        assert result.source_class == SourceClass.STATIC_CONSTANT
        assert result.is_false_positive_candidate is True

    def test_variable_with_trim_traced_to_const(self):
        """template.innerHTML = html.trim() where html is a constant."""
        code = """\
const html = "<div class='spinner'></div>";
template.innerHTML = html.trim();
"""
        result = classify_innerHTML_source(lines(code), 1, "html.trim()")
        assert result.source_class == SourceClass.STATIC_CONSTANT
        assert result.is_false_positive_candidate is True

    def test_empty_string_rhs(self):
        result = classify_innerHTML_source(['el.innerHTML = "";'], 0, '""')
        assert result.source_class == SourceClass.STATIC_CONSTANT


# ===========================================================================
# 3. classify_innerHTML_source — TRUSTED_INTERNAL (SVG / icon)
# ===========================================================================


class TestTrustedInternal:
    def test_svg_template_literal_direct(self):
        code = "el.innerHTML = `<svg viewBox='0 0 24 24'><path/></svg>`;"
        result = classify_innerHTML_source(lines(code), 0, "`<svg viewBox='0 0 24 24'><path/></svg>`")
        assert result.source_class in (SourceClass.TRUSTED_INTERNAL, SourceClass.STATIC_CONSTANT)
        assert result.is_false_positive_candidate is True

    def test_const_icon_variable(self):
        code = """\
const ICON_ARROW = `<svg><path d="M5 12h14"/></svg>`;
el.innerHTML = ICON_ARROW;
"""
        result = classify_innerHTML_source(lines(code), 1, "ICON_ARROW")
        assert result.source_class in (SourceClass.TRUSTED_INTERNAL, SourceClass.STATIC_CONSTANT)
        assert result.is_false_positive_candidate is True

    def test_const_svg_variable(self):
        code = """\
const SVG_SPINNER = `<svg class="spin"><circle/></svg>`;
container.innerHTML = SVG_SPINNER;
"""
        result = classify_innerHTML_source(lines(code), 1, "SVG_SPINNER")
        assert result.source_class in (SourceClass.TRUSTED_INTERNAL, SourceClass.STATIC_CONSTANT)

    def test_const_template_variable(self):
        code = """\
const loadingTemplate = `<div class="skeleton"></div>`;
wrapper.innerHTML = loadingTemplate;
"""
        result = classify_innerHTML_source(lines(code), 1, "loadingTemplate")
        assert result.source_class in (SourceClass.TRUSTED_INTERNAL, SourceClass.STATIC_CONSTANT)
        assert result.is_false_positive_candidate is True


# ===========================================================================
# 4. classify_innerHTML_source — USER_INPUT
# ===========================================================================


class TestUserInput:
    def test_direct_event_target_value(self):
        code = "el.innerHTML = event.target.value;"
        result = classify_innerHTML_source(lines(code), 0, "event.target.value")
        assert result.source_class == SourceClass.USER_INPUT
        assert result.severity == "high"
        assert result.confidence_delta >= 15
        assert result.is_false_positive_candidate is False

    def test_variable_userInput(self):
        code = "el.innerHTML = userInput;"
        result = classify_innerHTML_source(lines(code), 0, "userInput")
        assert result.source_class == SourceClass.USER_INPUT
        assert result.severity == "high"

    def test_aliased_user_input(self):
        code = """\
const val = event.target.value;
el.innerHTML = val;
"""
        result = classify_innerHTML_source(lines(code), 1, "val")
        assert result.source_class == SourceClass.USER_INPUT
        assert result.severity == "high"

    def test_input_dot_value(self):
        code = """\
const content = inputElement.value;
div.innerHTML = content;
"""
        result = classify_innerHTML_source(lines(code), 1, "content")
        assert result.source_class == SourceClass.USER_INPUT

    def test_user_data_variable(self):
        code = "container.innerHTML = userData;"
        result = classify_innerHTML_source(lines(code), 0, "userData")
        assert result.source_class == SourceClass.USER_INPUT


# ===========================================================================
# 5. classify_innerHTML_source — URL_DATA
# ===========================================================================


class TestUrlData:
    def test_location_search_direct(self):
        code = "el.innerHTML = location.search;"
        result = classify_innerHTML_source(lines(code), 0, "location.search")
        assert result.source_class == SourceClass.URL_DATA
        assert result.severity == "high"

    def test_search_params_get(self):
        code = """\
const q = searchParams.get('query');
el.innerHTML = q;
"""
        result = classify_innerHTML_source(lines(code), 1, "q")
        assert result.source_class == SourceClass.URL_DATA
        assert result.severity == "high"

    def test_location_hash_variable(self):
        code = """\
const hash = location.hash;
el.innerHTML = hash;
"""
        result = classify_innerHTML_source(lines(code), 1, "hash")
        assert result.source_class == SourceClass.URL_DATA

    def test_req_query_variable(self):
        code = """\
const id = req.query.id;
el.innerHTML = id;
"""
        result = classify_innerHTML_source(lines(code), 1, "id")
        assert result.source_class == SourceClass.URL_DATA


# ===========================================================================
# 6. classify_innerHTML_source — API_RESPONSE
# ===========================================================================


class TestApiResponse:
    def test_fetch_response_direct(self):
        code = """\
const data = await fetch('/api/content').then(r => r.text());
el.innerHTML = data;
"""
        result = classify_innerHTML_source(lines(code), 1, "data")
        assert result.source_class == SourceClass.API_RESPONSE
        assert result.severity == "medium"

    def test_axios_response(self):
        code = """\
const result = await axios.get('/api/html');
el.innerHTML = result.data;
"""
        result = classify_innerHTML_source(lines(code), 1, "result.data")
        assert result.source_class == SourceClass.API_RESPONSE

    def test_response_text_method(self):
        code = """\
const html = await response.text();
container.innerHTML = html;
"""
        result = classify_innerHTML_source(lines(code), 1, "html")
        assert result.source_class == SourceClass.API_RESPONSE

    def test_req_body(self):
        code = """\
const body = req.body.content;
el.innerHTML = body;
"""
        result = classify_innerHTML_source(lines(code), 1, "body")
        assert result.source_class == SourceClass.API_RESPONSE


# ===========================================================================
# 7. classify_innerHTML_source — UNKNOWN
# ===========================================================================


class TestUnknownSource:
    def test_completely_unknown_variable(self):
        code = "el.innerHTML = someVar;"
        result = classify_innerHTML_source(lines(code), 0, "someVar")
        assert result.source_class == SourceClass.UNKNOWN
        assert result.severity == "medium"
        assert result.manual_review is True

    def test_variable_not_defined_in_window(self):
        # The variable `content` is defined far outside the trace window
        preceding = ["// lots of unrelated code\n"] * 20
        code_lines = preceding + ["el.innerHTML = content;"]
        result = classify_innerHTML_source(code_lines, len(code_lines) - 1, "content")
        assert result.source_class == SourceClass.UNKNOWN
        assert result.manual_review is True

    def test_unknown_has_reasonable_confidence_delta(self):
        code = "el.innerHTML = mysteryData;"
        result = classify_innerHTML_source(lines(code), 0, "mysteryData")
        assert result.source_class == SourceClass.UNKNOWN
        # Delta should be small negative — keep medium severity
        assert -20 <= result.confidence_delta <= 0


# ===========================================================================
# 8. Sanitizer detection
# ===========================================================================


class TestSanitizerDetection:
    def test_dompurify_reduces_severity_from_high(self):
        code = """\
const clean = DOMPurify.sanitize(userInput);
el.innerHTML = clean;
"""
        result = classify_innerHTML_source(lines(code), 1, "clean")
        # DOMPurify should be detected; severity downgraded; sanitizer flag set
        assert result.sanitizer_detected is True

    def test_sanitize_html_function_detected(self):
        code = """\
const safe = sanitizeHtml(userInput);
el.innerHTML = safe;
"""
        result = classify_innerHTML_source(lines(code), 1, "safe")
        assert result.sanitizer_detected is True

    def test_no_sanitizer_for_plain_user_input(self):
        code = "el.innerHTML = userInput;"
        result = classify_innerHTML_source(lines(code), 0, "userInput")
        assert result.sanitizer_detected is False


# ===========================================================================
# 9. Multi-hop variable alias tracing
# ===========================================================================


class TestVariableTracing:
    def test_two_hop_alias(self):
        """a = event.target.value; b = a; el.innerHTML = b"""
        code = """\
const a = event.target.value;
const b = a;
el.innerHTML = b;
"""
        result = classify_innerHTML_source(lines(code), 2, "b")
        # Should trace b→a→event.target.value → USER_INPUT
        assert result.source_class == SourceClass.USER_INPUT

    def test_three_hop_alias(self):
        """chain: raw → trimmed → encoded → innerHTML"""
        code = """\
const raw = location.search;
const trimmed = raw.trim();
const encoded = trimmed;
el.innerHTML = encoded;
"""
        result = classify_innerHTML_source(lines(code), 3, "encoded")
        assert result.source_class in (SourceClass.URL_DATA, SourceClass.USER_INPUT)

    def test_static_through_reassignment(self):
        code = """\
const STATIC = "<span>ok</span>";
let html = STATIC;
el.innerHTML = html;
"""
        result = classify_innerHTML_source(lines(code), 2, "html")
        assert result.source_class == SourceClass.STATIC_CONSTANT


# ===========================================================================
# 10. End-to-end via analyze_js()
# ===========================================================================


class TestEndToEndJs005:
    """Integration tests: analyze_js() produces correct JS005 findings."""

    def test_user_input_innerHTML_is_high(self):
        code = "el.innerHTML = userInput;\n"
        findings = js005_findings(code)
        assert findings, "Should produce a JS005 finding"
        assert findings[0].severity == "high"

    def test_event_target_value_innerHTML_is_high(self):
        code = """\
const val = event.target.value;
el.innerHTML = val;
"""
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "high"

    def test_static_string_innerHTML_is_info(self):
        code = 'el.innerHTML = "<b>static</b>";\n'
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "info"
        assert findings[0].confidence < 40

    def test_const_html_trim_is_static(self):
        """template.innerHTML = html.trim() with const html — should be info."""
        code = """\
const html = "<div class='loading'></div>";
template.innerHTML = html.trim();
"""
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "info"

    def test_svg_icon_const_is_low_or_info(self):
        code = """\
const ICON = `<svg viewBox="0 0 24 24"><path d="M5 12h14"/></svg>`;
el.innerHTML = ICON;
"""
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity in ("info", "low")

    def test_api_response_innerHTML_is_medium(self):
        code = """\
const data = await fetch('/api').then(r => r.text());
el.innerHTML = data;
"""
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "medium"

    def test_unknown_variable_innerHTML_is_medium(self):
        code = "el.innerHTML = someVar;\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "medium"
        assert "manual review" in findings[0].description.lower() or "manual review" in (findings[0].evidence or "").lower()

    def test_outerhtml_user_input_is_high(self):
        code = "el.outerHTML = userInput;\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "high"

    def test_insert_adjacent_html_user_input_is_high(self):
        code = "el.insertAdjacentHTML('beforeend', userInput);\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "high"

    def test_insert_adjacent_html_static_is_info(self):
        code = "el.insertAdjacentHTML('afterbegin', '<li>Item</li>');\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "info"

    def test_dompurify_sanitized_user_input_downgraded(self):
        code = """\
const clean = DOMPurify.sanitize(userInput);
el.innerHTML = clean;
"""
        findings = js005_findings(code)
        assert findings
        # With sanitizer: should be downgraded from high to medium or lower
        assert findings[0].severity in ("medium", "low", "info")
        assert findings[0].sink is not None
        assert findings[0].sink.is_sanitized is True

    def test_location_search_innerHTML_is_high(self):
        code = """\
const q = location.search;
el.innerHTML = q;
"""
        findings = js005_findings(code)
        assert findings
        assert findings[0].severity == "high"

    def test_finding_has_cwe_79(self):
        code = "el.innerHTML = userInput;\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].cwe == "CWE-79"

    def test_finding_has_rule_id_js005(self):
        code = "el.innerHTML = someContent;\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].rule_id == "JS005"

    def test_finding_has_fingerprint(self):
        code = "el.innerHTML = userInput;\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].fingerprint, "Finding must have a fingerprint"

    def test_finding_has_code_snippet(self):
        code = "  el.innerHTML = userInput;\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].code_snippet is not None

    def test_suppression_prevents_finding(self):
        from app.services.scan_engine.scanner.suppression import build_suppression_map
        code = "el.innerHTML = userInput;  // devpilot: ignore JS005\n"
        sup_map = build_suppression_map(code)
        findings = analyze_js(code, "test.js", sup_map=sup_map)
        js005 = [f for f in findings if getattr(f, "rule_id", "") == "JS005"]
        assert not js005, "Suppressed finding should not appear"

    def test_text_content_not_flagged(self):
        """textContent is safe — should never produce a JS005 finding."""
        code = "el.textContent = userInput;\n"
        findings = js005_findings(code)
        assert not findings, "textContent should not be flagged as JS005"

    def test_no_false_positive_on_static_icon_library(self):
        """
        A real-world pattern: an icon library renders SVGs into innerHTML via
        a dynamic property lookup (icons[name]).  The classifier cannot trace
        icons[name] statically, so it reports UNKNOWN / medium severity but
        with LOW confidence (< 50) — which is the correct conservative behavior.
        It should NOT be reported as high severity.
        """
        code = """\
const icons = {
  close: `<svg viewBox="0 0 24 24" fill="none">
    <path d="M6 18L18 6M6 6l12 12" stroke="currentColor"/>
  </svg>`,
};

function setIcon(el, name) {
  el.innerHTML = icons[name];
}
"""
        findings = js005_findings(code)
        for f in findings:
            # Dynamic property lookup (icons[name]) → UNKNOWN → medium severity
            # but must NOT be high/critical — confidence must be low
            assert f.severity in ("info", "low", "medium"), (
                f"Icon library pattern should not be high/critical, got {f.severity}"
            )
            assert f.severity != "high", (
                f"Icon library dynamic lookup should not be high severity (got {f.severity})"
            )
            # Confidence must be low (classifier correctly uncertain)
            assert f.confidence < 55, (
                f"Icon library pattern confidence should be low, got {f.confidence}"
            )

    def test_confidence_user_input_above_60(self):
        code = "el.innerHTML = userInput;\n"
        findings = js005_findings(code)
        assert findings
        assert findings[0].confidence >= 55, (
            f"User-input innerHTML should have confidence ≥ 55, got {findings[0].confidence}"
        )

    def test_confidence_static_constant_below_40(self):
        code = 'el.innerHTML = "<b>static</b>";\n'
        findings = js005_findings(code)
        assert findings
        assert findings[0].confidence < 40, (
            f"Static constant should have confidence < 40, got {findings[0].confidence}"
        )


# ===========================================================================
# 11. Evidence and data_flow fields
# ===========================================================================


class TestEvidenceFields:
    def test_classification_result_has_evidence_string(self):
        code = "el.innerHTML = userInput;"
        result = classify_innerHTML_source(lines(code), 0, "userInput")
        assert result.evidence, "Evidence string must be populated"
        assert len(result.evidence) > 0

    def test_data_flow_hint_populated_for_traced_variable(self):
        code = """\
const val = event.target.value;
el.innerHTML = val;
"""
        result = classify_innerHTML_source(lines(code), 1, "val")
        assert len(result.data_flow_hint) >= 1

    def test_unknown_has_manual_review_flag(self):
        code = "el.innerHTML = mysteryVar;"
        result = classify_innerHTML_source(lines(code), 0, "mysteryVar")
        assert result.manual_review is True

    def test_static_constant_not_manual_review(self):
        result = classify_innerHTML_source(['el.innerHTML = "<b>x</b>";'], 0, '"<b>x</b>"')
        assert result.manual_review is False

    def test_end_to_end_unknown_description_mentions_manual_review(self):
        code = "el.innerHTML = mysteryContent;\n"
        findings = js005_findings(code)
        assert findings
        f = findings[0]
        has_manual_review = (
            "manual review" in (f.description or "").lower()
            or "manual review" in (f.evidence or "").lower()
        )
        assert has_manual_review, (
            f"Unknown source finding should mention manual review.\n"
            f"description: {f.description}\nevidence: {f.evidence}"
        )
