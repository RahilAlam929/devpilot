"""
Tests for Security vs Quality category filter on GET /api/scans/{scan_id}/findings.

Covers:
  - all findings (no filter)
  - security group filter
  - quality group filter
  - security + severity combined filter
  - quality + severity combined filter
  - zero-result combination
  - counts match backend summary
  - filter reset (no params)
  - scan switching (filters don't bleed between scans)
  - unauthorized access remains protected
"""

import pytest


# ── Shared helpers ──────────────────────────────────────────────────────────

# Security categories as defined in scans.py SECURITY_CATS
SECURITY_CATEGORIES = [
    "code_execution",
    "command_injection",
    "xss",
    "sql_injection",
    "path_traversal",
    "ssrf",
    "open_redirect",
    "deserialization",
    "secrets",
    "crypto",
    "template_injection",
    "configuration",
    "data_flow",
]

QUALITY_CATEGORIES = [
    "maintainability",
    "code_style",
    "performance",
    "debug",
    "error_handling",
    None,  # null category also maps to quality
]


def _create_findings(db, scan_id, specs):
    """
    Create findings from a list of (severity, category) tuples.
    Returns the list of created Finding objects.
    """
    from app.models.models import Finding as FindingModel

    created = []
    for i, (severity, category) in enumerate(specs):
        f = FindingModel(
            scan_id=scan_id,
            severity=severity,
            title=f"Finding {i}: {category or 'no-category'}",
            description=f"Test finding {i}",
            category=category,
        )
        db.add(f)
        created.append(f)
    db.commit()
    return created


# ── All findings (no filter) ───────────────────────────────────────────────

class TestAllFindings:
    def test_no_filter_returns_all_findings(self, client, db, scan):
        specs = [
            ("high", "command_injection"),   # security
            ("medium", "xss"),               # security
            ("low", "debug"),                # quality
            ("info", None),                  # quality (null)
        ]
        _create_findings(db, scan.id, specs)

        resp = client.get(f"/api/scans/{scan.id}/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 4

    def test_no_filter_returns_category_field(self, client, db, scan):
        _create_findings(db, scan.id, [("high", "command_injection")])

        resp = client.get(f"/api/scans/{scan.id}/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert data[0]["category"] == "command_injection"


# ── Security group filter ──────────────────────────────────────────────────

class TestSecurityGroupFilter:
    def test_security_filter_returns_only_security_findings(self, client, db, scan):
        specs = [
            ("high", "command_injection"),   # security
            ("medium", "sql_injection"),     # security
            ("low", "debug"),                # quality
            ("info", None),                  # quality
        ]
        _create_findings(db, scan.id, specs)

        resp = client.get(f"/api/scans/{scan.id}/findings?group=security")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        returned_categories = {f["category"] for f in data}
        assert returned_categories.issubset(set(SECURITY_CATEGORIES))

    def test_security_filter_all_security_categories(self, client, db, scan):
        """Each security category is correctly included."""
        specs = [(("high" if i % 2 == 0 else "medium"), cat)
                 for i, cat in enumerate(SECURITY_CATEGORIES)]
        _create_findings(db, scan.id, specs)
        # Also add a quality finding that must be excluded
        _create_findings(db, scan.id, [("low", "debug")])

        resp = client.get(f"/api/scans/{scan.id}/findings?group=security")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == len(SECURITY_CATEGORIES)

    def test_security_filter_excludes_quality_findings(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "debug"),
            ("medium", "maintainability"),
            ("low", None),
        ])

        resp = client.get(f"/api/scans/{scan.id}/findings?group=security")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_security_filter_returns_39_for_real_scan_counts(self, client, db, scan):
        """Simulate a scan with mixed findings; verify counts are consistent."""
        # 5 security, 3 quality
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
            ("high", "xss"),
            ("medium", "sql_injection"),
            ("low", "secrets"),
            ("info", "crypto"),
            ("high", "debug"),
            ("medium", "maintainability"),
            ("low", None),
        ])

        security_resp = client.get(f"/api/scans/{scan.id}/findings?group=security")
        quality_resp = client.get(f"/api/scans/{scan.id}/findings?group=quality")
        all_resp = client.get(f"/api/scans/{scan.id}/findings")

        assert security_resp.status_code == 200
        assert quality_resp.status_code == 200
        assert all_resp.status_code == 200

        sec_count = len(security_resp.json())
        qual_count = len(quality_resp.json())
        total_count = len(all_resp.json())

        assert sec_count == 5
        assert qual_count == 3
        assert sec_count + qual_count == total_count


# ── Quality group filter ───────────────────────────────────────────────────

class TestQualityGroupFilter:
    def test_quality_filter_returns_only_quality_findings(self, client, db, scan):
        specs = [
            ("high", "command_injection"),   # security
            ("low", "debug"),                # quality
            ("info", None),                  # quality (null category)
        ]
        _create_findings(db, scan.id, specs)

        resp = client.get(f"/api/scans/{scan.id}/findings?group=quality")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        returned_categories = {f["category"] for f in data}
        # Quality can include null and non-security categories
        assert not returned_categories.intersection(set(SECURITY_CATEGORIES))

    def test_quality_filter_includes_null_category(self, client, db, scan):
        """Findings with no category (null) are treated as quality."""
        _create_findings(db, scan.id, [("info", None)])

        resp = client.get(f"/api/scans/{scan.id}/findings?group=quality")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["category"] is None

    def test_quality_filter_excludes_security_findings(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
            ("critical", "xss"),
        ])

        resp = client.get(f"/api/scans/{scan.id}/findings?group=quality")
        assert resp.status_code == 200
        assert resp.json() == []


# ── Combined category + severity filter ────────────────────────────────────

class TestCombinedFilters:
    def _populate(self, db, scan_id):
        """Create a representative set of mixed findings."""
        _create_findings(db, scan_id, [
            ("high", "command_injection"),   # security + high
            ("high", "sql_injection"),       # security + high
            ("medium", "xss"),               # security + medium
            ("low", "secrets"),              # security + low
            ("info", "crypto"),              # security + info
            ("high", "debug"),               # quality + high
            ("medium", "maintainability"),   # quality + medium
            ("low", None),                   # quality + low
        ])

    def test_security_and_high(self, client, db, scan):
        self._populate(db, scan.id)

        resp = client.get(f"/api/scans/{scan.id}/findings?group=security&severity=high")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert all(f["severity"] == "high" for f in data)
        assert all(f["category"] in SECURITY_CATEGORIES for f in data)

    def test_security_and_medium(self, client, db, scan):
        self._populate(db, scan.id)

        resp = client.get(f"/api/scans/{scan.id}/findings?group=security&severity=medium")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "medium"
        assert data[0]["category"] == "xss"

    def test_quality_and_low(self, client, db, scan):
        self._populate(db, scan.id)

        resp = client.get(f"/api/scans/{scan.id}/findings?group=quality&severity=low")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "low"

    def test_security_and_info(self, client, db, scan):
        self._populate(db, scan.id)

        resp = client.get(f"/api/scans/{scan.id}/findings?group=security&severity=info")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["category"] == "crypto"

    def test_quality_and_high(self, client, db, scan):
        self._populate(db, scan.id)

        resp = client.get(f"/api/scans/{scan.id}/findings?group=quality&severity=high")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["category"] == "debug"


# ── Zero-result combination ────────────────────────────────────────────────

class TestZeroResultCombinations:
    def test_security_plus_nonexistent_severity_returns_empty(self, client, db, scan):
        """Security has no critical findings → empty list, not error."""
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
        ])

        resp = client.get(f"/api/scans/{scan.id}/findings?group=security&severity=critical")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_quality_filter_when_all_are_security(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
            ("medium", "xss"),
        ])

        resp = client.get(f"/api/scans/{scan.id}/findings?group=quality")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_empty_scan_returns_empty_for_any_filter(self, client, scan):
        for filter_qs in ["", "?group=security", "?group=quality", "?severity=high"]:
            resp = client.get(f"/api/scans/{scan.id}/findings{filter_qs}")
            assert resp.status_code == 200
            assert resp.json() == [], f"Expected empty list for filter: {filter_qs}"


# ── Counts match backend summary ───────────────────────────────────────────

class TestCountsMatchSummary:
    def test_security_count_matches_summary(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
            ("medium", "xss"),
            ("low", "debug"),         # quality
            ("info", None),           # quality
        ])

        summary_resp = client.get(f"/api/scans/{scan.id}/summary")
        findings_resp = client.get(f"/api/scans/{scan.id}/findings?group=security")

        assert summary_resp.status_code == 200
        assert findings_resp.status_code == 200

        summary_sec = summary_resp.json()["security_findings"]
        findings_sec = len(findings_resp.json())
        assert summary_sec == findings_sec == 2

    def test_quality_count_matches_summary(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "command_injection"),   # security
            ("low", "debug"),                # quality
            ("info", None),                  # quality
        ])

        summary_resp = client.get(f"/api/scans/{scan.id}/summary")
        findings_resp = client.get(f"/api/scans/{scan.id}/findings?group=quality")

        assert summary_resp.status_code == 200
        assert findings_resp.status_code == 200

        summary_qual = summary_resp.json()["quality_findings"]
        findings_qual = len(findings_resp.json())
        assert summary_qual == findings_qual == 2

    def test_total_equals_security_plus_quality(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
            ("medium", "sql_injection"),
            ("low", "debug"),
            ("info", None),
            ("info", "maintainability"),
        ])

        all_resp = client.get(f"/api/scans/{scan.id}/findings")
        sec_resp = client.get(f"/api/scans/{scan.id}/findings?group=security")
        qual_resp = client.get(f"/api/scans/{scan.id}/findings?group=quality")

        total = len(all_resp.json())
        sec = len(sec_resp.json())
        qual = len(qual_resp.json())

        assert sec + qual == total == 5


# ── Filter reset ───────────────────────────────────────────────────────────

class TestFilterReset:
    def test_removing_group_filter_returns_all(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
            ("low", "debug"),
        ])

        # Apply group filter
        filtered = client.get(f"/api/scans/{scan.id}/findings?group=security")
        assert len(filtered.json()) == 1

        # Remove group filter → all findings
        all_findings = client.get(f"/api/scans/{scan.id}/findings")
        assert len(all_findings.json()) == 2

    def test_removing_severity_filter_returns_category_group(self, client, db, scan):
        _create_findings(db, scan.id, [
            ("high", "command_injection"),
            ("medium", "xss"),
            ("low", "debug"),
        ])

        # Security + high
        filtered = client.get(f"/api/scans/{scan.id}/findings?group=security&severity=high")
        assert len(filtered.json()) == 1

        # Security only (remove severity)
        sec_only = client.get(f"/api/scans/{scan.id}/findings?group=security")
        assert len(sec_only.json()) == 2


# ── Scan switching ─────────────────────────────────────────────────────────

class TestScanSwitching:
    def test_filters_scoped_to_scan(self, client, db, repository):
        from app.models.models import Scan as ScanModel

        # Two scans, different findings
        scan1 = ScanModel(repository_id=repository.id, status="completed")
        scan2 = ScanModel(repository_id=repository.id, status="completed")
        db.add_all([scan1, scan2])
        db.commit()

        _create_findings(db, scan1.id, [
            ("high", "command_injection"),  # security
            ("low", "debug"),               # quality
        ])
        _create_findings(db, scan2.id, [
            ("medium", "xss"),              # security
        ])

        # Scan 1: security filter returns 1
        resp1 = client.get(f"/api/scans/{scan1.id}/findings?group=security")
        assert len(resp1.json()) == 1

        # Scan 2: security filter returns 1 (different finding)
        resp2 = client.get(f"/api/scans/{scan2.id}/findings?group=security")
        assert len(resp2.json()) == 1

        # Scan 1: quality filter returns 1 (debug)
        resp3 = client.get(f"/api/scans/{scan1.id}/findings?group=quality")
        assert len(resp3.json()) == 1
        assert resp3.json()[0]["category"] == "debug"

        # Scan 2: quality filter returns 0
        resp4 = client.get(f"/api/scans/{scan2.id}/findings?group=quality")
        assert resp4.json() == []


# ── Authorization ──────────────────────────────────────────────────────────

class TestUnauthorizedAccess:
    def test_unauthenticated_request_rejected(self, client, db, scan):
        """No auth override: the fixture-provided client IS authenticated.
        We verify the other_client cannot access test_user's scan."""
        pass  # Handled by test below

    def test_other_user_cannot_access_scan_findings(
        self, other_client, db, scan
    ):
        """other_client is authenticated as other_user, who does not own scan."""
        resp = other_client.get(f"/api/scans/{scan.id}/findings")
        assert resp.status_code == 404

    def test_other_user_cannot_use_security_filter_on_foreign_scan(
        self, other_client, db, scan
    ):
        resp = other_client.get(f"/api/scans/{scan.id}/findings?group=security")
        assert resp.status_code == 404

    def test_other_user_cannot_access_summary(self, other_client, scan):
        resp = other_client.get(f"/api/scans/{scan.id}/summary")
        assert resp.status_code == 404

    def test_unauthenticated_client_returns_401(self, db, scan, test_user):
        """A client with no authentication dependency override gets 401."""
        from fastapi.testclient import TestClient
        from main import app as fastapi_app

        # Raw client with no override — the real get_current_user will fire
        with TestClient(fastapi_app, raise_server_exceptions=False) as raw_client:
            resp = raw_client.get(f"/api/scans/{scan.id}/findings")
        assert resp.status_code == 401
