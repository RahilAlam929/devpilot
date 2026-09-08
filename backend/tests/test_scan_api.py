"""
Tests for POST/GET /api/scans and related endpoints.

Covers:
  - POST /api/scans: schema — only repository_id accepted, no repository_path
  - POST /api/scans: returns 201 + pending scan immediately
  - POST /api/scans: background task is enqueued (mocked, not executed)
  - POST /api/scans: 404 when repository belongs to another user
  - POST /api/scans: 404 when repository does not exist
  - POST /api/scans: 422 when stored URL is not a valid GitHub URL
  - GET  /api/scans: lists scans for owned repository
  - GET  /api/scans: 404 for unowned repository
  - GET  /api/scans/{id}: returns scan for owner
  - GET  /api/scans/{id}: 404 for unowned scan
  - GET  /api/scans/{id}/summary: returns summary
  - GET  /api/scans/{id}/findings: returns findings list
"""

from unittest.mock import patch, MagicMock

import pytest


class TestScanCreate:
    def test_creates_scan_with_repository_id_only(self, client, repository):
        """POST /api/scans must accept only repository_id (no repository_path)."""
        with patch("app.api.scans.run_scan_background"):
            resp = client.post("/api/scans", json={"repository_id": repository.id})

        assert resp.status_code == 201
        data = resp.json()
        assert data["repository_id"] == repository.id
        assert data["status"] == "pending"
        assert "id" in data

    def test_scan_create_rejects_extra_repository_path_field(self, client, repository):
        """repository_path must be silently ignored / not accepted in schema."""
        with patch("app.api.scans.run_scan_background"):
            resp = client.post(
                "/api/scans",
                json={
                    "repository_id": repository.id,
                    "repository_path": "/tmp/some/path",  # must be ignored
                },
            )
        # Should still succeed (extra field is ignored by pydantic), or 422
        # Either way, repository_path must NOT appear in the response.
        if resp.status_code == 201:
            assert "repository_path" not in resp.json()
        else:
            # Strict mode might reject — that's also acceptable
            assert resp.status_code == 422

    def test_scan_create_requires_repository_id(self, client):
        """Omitting repository_id must result in a 422."""
        resp = client.post("/api/scans", json={})
        assert resp.status_code == 422

    def test_scan_create_404_for_unknown_repository(self, client):
        """Repository that doesn't exist → 404."""
        with patch("app.api.scans.run_scan_background"):
            resp = client.post("/api/scans", json={"repository_id": "nonexistent-id"})
        assert resp.status_code == 404

    def test_scan_create_404_for_other_users_repository(
        self, client, other_repository
    ):
        """Repository owned by a different user → 404 (not 403, to avoid leaking existence)."""
        with patch("app.api.scans.run_scan_background"):
            resp = client.post(
                "/api/scans", json={"repository_id": other_repository.id}
            )
        assert resp.status_code == 404

    def test_scan_create_422_for_invalid_stored_url(self, client, db, project):
        """If the stored URL is not a valid GitHub URL, return 422 immediately."""
        from app.models.models import Repository as RepoModel

        # Insert a repo with a bad URL directly (bypassing API validation)
        bad_repo = RepoModel(
            name="bad-url-repo",
            url="file:///etc/passwd",
            project_id=project.id,
        )
        db.add(bad_repo)
        db.commit()
        db.refresh(bad_repo)

        with patch("app.api.scans.run_scan_background"):
            resp = client.post("/api/scans", json={"repository_id": bad_repo.id})
        assert resp.status_code == 422

    def test_background_task_receives_validated_url(self, client, repository):
        """The background task must be called with the normalised .git URL."""
        with patch("app.api.scans.BackgroundTasks.add_task") as mock_add:
            resp = client.post("/api/scans", json={"repository_id": repository.id})

        assert resp.status_code == 201
        # Background task was registered
        assert mock_add.called

        # The URL argument (4th positional) must be the canonical .git form
        call_args = mock_add.call_args
        # add_task(func, scan_id, repo_id, url, timeout)
        args = call_args[0]  # positional args tuple
        url_arg = args[3]    # 4th arg is repository_url
        assert url_arg.endswith(".git")
        assert url_arg.startswith("https://github.com/")

    def test_scan_returns_pending_status_immediately(self, client, repository):
        """The HTTP response must return before the scan finishes."""
        with patch("app.api.scans.run_scan_background"):
            resp = client.post("/api/scans", json={"repository_id": repository.id})

        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"


class TestScanList:
    def test_list_scans_for_owned_repository(self, client, scan, repository):
        resp = client.get(f"/api/scans?repository_id={repository.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert any(s["id"] == scan.id for s in data)

    def test_list_scans_404_for_unknown_repository(self, client):
        resp = client.get("/api/scans?repository_id=does-not-exist")
        assert resp.status_code == 404

    def test_list_scans_404_for_other_users_repository(
        self, client, other_repository
    ):
        resp = client.get(f"/api/scans?repository_id={other_repository.id}")
        assert resp.status_code == 404

    def test_list_scans_empty_for_new_repository(self, client, repository):
        resp = client.get(f"/api/scans?repository_id={repository.id}")
        assert resp.status_code == 200
        assert resp.json() == []


class TestScanGet:
    def test_get_owned_scan(self, client, scan):
        resp = client.get(f"/api/scans/{scan.id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == scan.id

    def test_get_scan_404_for_unknown_id(self, client):
        resp = client.get("/api/scans/nonexistent")
        assert resp.status_code == 404

    def test_get_scan_404_for_other_users_scan(self, client, db, other_repository):
        from app.models.models import Scan as ScanModel

        other_scan = ScanModel(
            repository_id=other_repository.id, status="pending"
        )
        db.add(other_scan)
        db.commit()
        db.refresh(other_scan)

        resp = client.get(f"/api/scans/{other_scan.id}")
        assert resp.status_code == 404


class TestScanSummary:
    def test_get_summary_for_owned_scan(self, client, scan):
        resp = client.get(f"/api/scans/{scan.id}/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan.id
        assert "total_findings" in data
        assert "high" in data
        assert "medium" in data
        assert "low" in data
        assert "info" in data

    def test_summary_counts_findings_by_severity(self, client, db, scan):
        from app.models.models import Finding as FindingModel

        for severity in ["high", "high", "medium", "low", "info"]:
            db.add(FindingModel(
                scan_id=scan.id,
                severity=severity,
                title="Test",
                description="desc",
            ))
        db.commit()

        resp = client.get(f"/api/scans/{scan.id}/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_findings"] == 5
        assert data["high"] == 2
        assert data["medium"] == 1
        assert data["low"] == 1
        assert data["info"] == 1

    def test_summary_404_for_unknown_scan(self, client):
        resp = client.get("/api/scans/nonexistent/summary")
        assert resp.status_code == 404


class TestScanFindings:
    def test_list_findings_for_owned_scan(self, client, db, scan):
        from app.models.models import Finding as FindingModel

        f = FindingModel(
            scan_id=scan.id,
            severity="high",
            title="Hardcoded secret",
            description="Found API_KEY",
            file_path="src/config.py",
            line_number=42,
        )
        db.add(f)
        db.commit()

        resp = client.get(f"/api/scans/{scan.id}/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "high"
        assert data[0]["file_path"] == "src/config.py"
        assert data[0]["line_number"] == 42

    def test_list_findings_empty_for_new_scan(self, client, scan):
        resp = client.get(f"/api/scans/{scan.id}/findings")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_findings_404_for_unknown_scan(self, client):
        resp = client.get("/api/scans/nonexistent/findings")
        assert resp.status_code == 404
