"""
Tests for POST/GET /api/repositories.

Covers:
  - POST /api/repositories: valid GitHub HTTPS URL accepted and normalised
  - POST /api/repositories: various invalid URLs rejected with 422
  - POST /api/repositories: 404 when project belongs to another user
  - POST /api/repositories: 404 when project does not exist
  - GET  /api/repositories: lists repos for owned project
  - GET  /api/repositories: 404 for unowned project
  - GET  /api/repositories/{id}: returns repo for owner
  - GET  /api/repositories/{id}: 404 for unowned repo
  - Stored URL is the canonical .git normalised form
"""

import pytest


VALID_GITHUB_URL = "https://github.com/owner/repo"
CANONICAL_GITHUB_URL = "https://github.com/owner/repo.git"


class TestRepositoryCreate:
    def test_create_with_valid_github_url(self, client, project):
        resp = client.post(
            "/api/repositories",
            json={
                "name": "My Repo",
                "url": VALID_GITHUB_URL,
                "project_id": project.id,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My Repo"
        assert data["project_id"] == project.id
        assert "id" in data

    def test_stored_url_is_normalised_with_git_suffix(self, client, project):
        """URL without .git must be stored in canonical .git form."""
        resp = client.post(
            "/api/repositories",
            json={
                "name": "Repo",
                "url": "https://github.com/owner/repo",
                "project_id": project.id,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["url"] == CANONICAL_GITHUB_URL

    def test_create_with_git_suffix_url_accepted(self, client, project):
        resp = client.post(
            "/api/repositories",
            json={
                "name": "Repo",
                "url": "https://github.com/owner/repo.git",
                "project_id": project.id,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["url"] == CANONICAL_GITHUB_URL

    def test_create_404_for_unknown_project(self, client):
        resp = client.post(
            "/api/repositories",
            json={
                "name": "Repo",
                "url": VALID_GITHUB_URL,
                "project_id": "nonexistent-project",
            },
        )
        assert resp.status_code == 404

    def test_create_404_for_other_users_project(self, client, other_project):
        resp = client.post(
            "/api/repositories",
            json={
                "name": "Repo",
                "url": VALID_GITHUB_URL,
                "project_id": other_project.id,
            },
        )
        assert resp.status_code == 404

    # ── Invalid URL cases ─────────────────────────────────────────────────

    @pytest.mark.parametrize("bad_url", [
        "http://github.com/owner/repo",           # http, not https
        "git://github.com/owner/repo.git",        # git scheme
        "ssh://git@github.com/owner/repo.git",    # ssh scheme
        "git@github.com:owner/repo.git",          # SSH shorthand
        "file:///home/user/repo",                 # local file
        "https://gitlab.com/owner/repo",          # wrong host
        "https://bitbucket.org/owner/repo",       # wrong host
        "https://localhost/owner/repo",           # localhost
        "https://192.168.1.1/owner/repo",         # private IP
        "https://evil.com/owner/repo",            # untrusted host
        "https://github.com/owner",               # missing repo segment
        "https://github.com/",                    # root path
        "https://user:pass@github.com/owner/repo",# credentials
        "https://github.com:8080/owner/repo",     # non-standard port
        "https://github.com/owner/repo?foo=bar",  # query string
        "https://github.com/owner/repo#readme",   # fragment
        "/home/user/repo",                        # absolute path
        "./local/repo",                           # relative path
        "",                                       # empty
        "   ",                                    # whitespace only
    ])
    def test_invalid_url_returns_422(self, client, project, bad_url):
        resp = client.post(
            "/api/repositories",
            json={
                "name": "Repo",
                "url": bad_url,
                "project_id": project.id,
            },
        )
        assert resp.status_code == 422, \
            f"Expected 422 for URL {bad_url!r}, got {resp.status_code}: {resp.text}"

    def test_invalid_url_error_message_is_user_friendly(self, client, project):
        resp = client.post(
            "/api/repositories",
            json={
                "name": "Repo",
                "url": "http://github.com/owner/repo",
                "project_id": project.id,
            },
        )
        assert resp.status_code == 422
        detail = resp.json().get("detail", "")
        # Should mention https or GitHub, not expose internal traceback
        assert "https" in detail.lower() or "github" in detail.lower()
        assert "traceback" not in detail.lower()
        assert "exception" not in detail.lower()


class TestRepositoryList:
    def test_list_repos_for_owned_project(self, client, repository, project):
        resp = client.get(f"/api/repositories?project_id={project.id}")
        assert resp.status_code == 200
        ids = [r["id"] for r in resp.json()]
        assert repository.id in ids

    def test_list_repos_empty_for_new_project(self, client, project):
        resp = client.get(f"/api/repositories?project_id={project.id}")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_repos_404_for_unknown_project(self, client):
        resp = client.get("/api/repositories?project_id=does-not-exist")
        assert resp.status_code == 404

    def test_list_repos_404_for_other_users_project(self, client, other_project):
        resp = client.get(f"/api/repositories?project_id={other_project.id}")
        assert resp.status_code == 404


class TestRepositoryGet:
    def test_get_owned_repository(self, client, repository):
        resp = client.get(f"/api/repositories/{repository.id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == repository.id

    def test_get_repository_404_for_unknown_id(self, client):
        resp = client.get("/api/repositories/nonexistent")
        assert resp.status_code == 404

    def test_get_repository_404_for_other_users_repo(self, client, other_repository):
        resp = client.get(f"/api/repositories/{other_repository.id}")
        assert resp.status_code == 404
