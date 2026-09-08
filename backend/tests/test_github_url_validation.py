"""
Tests for validate_github_url().

Covers:
  - Valid HTTPS GitHub URLs (with and without .git)
  - Normalisation: always returns https://github.com/<owner>/<repo>.git
  - Rejection of wrong scheme (http, git, ssh, ftp, file)
  - Rejection of SSH shorthand (git@github.com:...)
  - Rejection of wrong host (gitlab, bitbucket, localhost, IP addresses)
  - Rejection of embedded credentials
  - Rejection of non-standard ports
  - Rejection of query strings and fragments
  - Rejection of local/relative paths
  - Rejection of paths with too many or too few segments
  - Rejection of empty / non-string input
  - Edge cases: single-char names, max-length names, dots-only names
"""

import pytest

from app.services.github.repository import (
    GitHubURLValidationError,
    validate_github_url,
)


# ── Helpers ────────────────────────────────────────────────────────────────

def valid(url: str) -> str:
    """Assert no exception and return the normalised URL."""
    return validate_github_url(url)


def invalid(url: str) -> str:
    """Assert GitHubURLValidationError is raised; return its message."""
    with pytest.raises(GitHubURLValidationError) as exc_info:
        validate_github_url(url)
    return str(exc_info.value)


# ── Valid URLs ─────────────────────────────────────────────────────────────

class TestValidURLs:
    def test_bare_url(self):
        result = valid("https://github.com/owner/repo")
        assert result == "https://github.com/owner/repo.git"

    def test_url_with_git_suffix(self):
        result = valid("https://github.com/owner/repo.git")
        assert result == "https://github.com/owner/repo.git"

    def test_leading_trailing_whitespace_stripped(self):
        result = valid("  https://github.com/owner/repo  ")
        assert result == "https://github.com/owner/repo.git"

    def test_hyphens_in_owner(self):
        result = valid("https://github.com/my-org/my-repo")
        assert result == "https://github.com/my-org/my-repo.git"

    def test_underscores_in_repo(self):
        result = valid("https://github.com/owner/my_repo")
        assert result == "https://github.com/owner/my_repo.git"

    def test_dots_in_repo(self):
        result = valid("https://github.com/owner/my.repo")
        assert result == "https://github.com/owner/my.repo.git"

    def test_numbers_in_names(self):
        result = valid("https://github.com/user123/repo456")
        assert result == "https://github.com/user123/repo456.git"

    def test_single_char_owner_and_repo(self):
        result = valid("https://github.com/a/b")
        assert result == "https://github.com/a/b.git"

    def test_max_length_owner_39_chars(self):
        owner = "a" * 39
        result = valid(f"https://github.com/{owner}/repo")
        assert result == f"https://github.com/{owner}/repo.git"

    def test_real_world_url(self):
        result = valid("https://github.com/torvalds/linux")
        assert result == "https://github.com/torvalds/linux.git"

    def test_real_world_url_with_git(self):
        result = valid("https://github.com/torvalds/linux.git")
        assert result == "https://github.com/torvalds/linux.git"

    def test_org_with_capital_letters(self):
        result = valid("https://github.com/MyOrg/MyRepo")
        assert result == "https://github.com/MyOrg/MyRepo.git"

    def test_trailing_slash_on_url_ignored(self):
        # path after strip("/") should still match
        result = valid("https://github.com/owner/repo/")
        assert result == "https://github.com/owner/repo.git"


# ── Invalid: wrong scheme ──────────────────────────────────────────────────

class TestWrongScheme:
    def test_http_rejected(self):
        msg = invalid("http://github.com/owner/repo")
        assert "https" in msg.lower()

    def test_git_scheme_rejected(self):
        msg = invalid("git://github.com/owner/repo.git")
        assert "https" in msg.lower()

    def test_ssh_scheme_rejected(self):
        msg = invalid("ssh://git@github.com/owner/repo.git")
        assert "https" in msg.lower()

    def test_ftp_scheme_rejected(self):
        msg = invalid("ftp://github.com/owner/repo")
        assert "https" in msg.lower()

    def test_file_scheme_rejected(self):
        msg = invalid("file:///home/user/repos/myrepo")
        assert "https" in msg.lower()

    def test_ssh_shorthand_rejected(self):
        # git@github.com:owner/repo  — parsed as scheme-less, fails early
        msg = invalid("git@github.com:owner/repo.git")
        assert msg  # any message is fine; just must not succeed


# ── Invalid: wrong host ────────────────────────────────────────────────────

class TestWrongHost:
    def test_gitlab_rejected(self):
        msg = invalid("https://gitlab.com/owner/repo")
        assert "github.com" in msg

    def test_bitbucket_rejected(self):
        msg = invalid("https://bitbucket.org/owner/repo")
        assert "github.com" in msg

    def test_localhost_rejected(self):
        msg = invalid("https://localhost/owner/repo")
        assert "github.com" in msg

    def test_private_ip_rejected(self):
        msg = invalid("https://192.168.1.1/owner/repo")
        assert "github.com" in msg

    def test_evil_domain_rejected(self):
        msg = invalid("https://evil.example.com/owner/repo")
        assert "github.com" in msg

    def test_github_com_subdomain_rejected(self):
        # api.github.com should not be accepted
        msg = invalid("https://api.github.com/owner/repo")
        assert "github.com" in msg

    def test_not_github_com_suffix(self):
        # notgithub.com must be rejected
        msg = invalid("https://notgithub.com/owner/repo")
        assert "github.com" in msg


# ── Invalid: credentials ───────────────────────────────────────────────────

class TestCredentials:
    def test_username_in_url_rejected(self):
        msg = invalid("https://user@github.com/owner/repo")
        assert "credential" in msg.lower()

    def test_username_password_in_url_rejected(self):
        msg = invalid("https://user:pass@github.com/owner/repo")
        assert "credential" in msg.lower()


# ── Invalid: non-standard port ─────────────────────────────────────────────

class TestPort:
    def test_explicit_port_rejected(self):
        msg = invalid("https://github.com:8080/owner/repo")
        assert "port" in msg.lower()

    def test_standard_port_443_still_rejected(self):
        # We don't allow explicit ports at all — even 443.
        msg = invalid("https://github.com:443/owner/repo")
        assert "port" in msg.lower()


# ── Invalid: query / fragment ──────────────────────────────────────────────

class TestQueryFragment:
    def test_query_string_rejected(self):
        msg = invalid("https://github.com/owner/repo?foo=bar")
        assert "query" in msg.lower() or "fragment" in msg.lower()

    def test_fragment_rejected(self):
        msg = invalid("https://github.com/owner/repo#readme")
        assert "query" in msg.lower() or "fragment" in msg.lower()


# ── Invalid: bad path structure ────────────────────────────────────────────

class TestPathStructure:
    def test_no_repo_segment_rejected(self):
        msg = invalid("https://github.com/owner")
        assert "path" in msg.lower() or "form" in msg.lower()

    def test_extra_path_segment_rejected(self):
        msg = invalid("https://github.com/owner/repo/extra")
        assert msg  # must not succeed

    def test_deep_path_rejected(self):
        msg = invalid("https://github.com/owner/repo/tree/main/src")
        assert msg  # must not succeed

    def test_root_path_rejected(self):
        msg = invalid("https://github.com/")
        assert msg

    def test_empty_host_rejected(self):
        msg = invalid("https:///owner/repo")
        assert msg

    def test_dots_only_owner_rejected(self):
        msg = invalid("https://github.com/../repo")
        assert msg

    def test_dots_only_repo_rejected(self):
        msg = invalid("https://github.com/owner/..")
        assert msg


# ── Invalid: local / relative paths ───────────────────────────────────────

class TestLocalPaths:
    def test_absolute_path_rejected(self):
        msg = invalid("/home/user/repo")
        assert "path" in msg.lower() or "https" in msg.lower()

    def test_relative_path_rejected(self):
        msg = invalid("./relative/path")
        assert msg

    def test_parent_traversal_rejected(self):
        msg = invalid("../../etc/passwd")
        assert msg

    def test_tilde_path_rejected(self):
        msg = invalid("~/repos/myrepo")
        assert msg

    def test_windows_path_rejected(self):
        msg = invalid("C:\\Users\\user\\repo")
        assert msg


# ── Invalid: empty / non-string ────────────────────────────────────────────

class TestEmptyOrNonString:
    def test_empty_string_rejected(self):
        msg = invalid("")
        assert "empty" in msg.lower()

    def test_whitespace_only_rejected(self):
        msg = invalid("   ")
        assert "empty" in msg.lower()

    def test_non_string_int_rejected(self):
        with pytest.raises(GitHubURLValidationError):
            validate_github_url(123)  # type: ignore[arg-type]

    def test_non_string_none_rejected(self):
        with pytest.raises(GitHubURLValidationError):
            validate_github_url(None)  # type: ignore[arg-type]
