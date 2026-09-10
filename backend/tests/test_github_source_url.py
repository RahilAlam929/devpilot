"""
Tests for build_github_source_url() and its helpers.

Covers:
  - Normal GitHub URL (HTTPS, no .git suffix)
  - .git repository URL (suffix stripped)
  - Branch reference
  - Commit SHA reference (40-char and 64-char)
  - Line-only URL (no end line)
  - Start/end line URL
  - Missing / empty file path → None
  - Missing / empty line → URL without anchor
  - Invalid / non-GitHub repository URL → None
  - Unsafe file paths (absolute, traversal, null bytes) → None or sanitised
  - Correct URL encoding of special characters in file paths
  - Non-string repo_url → None
  - Long ref / branch with slashes (remote-tracking)
"""

import pytest

from app.services.github.source_url import (
    _build_line_anchor,
    _parse_github_owner_repo,
    _sanitise_file_path,
    _sanitise_ref,
    build_github_source_url,
)


from typing import Optional


# ── Helpers ────────────────────────────────────────────────────────────────


def url(
    repo_url: str,
    file_path: Optional[str],
    ref: Optional[str],
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> Optional[str]:
    return build_github_source_url(
        repo_url=repo_url,
        file_path=file_path,
        ref=ref,
        start_line=start_line,
        end_line=end_line,
    )


# ── build_github_source_url: valid cases ──────────────────────────────────


class TestBuildGithubSourceUrl:
    def test_normal_github_url_no_git_suffix(self):
        result = url(
            "https://github.com/owner/repo",
            "app/main.py",
            "main",
            42,
        )
        assert result == "https://github.com/owner/repo/blob/main/app/main.py#L42"

    def test_git_suffix_stripped(self):
        result = url(
            "https://github.com/owner/repo.git",
            "app/main.py",
            "main",
            42,
        )
        assert result == "https://github.com/owner/repo/blob/main/app/main.py#L42"

    def test_branch_reference(self):
        result = url(
            "https://github.com/owner/repo",
            "src/utils.py",
            "develop",
        )
        assert result == "https://github.com/owner/repo/blob/develop/src/utils.py"

    def test_commit_sha_40_char(self):
        sha = "a" * 40
        result = url(
            "https://github.com/owner/repo",
            "backend/app/main.py",
            sha,
            10,
        )
        assert result == f"https://github.com/owner/repo/blob/{sha}/backend/app/main.py#L10"

    def test_commit_sha_64_char(self):
        sha = "b" * 64
        result = url(
            "https://github.com/owner/repo",
            "main.go",
            sha,
            1,
        )
        assert result == f"https://github.com/owner/repo/blob/{sha}/main.go#L1"

    def test_line_only_url(self):
        result = url(
            "https://github.com/owner/repo",
            "src/index.ts",
            "main",
            100,
        )
        assert result == "https://github.com/owner/repo/blob/main/src/index.ts#L100"

    def test_start_end_line_url(self):
        result = url(
            "https://github.com/owner/repo",
            "lib/auth.py",
            "main",
            20,
            30,
        )
        assert result == "https://github.com/owner/repo/blob/main/lib/auth.py#L20-L30"

    def test_end_line_equal_to_start_line_no_range(self):
        """When end_line == start_line, only #L{n} should be produced."""
        result = url(
            "https://github.com/owner/repo",
            "file.py",
            "main",
            5,
            5,
        )
        assert result == "https://github.com/owner/repo/blob/main/file.py#L5"

    def test_end_line_less_than_start_no_range(self):
        result = url(
            "https://github.com/owner/repo",
            "file.py",
            "main",
            10,
            5,
        )
        assert result == "https://github.com/owner/repo/blob/main/file.py#L10"

    def test_no_line_number_no_anchor(self):
        result = url(
            "https://github.com/owner/repo",
            "app/config.py",
            "main",
        )
        assert result == "https://github.com/owner/repo/blob/main/app/config.py"

    def test_line_zero_no_anchor(self):
        result = url(
            "https://github.com/owner/repo",
            "file.py",
            "main",
            0,
        )
        assert result == "https://github.com/owner/repo/blob/main/file.py"

    def test_negative_line_no_anchor(self):
        result = url(
            "https://github.com/owner/repo",
            "file.py",
            "main",
            -1,
        )
        assert result == "https://github.com/owner/repo/blob/main/file.py"

    def test_url_encoding_spaces(self):
        result = url(
            "https://github.com/owner/repo",
            "my folder/my file.py",
            "main",
            1,
        )
        assert result == "https://github.com/owner/repo/blob/main/my%20folder/my%20file.py#L1"

    def test_url_encoding_special_chars(self):
        result = url(
            "https://github.com/owner/repo",
            "src/[test].py",
            "main",
            5,
        )
        assert "%5B" in result or "[" not in result.split("/blob/")[1].split("#")[0]

    def test_remote_tracking_branch(self):
        result = url(
            "https://github.com/owner/repo",
            "main.py",
            "refs/remotes/origin/main",
        )
        assert result == "https://github.com/owner/repo/blob/refs/remotes/origin/main/main.py"

    def test_owner_with_hyphens_and_digits(self):
        result = url(
            "https://github.com/my-org-123/my-repo_456",
            "app.py",
            "main",
            1,
        )
        assert result == "https://github.com/my-org-123/my-repo_456/blob/main/app.py#L1"


# ── build_github_source_url: returns None ─────────────────────────────────


class TestBuildGithubSourceUrlNone:
    def test_missing_file_path_returns_none(self):
        assert url("https://github.com/owner/repo", None, "main") is None

    def test_empty_file_path_returns_none(self):
        assert url("https://github.com/owner/repo", "", "main") is None

    def test_missing_ref_returns_none(self):
        assert url("https://github.com/owner/repo", "file.py", None) is None

    def test_empty_ref_returns_none(self):
        assert url("https://github.com/owner/repo", "file.py", "") is None

    def test_non_github_url_returns_none(self):
        assert url("https://gitlab.com/owner/repo", "file.py", "main") is None

    def test_http_url_returns_none(self):
        assert url("http://github.com/owner/repo", "file.py", "main") is None

    def test_empty_repo_url_returns_none(self):
        assert url("", "file.py", "main") is None

    def test_non_string_repo_url_returns_none(self):
        assert url(None, "file.py", "main") is None  # type: ignore[arg-type]

    def test_ssh_url_returns_none(self):
        assert url("git@github.com:owner/repo.git", "file.py", "main") is None

    def test_local_path_as_repo_url_returns_none(self):
        assert url("/home/user/repo", "file.py", "main") is None

    def test_unsafe_file_path_traversal_sanitised_or_none(self):
        """../../etc/passwd should not appear in the final URL."""
        result = url("https://github.com/owner/repo", "../../etc/passwd", "main")
        # Either None (all parts dropped) or a clean path without traversal
        if result is not None:
            assert ".." not in result
            assert "etc/passwd" in result or result.endswith("/blob/main/")

    def test_file_path_all_dots_returns_none(self):
        """A path of only dots after sanitisation is empty → None."""
        result = url("https://github.com/owner/repo", "../../..", "main")
        assert result is None

    def test_file_path_null_byte_returns_none(self):
        assert url("https://github.com/owner/repo", "file\x00.py", "main") is None

    def test_ref_with_unsafe_chars_returns_none(self):
        assert url("https://github.com/owner/repo", "file.py", "main; rm -rf") is None

    def test_ref_with_null_byte_returns_none(self):
        assert url("https://github.com/owner/repo", "file.py", "main\x00") is None


# ── _parse_github_owner_repo ───────────────────────────────────────────────


class TestParseGithubOwnerRepo:
    def test_valid_url(self):
        owner, repo = _parse_github_owner_repo("https://github.com/torvalds/linux")
        assert owner == "torvalds"
        assert repo == "linux"

    def test_git_suffix_stripped(self):
        owner, repo = _parse_github_owner_repo("https://github.com/owner/repo.git")
        assert repo == "repo"

    def test_non_github_url_returns_none(self):
        owner, repo = _parse_github_owner_repo("https://gitlab.com/owner/repo")
        assert owner is None
        assert repo is None

    def test_non_string_returns_none(self):
        owner, repo = _parse_github_owner_repo(123)  # type: ignore[arg-type]
        assert owner is None
        assert repo is None

    def test_local_path_returns_none(self):
        owner, repo = _parse_github_owner_repo("/home/user/repo")
        assert owner is None

    def test_credentials_returns_none(self):
        owner, repo = _parse_github_owner_repo("https://user:pass@github.com/owner/repo")
        assert owner is None


# ── _sanitise_file_path ────────────────────────────────────────────────────


class TestSanitiseFilePath:
    def test_relative_path(self):
        assert _sanitise_file_path("app/main.py") == "app/main.py"

    def test_absolute_path_stripped(self):
        result = _sanitise_file_path("/app/main.py")
        assert result == "app/main.py"

    def test_traversal_components_removed(self):
        result = _sanitise_file_path("../../etc/passwd")
        assert result == "etc/passwd"

    def test_all_traversal_returns_none(self):
        assert _sanitise_file_path("../../..") is None

    def test_empty_returns_none(self):
        assert _sanitise_file_path("") is None

    def test_null_byte_returns_none(self):
        assert _sanitise_file_path("file\x00.py") is None

    def test_double_slashes_collapsed(self):
        result = _sanitise_file_path("app//main.py")
        assert result == "app/main.py"

    def test_dot_components_removed(self):
        result = _sanitise_file_path("app/./main.py")
        assert result == "app/main.py"

    def test_spaces_percent_encoded(self):
        result = _sanitise_file_path("my folder/file.py")
        assert result == "my%20folder/file.py"

    def test_windows_backslash_normalised(self):
        result = _sanitise_file_path("app\\main.py")
        assert result == "app/main.py"

    def test_none_returns_none(self):
        assert _sanitise_file_path(None) is None  # type: ignore[arg-type]


# ── _sanitise_ref ──────────────────────────────────────────────────────────


class TestSanitiseRef:
    def test_valid_sha_40(self):
        sha = "a" * 40
        assert _sanitise_ref(sha) == sha

    def test_valid_sha_64(self):
        sha = "b" * 64
        assert _sanitise_ref(sha) == sha

    def test_valid_branch_name(self):
        assert _sanitise_ref("main") == "main"

    def test_valid_branch_with_slash(self):
        assert _sanitise_ref("feature/my-branch") == "feature/my-branch"

    def test_empty_returns_none(self):
        assert _sanitise_ref("") is None

    def test_none_returns_none(self):
        assert _sanitise_ref(None) is None

    def test_ref_with_spaces_returns_none(self):
        assert _sanitise_ref("main branch") is None

    def test_ref_with_shell_chars_returns_none(self):
        assert _sanitise_ref("main; rm -rf") is None

    def test_ref_starting_with_dot_returns_none(self):
        assert _sanitise_ref(".hidden") is None

    def test_ref_ending_with_dot_returns_none(self):
        assert _sanitise_ref("branch.") is None

    def test_ref_with_double_dot_traversal_returns_none(self):
        assert _sanitise_ref("branch/../other") is None


# ── _build_line_anchor ────────────────────────────────────────────────────


class TestBuildLineAnchor:
    def test_start_only(self):
        assert _build_line_anchor(42, None) == "#L42"

    def test_start_and_end(self):
        assert _build_line_anchor(10, 20) == "#L10-L20"

    def test_start_equals_end_no_range(self):
        assert _build_line_anchor(5, 5) == "#L5"

    def test_end_less_than_start_no_range(self):
        assert _build_line_anchor(10, 5) == "#L10"

    def test_zero_start_empty(self):
        assert _build_line_anchor(0, None) == ""

    def test_negative_start_empty(self):
        assert _build_line_anchor(-1, None) == ""

    def test_none_start_empty(self):
        assert _build_line_anchor(None, None) == ""

    def test_string_start_empty(self):
        assert _build_line_anchor("42", None) == ""  # type: ignore[arg-type]
