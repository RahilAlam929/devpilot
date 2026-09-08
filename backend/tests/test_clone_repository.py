"""
Tests for clone_repository() context manager and _run_clone().

All network calls are mocked — no actual git operations are performed.

Covers:
  - Successful clone: temp dir created, repo path yielded, cleanup after exit
  - Cleanup happens even when the body raises an exception
  - GitCloneError raised on non-zero git exit (generic, not-found, no-network,
    access-denied variants)
  - GitCloneTimeoutError raised on subprocess.TimeoutExpired
  - GitCloneError raised when git binary is absent (FileNotFoundError)
  - shell=False is always used (never shell=True)
  - GIT_TERMINAL_PROMPT=0 is set in subprocess environment
  - git clone --depth 1 is in the command
  - -- separator between options and URL
  - Temp directory is always deleted on exit (success and failure paths)
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from app.services.github.repository import (
    GitCloneError,
    GitCloneTimeoutError,
    clone_repository,
    _run_clone,
)


# ── Helpers ────────────────────────────────────────────────────────────────

VALID_URL = "https://github.com/owner/repo.git"


def _make_result(returncode: int = 0, stderr: bytes = b"") -> MagicMock:
    """Create a mock subprocess.CompletedProcess."""
    result = MagicMock()
    result.returncode = returncode
    result.stderr = stderr
    result.stdout = b""
    return result


# ── _run_clone unit tests ──────────────────────────────────────────────────

class TestRunClone:
    """Low-level tests on _run_clone() without touching the filesystem."""

    def test_uses_correct_command_structure(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(0)) as mock_run:
            _run_clone(url=VALID_URL, dest=dest, timeout=30)

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "git"
        assert "clone" in cmd
        assert "--depth" in cmd
        assert "1" in cmd
        assert "--" in cmd
        assert VALID_URL in cmd
        assert str(dest) in cmd

    def test_never_uses_shell(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(0)) as mock_run:
            _run_clone(url=VALID_URL, dest=dest, timeout=30)

        kwargs = mock_run.call_args[1]
        assert kwargs.get("shell") is False

    def test_sets_git_terminal_prompt_zero(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(0)) as mock_run:
            _run_clone(url=VALID_URL, dest=dest, timeout=30)

        env = mock_run.call_args[1]["env"]
        assert env["GIT_TERMINAL_PROMPT"] == "0"

    def test_passes_timeout(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(0)) as mock_run:
            _run_clone(url=VALID_URL, dest=dest, timeout=42)

        assert mock_run.call_args[1]["timeout"] == 42

    def test_depth_1_is_in_command(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(0)) as mock_run:
            _run_clone(url=VALID_URL, dest=dest, timeout=30)

        cmd = mock_run.call_args[0][0]
        depth_idx = cmd.index("--depth")
        assert cmd[depth_idx + 1] == "1"

    def test_separator_before_url(self, tmp_path):
        """-- must appear before the URL to prevent URL injection."""
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(0)) as mock_run:
            _run_clone(url=VALID_URL, dest=dest, timeout=30)

        cmd = mock_run.call_args[0][0]
        sep_idx = cmd.index("--")
        url_idx = cmd.index(VALID_URL)
        assert sep_idx < url_idx

    def test_success_does_not_raise(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(0)):
            _run_clone(url=VALID_URL, dest=dest, timeout=30)  # should not raise

    def test_nonzero_exit_raises_clone_error(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", return_value=_make_result(1, b"some error")):
            with pytest.raises(GitCloneError):
                _run_clone(url=VALID_URL, dest=dest, timeout=30)

    def test_not_found_stderr_raises_clone_error_with_message(self, tmp_path):
        dest = tmp_path / "repo"
        stderr = b"ERROR: Repository not found."
        with patch("subprocess.run", return_value=_make_result(128, stderr)):
            with pytest.raises(GitCloneError) as exc_info:
                _run_clone(url=VALID_URL, dest=dest, timeout=30)
        assert "not publicly accessible" in exc_info.value.user_message

    def test_no_network_stderr_raises_clone_error_with_message(self, tmp_path):
        dest = tmp_path / "repo"
        stderr = b"fatal: Could not resolve host: github.com"
        with patch("subprocess.run", return_value=_make_result(128, stderr)):
            with pytest.raises(GitCloneError) as exc_info:
                _run_clone(url=VALID_URL, dest=dest, timeout=30)
        assert "reached" in exc_info.value.user_message.lower() or \
               "network" in exc_info.value.user_message.lower()

    def test_access_denied_stderr_raises_clone_error_with_message(self, tmp_path):
        dest = tmp_path / "repo"
        stderr = b"fatal: Authentication failed for 'https://github.com/owner/private.git'"
        with patch("subprocess.run", return_value=_make_result(128, stderr)):
            with pytest.raises(GitCloneError) as exc_info:
                _run_clone(url=VALID_URL, dest=dest, timeout=30)
        assert "denied" in exc_info.value.user_message.lower() or \
               "public" in exc_info.value.user_message.lower()

    def test_timeout_raises_clone_timeout_error(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=5)):
            with pytest.raises(GitCloneTimeoutError) as exc_info:
                _run_clone(url=VALID_URL, dest=dest, timeout=5)
        assert "timed out" in exc_info.value.user_message.lower()

    def test_git_not_found_raises_clone_error(self, tmp_path):
        dest = tmp_path / "repo"
        with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
            with pytest.raises(GitCloneError) as exc_info:
                _run_clone(url=VALID_URL, dest=dest, timeout=30)
        assert "git" in exc_info.value.user_message.lower()

    def test_generic_error_message_contains_no_raw_path(self, tmp_path):
        """Generic fallback message must not leak internal paths."""
        dest = tmp_path / "repo"
        stderr = b"some completely unknown git error"
        with patch("subprocess.run", return_value=_make_result(1, stderr)):
            with pytest.raises(GitCloneError) as exc_info:
                _run_clone(url=VALID_URL, dest=dest, timeout=30)
        assert str(tmp_path) not in exc_info.value.user_message
        assert str(dest) not in exc_info.value.user_message


# ── clone_repository context manager ──────────────────────────────────────

class TestCloneRepositoryContextManager:
    """Integration-level tests of the full context manager."""

    def test_successful_clone_yields_path(self):
        """On success, a Path is yielded inside the context."""
        with patch("app.services.github.repository._run_clone") as mock_clone:
            with clone_repository(VALID_URL, timeout=30) as repo_path:
                assert isinstance(repo_path, Path)
                assert "devpilot_clone_" in str(repo_path.parent)

    def test_temp_dir_deleted_after_success(self):
        """Temp dir must not exist after a successful clone + context exit."""
        captured = {}

        with patch("app.services.github.repository._run_clone"):
            with clone_repository(VALID_URL, timeout=30) as repo_path:
                captured["tmpdir"] = str(repo_path.parent)

        assert not os.path.exists(captured["tmpdir"]), \
            f"Temp dir was not cleaned up: {captured['tmpdir']}"

    def test_temp_dir_deleted_after_body_exception(self):
        """Cleanup must happen even when the body raises."""
        captured = {}

        with patch("app.services.github.repository._run_clone"):
            with pytest.raises(RuntimeError, match="body error"):
                with clone_repository(VALID_URL, timeout=30) as repo_path:
                    captured["tmpdir"] = str(repo_path.parent)
                    raise RuntimeError("body error")

        assert not os.path.exists(captured["tmpdir"]), \
            f"Temp dir was not cleaned up after body exception"

    def test_temp_dir_deleted_after_clone_failure(self):
        """Cleanup must happen when _run_clone itself raises."""
        captured = {}

        def fake_clone(url, dest, timeout):
            # Record the tmpdir before raising
            captured["tmpdir"] = str(dest.parent)
            raise GitCloneError("clone failed")

        with patch("app.services.github.repository._run_clone", side_effect=fake_clone):
            with pytest.raises(GitCloneError):
                with clone_repository(VALID_URL, timeout=30) as repo_path:
                    pass  # never reached

        assert not os.path.exists(captured["tmpdir"]), \
            f"Temp dir was not cleaned up after clone failure"

    def test_temp_dir_deleted_after_timeout(self):
        """Cleanup must happen when clone times out."""
        captured = {}

        def fake_clone(url, dest, timeout):
            captured["tmpdir"] = str(dest.parent)
            raise GitCloneTimeoutError("timed out")

        with patch("app.services.github.repository._run_clone", side_effect=fake_clone):
            with pytest.raises(GitCloneTimeoutError):
                with clone_repository(VALID_URL, timeout=5) as _:
                    pass

        assert not os.path.exists(captured["tmpdir"]), \
            f"Temp dir was not cleaned up after timeout"

    def test_clone_failure_propagates_exception(self):
        """GitCloneError from _run_clone must propagate out of the context."""
        with patch("app.services.github.repository._run_clone",
                   side_effect=GitCloneError("repo not found")):
            with pytest.raises(GitCloneError, match="repo not found"):
                with clone_repository(VALID_URL, timeout=30) as _:
                    pass

    def test_timeout_propagates_as_timeout_error(self):
        with patch("app.services.github.repository._run_clone",
                   side_effect=GitCloneTimeoutError("timed out after 30 seconds.")):
            with pytest.raises(GitCloneTimeoutError):
                with clone_repository(VALID_URL, timeout=30) as _:
                    pass

    def test_each_clone_uses_isolated_directory(self):
        """Two concurrent clones must not share a temp directory."""
        dirs = []

        with patch("app.services.github.repository._run_clone"):
            with clone_repository(VALID_URL, timeout=30) as p1:
                dirs.append(str(p1.parent))
            with clone_repository(VALID_URL, timeout=30) as p2:
                dirs.append(str(p2.parent))

        assert dirs[0] != dirs[1]

    def test_default_timeout_is_120(self):
        """Default timeout parameter must be 120 seconds."""
        with patch("app.services.github.repository._run_clone") as mock_clone:
            with clone_repository(VALID_URL) as _:
                pass

        _, kwargs = mock_clone.call_args
        assert kwargs.get("timeout") == 120 or mock_clone.call_args[0][2] == 120

    def test_repo_subdir_name_is_repo(self):
        """The yielded path should be <tmpdir>/repo."""
        with patch("app.services.github.repository._run_clone"):
            with clone_repository(VALID_URL, timeout=30) as repo_path:
                assert repo_path.name == "repo"
