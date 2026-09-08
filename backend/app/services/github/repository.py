"""
GitHub repository service.

Responsibilities:
  - Validate GitHub HTTPS repository URLs.
  - Clone repositories into isolated temporary workspaces.
  - Guarantee workspace cleanup regardless of success or failure.
  - Never use shell=True or build commands via string interpolation.
  - Never log secrets or credentials.

Supported URLs (public repos, HTTPS only):
  https://github.com/owner/repo
  https://github.com/owner/repo.git

Not supported (rejected at validation):
  http://github.com/...        (no plain-text HTTP)
  git://github.com/...
  ssh://git@github.com/...
  git@github.com:owner/repo
  file:///...
  /absolute/local/path
  ../../relative/path
  https://evil.example.com/...
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_HOST = "github.com"

# Path must be /<owner>/<repo> or /<owner>/<repo>.git
# Both owner and repo segments: letters, digits, hyphens, underscores, dots.
# Length limits match GitHub's actual constraints (owner ≤ 39, repo ≤ 100).
_GITHUB_PATH_RE = re.compile(
    r"^/([A-Za-z0-9](?:[A-Za-z0-9\-]{0,37}[A-Za-z0-9])?)"
    r"/([A-Za-z0-9][A-Za-z0-9_\-\.]{0,98})(?:\.git)?$"
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GitHubURLValidationError(ValueError):
    """Raised when a repository URL fails validation."""


class GitCloneError(RuntimeError):
    """Raised when a repository clone operation fails."""

    def __init__(self, user_message: str) -> None:
        # user_message is safe to surface to the API caller.
        super().__init__(user_message)
        self.user_message = user_message


class GitCloneTimeoutError(GitCloneError):
    """Raised when cloning exceeds the configured timeout."""


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def validate_github_url(url: str) -> str:
    """
    Validate and normalise a GitHub HTTPS repository URL.

    Returns the normalised URL (without trailing .git) on success.
    Raises GitHubURLValidationError with a user-safe message on failure.

    The function is intentionally strict:
      - scheme must be ``https`` (not http, git, ssh, file, …)
      - host must be exactly ``github.com``
      - path must match /<owner>/<repo>[.git]
      - no credentials in URL (no user:password@ component)
      - no query string or fragment
    """
    if not isinstance(url, str):
        raise GitHubURLValidationError("Repository URL must be a string.")

    url = url.strip()

    if not url:
        raise GitHubURLValidationError("Repository URL must not be empty.")

    # Reject anything that looks like a local path before urllib touches it.
    if url.startswith(("/", ".", "~", "\\")) or re.match(r"^[A-Za-z]:\\", url):
        raise GitHubURLValidationError(
            "Repository URL must be a GitHub HTTPS URL, not a local path."
        )

    try:
        parsed = urlparse(url)
    except Exception:
        raise GitHubURLValidationError("Repository URL could not be parsed.")

    # Enforce HTTPS exclusively.
    if parsed.scheme != "https":
        raise GitHubURLValidationError(
            f"Repository URL must use HTTPS (got '{parsed.scheme}://')."
        )

    # Reject embedded credentials (https://user:pass@github.com/…).
    if parsed.username or parsed.password:
        raise GitHubURLValidationError(
            "Repository URL must not contain credentials."
        )

    # Normalise host (strip www. prefix if present, lower-case).
    host = (parsed.hostname or "").lower().lstrip("www.")

    if host != _ALLOWED_HOST:
        raise GitHubURLValidationError(
            f"Only GitHub repositories are supported "
            f"(expected host 'github.com', got '{parsed.hostname}')."
        )

    # Reject non-standard ports.
    if parsed.port is not None:
        raise GitHubURLValidationError(
            "Repository URL must not specify a port number."
        )

    # Validate path: /<owner>/<repo>[.git] — nothing else.
    path = parsed.path.rstrip("/")
    match = _GITHUB_PATH_RE.match(path)
    if not match:
        raise GitHubURLValidationError(
            "Repository URL path must be in the form "
            "https://github.com/<owner>/<repo>[.git]."
        )

    owner = match.group(1)
    repo = match.group(2).removesuffix(".git")

    # Reject names that are only dots (traversal risk).
    if set(owner) <= {"."} or set(repo) <= {"."} :
        raise GitHubURLValidationError(
            "Repository owner or name is invalid."
        )

    # Reject query strings and fragments (no legitimate use here).
    if parsed.query or parsed.fragment:
        raise GitHubURLValidationError(
            "Repository URL must not contain query parameters or fragments."
        )

    # Return the canonical form (always .git for consistency).
    return f"https://github.com/{owner}/{repo}.git"


# ---------------------------------------------------------------------------
# Cloning
# ---------------------------------------------------------------------------

@contextmanager
def clone_repository(
    url: str,
    timeout: int = 120,
) -> Generator[Path, None, None]:
    """
    Context manager: shallow-clone *url* into a fresh temporary directory,
    yield the directory path, then delete it unconditionally on exit.

    Usage::

        with clone_repository("https://github.com/owner/repo.git") as path:
            # path is a Path pointing to the cloned tree
            run_analysis(path)
        # directory has been deleted here, even if an exception occurred

    Parameters
    ----------
    url:
        A validated GitHub HTTPS URL (call ``validate_github_url`` first).
    timeout:
        Maximum seconds to wait for ``git clone`` to complete.
        Defaults to 120 s.

    Raises
    ------
    GitCloneTimeoutError
        If the clone process does not finish within *timeout* seconds.
    GitCloneError
        For any other clone failure (non-zero exit, repository not found, …).
    """
    tmpdir: str | None = None

    try:
        tmpdir = tempfile.mkdtemp(prefix="devpilot_clone_")
        dest = Path(tmpdir) / "repo"

        _run_clone(url=url, dest=dest, timeout=timeout)

        yield dest

    finally:
        if tmpdir is not None:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                # Log but never propagate cleanup failures — they must not
                # mask the original exception or scan result.
                logger.warning(
                    "Failed to clean up temporary clone directory: %s", tmpdir
                )


def _run_clone(url: str, dest: Path, timeout: int) -> None:
    """
    Execute ``git clone --depth 1 <url> <dest>`` safely.

    - Uses an argument list (never shell=True).
    - Passes a controlled environment (GIT_TERMINAL_PROMPT=0 prevents
      interactive prompts from hanging the process).
    - Captures both stdout and stderr; neither is logged at INFO level to
      avoid accidentally surfacing sensitive output.
    - Maps timeout / non-zero exit / FileNotFoundError to typed exceptions
      with user-safe messages.
    """
    import os

    # Inherit a minimal environment.  GIT_TERMINAL_PROMPT=0 makes git fail
    # immediately instead of waiting for a password prompt when a private
    # repo is encountered.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

    cmd = [
        "git",
        "clone",
        "--depth", "1",
        "--",           # signal end of options, preventing URL injection
        url,
        str(dest),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env=env,
            shell=False,        # explicit, never True
        )
    except subprocess.TimeoutExpired:
        raise GitCloneTimeoutError(
            f"Repository clone timed out after {timeout} seconds."
        )
    except FileNotFoundError:
        # git binary not found on PATH.
        raise GitCloneError(
            "git is not installed or not available on the server."
        )

    if result.returncode != 0:
        # Parse stderr for common, user-safe error patterns.
        # We deliberately do NOT include the raw stderr in the raised message
        # because it may contain path information or internal details.
        stderr_lower = result.stderr.decode(errors="replace").lower()

        if "repository not found" in stderr_lower or "not found" in stderr_lower:
            raise GitCloneError(
                "Repository does not exist or is not publicly accessible."
            )

        if "could not resolve host" in stderr_lower or "unable to connect" in stderr_lower:
            raise GitCloneError(
                "Repository could not be reached. Check the URL and network access."
            )

        if "authentication failed" in stderr_lower or "access denied" in stderr_lower:
            raise GitCloneError(
                "Repository access was denied. "
                "Only public GitHub repositories are supported."
            )

        # Generic fallback — safe, no internal details.
        raise GitCloneError("Repository clone failed.")
