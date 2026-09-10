"""
GitHub source URL builder.

Builds a canonical "Open on GitHub" link for a specific file and line range
within a repository, pointing to the exact ref (commit SHA or branch) that
was scanned.

URL format:
  https://github.com/{owner}/{repo}/blob/{ref}/{file_path}#L{start_line}
  https://github.com/{owner}/{repo}/blob/{ref}/{file_path}#L{start_line}-L{end_line}

Security requirements:
  - repo_url is validated against the same strict rules as validate_github_url().
  - file_path is sanitised: absolute paths, parent-directory traversal, and
    null bytes are all rejected; the path is always treated as relative to the
    repository root.
  - ref (SHA / branch) is validated to contain only safe characters.
  - URL percent-encoding is applied to file path components.
  - Credentials, query strings, or fragments from the stored URL are never
    propagated into the generated link.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import quote

from app.services.github.repository import _GITHUB_PATH_RE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Allowed characters in a git ref (SHA or branch name).
# SHA-1: 40 hex chars. SHA-256: 64 hex chars. Branch: letters, digits,
# hyphens, underscores, dots, slashes (for remote-tracking refs like main).
_REF_RE = re.compile(r"^[A-Za-z0-9/_.\-]{1,200}$")

# Characters that must not appear in a file path component (security check).
_NULL_BYTE_RE = re.compile(r"\x00")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_github_source_url(
    repo_url: str,
    file_path: Optional[str],
    ref: Optional[str],
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> Optional[str]:
    """
    Build a GitHub blob URL for a specific file and optional line range.

    Parameters
    ----------
    repo_url:
        The repository's canonical HTTPS URL as stored in the database
        (e.g. ``https://github.com/owner/repo`` or
        ``https://github.com/owner/repo.git``).
        Must be a valid GitHub HTTPS URL; returns ``None`` for any other URL.
    file_path:
        Path of the file relative to the repository root.
        Returns ``None`` if not provided or unsafe.
    ref:
        Git ref to link to — ideally the commit SHA captured at scan time,
        or a branch name.  Returns ``None`` if not provided or contains
        unsafe characters.
    start_line:
        1-based line number of the finding.  Omitted from the anchor if
        ``None`` or ≤ 0.
    end_line:
        1-based end line (inclusive).  Only appended to the anchor if
        different from ``start_line`` and both are valid.

    Returns
    -------
    str | None
        A fully-qualified GitHub blob URL, or ``None`` if any required
        component is missing or invalid.
    """
    owner, repo = _parse_github_owner_repo(repo_url)
    if owner is None or repo is None:
        return None

    if not file_path:
        return None

    safe_path = _sanitise_file_path(file_path)
    if safe_path is None:
        return None

    safe_ref = _sanitise_ref(ref)
    if safe_ref is None:
        return None

    # Build base URL
    url = f"https://github.com/{owner}/{repo}/blob/{safe_ref}/{safe_path}"

    # Append line anchor
    anchor = _build_line_anchor(start_line, end_line)
    if anchor:
        url = f"{url}{anchor}"

    return url


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_github_owner_repo(url: str) -> tuple[Optional[str], Optional[str]]:
    """
    Extract (owner, repo) from a GitHub HTTPS URL.

    Returns (None, None) for any URL that is not a valid GitHub HTTPS URL.
    Credentials, ports, query strings, and fragments are all rejected.
    """
    if not isinstance(url, str):
        return None, None

    url = url.strip()

    # Must start with https://github.com/ (case-insensitive prefix check)
    if not url.lower().startswith("https://github.com/"):
        return None, None

    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
    except Exception:
        return None, None

    if parsed.scheme.lower() != "https":
        return None, None

    host = (parsed.hostname or "").lower()
    if host != "github.com":
        return None, None

    # Reject credentials and ports
    if parsed.username or parsed.password or parsed.port:
        return None, None

    # Reject query strings and fragments
    if parsed.query or parsed.fragment:
        return None, None

    path = parsed.path.rstrip("/")
    match = _GITHUB_PATH_RE.match(path)
    if not match:
        return None, None

    owner = match.group(1)
    repo = match.group(2)
    # Strip .git suffix if present
    if repo.endswith(".git"):
        repo = repo[:-4]

    return owner, repo


def _sanitise_file_path(file_path: str) -> Optional[str]:
    """
    Sanitise a repository-relative file path for use in a GitHub URL.

    Rules:
    - Must not be empty.
    - Must not contain null bytes.
    - Absolute paths are stripped of their leading separator so they become
      relative.  A path like /app/main.py becomes app/main.py.
    - Parent-directory traversal components (..) are removed.
    - Each path component is percent-encoded with ``quote`` (safe='/').

    Returns ``None`` if the path is empty after sanitisation.
    """
    if not file_path:
        return None

    # Reject null bytes outright
    if _NULL_BYTE_RE.search(file_path):
        return None

    # Normalise separators to forward slash (handles Windows-style paths
    # that may appear in repositories cloned on Windows).
    normalised = file_path.replace("\\", "/")

    # Strip leading slashes — paths must be relative to the repo root.
    normalised = normalised.lstrip("/")

    # Split into components and drop dangerous segments.
    parts = normalised.split("/")
    safe_parts: list[str] = []
    for part in parts:
        if part in ("", ".", ".."):
            # Skip empty parts (double slashes), current-dir, and parent-dir
            continue
        safe_parts.append(part)

    if not safe_parts:
        return None

    # Percent-encode each component; keep forward-slashes as separators.
    encoded_parts = [quote(p, safe="") for p in safe_parts]
    return "/".join(encoded_parts)


def _sanitise_ref(ref: Optional[str]) -> Optional[str]:
    """
    Validate and return a safe git ref string.

    Accepts 40-hex commit SHAs, branch names, and tag names.
    Rejects anything that would allow URL injection or unsafe characters.

    Returns ``None`` if ``ref`` is None, empty, or fails validation.
    """
    if not ref:
        return None

    ref = ref.strip()

    if not ref:
        return None

    if not _REF_RE.match(ref):
        return None

    # Additional guard: refs must not start or end with a dot (e.g. ".hidden")
    if ref.startswith(".") or ref.endswith("."):
        return None

    # Refs must not contain ".." (traversal in branch names)
    if ".." in ref:
        return None

    return ref


def _build_line_anchor(
    start_line: Optional[int],
    end_line: Optional[int],
) -> str:
    """
    Build the ``#L{n}`` or ``#L{n}-L{m}`` fragment for a GitHub blob URL.

    Returns an empty string if ``start_line`` is not a valid positive integer.
    """
    if not isinstance(start_line, int) or start_line <= 0:
        return ""

    if isinstance(end_line, int) and end_line > start_line:
        return f"#L{start_line}-L{end_line}"

    return f"#L{start_line}"
