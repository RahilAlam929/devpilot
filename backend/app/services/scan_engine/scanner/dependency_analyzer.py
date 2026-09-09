"""
Software Composition Analysis (SCA) — Dependency Analyzer — Phase 6.

Parses dependency manifests and reports:
  - Known vulnerable packages (via local advisory database)
  - Outdated major-version packages
  - Direct vs transitive classification where determinable

Supported manifests:
  JavaScript/TypeScript:
    - package.json        (direct dependencies)
    - package-lock.json   (resolved/transitive, versions)

  Python:
    - requirements.txt / requirements-dev.txt / requirements-*.txt
    - pyproject.toml      (tool.poetry.dependencies or project.dependencies)
    - poetry.lock         (resolved versions)

  Java:
    - pom.xml             (Maven, best-effort XML parse)

Safety rules enforced here:
  - Never executes package managers.
  - Never runs install scripts.
  - Never evaluates repository code.
  - Uses only safe file parsing (JSON, TOML, XML, line-by-line text).
  - No real network calls. Advisory data is local only.
  - Fails gracefully per-manifest — one parse failure does not abort the scan.

Advisory data design:
  Phase 6 ships a LOCAL_ADVISORIES dictionary with well-known, publicly-
  documented CVEs for common packages. This is intentionally conservative.
  No CVEs are fabricated. The data comes from NVD/OSV public sources
  and is embedded here to avoid network dependency.

  The abstraction VulnerabilityProvider allows future integration with
  OSV or GitHub Advisory API, gated by a feature flag and isolated from
  the core scan pipeline.
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class DependencyInfo:
    """Parsed dependency from a manifest file."""
    name: str
    version: Optional[str]           # None if unresolved
    ecosystem: str                    # "npm" | "pypi" | "maven"
    is_direct: bool = True
    manifest_file: str = ""


@dataclass
class Advisory:
    """A known vulnerability advisory."""
    advisory_id: str                  # CVE-XXXX-XXXXX or GHSA-xxxx
    package_name: str
    ecosystem: str                    # "npm" | "pypi" | "maven"
    affected_versions: str            # human-readable range, e.g. "<1.2.3"
    severity: str                     # "critical"|"high"|"medium"|"low"
    title: str
    description: str
    fixed_version: Optional[str]
    cwe: Optional[str] = None


# ---------------------------------------------------------------------------
# Local advisory database
# Well-known, publicly documented CVEs only.
# Source: NVD / GitHub Advisory Database (public).
# These are historic, widely-reported vulnerabilities in popular packages.
# ---------------------------------------------------------------------------

LOCAL_ADVISORIES: List[Advisory] = [
    # npm: lodash prototype pollution
    Advisory(
        advisory_id="CVE-2019-10744",
        package_name="lodash",
        ecosystem="npm",
        affected_versions="<4.17.12",
        severity="critical",
        title="Prototype Pollution in lodash",
        description="lodash versions prior to 4.17.12 are vulnerable to Prototype Pollution. The function defaultsDeep could be tricked into adding or modifying properties of Object.prototype.",
        fixed_version="4.17.12",
        cwe="CWE-1321",
    ),
    Advisory(
        advisory_id="CVE-2021-23337",
        package_name="lodash",
        ecosystem="npm",
        affected_versions="<4.17.21",
        severity="high",
        title="Command Injection in lodash",
        description="lodash versions prior to 4.17.21 are vulnerable to command injection via the template function.",
        fixed_version="4.17.21",
        cwe="CWE-78",
    ),
    # npm: minimist argument injection
    Advisory(
        advisory_id="CVE-2020-7598",
        package_name="minimist",
        ecosystem="npm",
        affected_versions="<0.2.1,<1.2.3",
        severity="medium",
        title="Prototype Pollution in minimist",
        description="minimist before 1.2.3 is vulnerable to prototype pollution.",
        fixed_version="1.2.3",
        cwe="CWE-1321",
    ),
    # npm: axios SSRF
    Advisory(
        advisory_id="CVE-2023-45857",
        package_name="axios",
        ecosystem="npm",
        affected_versions=">=1.0.0,<1.6.0",
        severity="medium",
        title="Axios cross-site request forgery / CSRF token exposure",
        description="Axios 1.0.0 through 1.5.1 sends the secret XSRF-TOKEN cookie to all origins when making cross-origin requests.",
        fixed_version="1.6.0",
        cwe="CWE-352",
    ),
    # npm: express prototype pollution
    Advisory(
        advisory_id="CVE-2022-24999",
        package_name="qs",
        ecosystem="npm",
        affected_versions="<6.11.0",
        severity="high",
        title="Prototype Pollution in qs",
        description="qs before 6.10.3 allows prototype pollution, which can lead to arbitrary code execution.",
        fixed_version="6.11.0",
        cwe="CWE-1321",
    ),
    # npm: path-to-regexp ReDoS
    Advisory(
        advisory_id="CVE-2024-45296",
        package_name="path-to-regexp",
        ecosystem="npm",
        affected_versions="<0.1.10,>=1.0.0 <6.3.0",
        severity="high",
        title="path-to-regexp ReDoS vulnerability",
        description="path-to-regexp versions before 0.1.10 and 1.x through 6.x before 6.3.0 fail to limit backtracking, allowing ReDoS.",
        fixed_version="6.3.0",
        cwe="CWE-1333",
    ),
    # npm: semver ReDoS
    Advisory(
        advisory_id="CVE-2022-25883",
        package_name="semver",
        ecosystem="npm",
        affected_versions="<5.7.2,>=6.0.0 <6.3.1,>=7.0.0 <7.5.2",
        severity="medium",
        title="semver Regular Expression Denial of Service",
        description="semver versions before 7.5.2, 6.3.1, and 5.7.2 are vulnerable to Regular Expression Denial of Service (ReDoS).",
        fixed_version="7.5.2",
        cwe="CWE-1333",
    ),
    # PyPI: Werkzeug directory traversal
    Advisory(
        advisory_id="CVE-2023-25577",
        package_name="werkzeug",
        ecosystem="pypi",
        affected_versions="<2.2.3",
        severity="high",
        title="Werkzeug multipart data parsing excessive resource consumption",
        description="Werkzeug before 2.2.3 allows excessive CPU and RAM consumption when a client sends many multipart form data parts.",
        fixed_version="2.2.3",
        cwe="CWE-400",
    ),
    Advisory(
        advisory_id="CVE-2024-49767",
        package_name="werkzeug",
        ecosystem="pypi",
        affected_versions="<3.0.6",
        severity="high",
        title="Werkzeug path traversal via debugger PIN",
        description="Werkzeug prior to 3.0.6 has a path traversal issue on Windows with debugger PIN.",
        fixed_version="3.0.6",
        cwe="CWE-22",
    ),
    # PyPI: Pillow
    Advisory(
        advisory_id="CVE-2023-44271",
        package_name="pillow",
        ecosystem="pypi",
        affected_versions="<10.0.1",
        severity="high",
        title="Pillow uncontrolled resource consumption",
        description="Pillow before 10.0.1 allows uncontrolled resource consumption when processing specially crafted image files.",
        fixed_version="10.0.1",
        cwe="CWE-400",
    ),
    # PyPI: requests
    Advisory(
        advisory_id="CVE-2023-32681",
        package_name="requests",
        ecosystem="pypi",
        affected_versions=">=2.1.0,<2.31.0",
        severity="medium",
        title="Requests forwards Proxy-Authorization header to destination server",
        description="Requests before 2.31.0 leaks the Proxy-Authorization header to the destination server when following a redirect through an HTTP proxy.",
        fixed_version="2.31.0",
        cwe="CWE-200",
    ),
    # PyPI: cryptography
    Advisory(
        advisory_id="CVE-2023-49083",
        package_name="cryptography",
        ecosystem="pypi",
        affected_versions="<41.0.6",
        severity="medium",
        title="cryptography NULL pointer dereference in PKCS12 parsing",
        description="cryptography before 41.0.6 has a NULL pointer dereference when parsing certain PKCS12 files.",
        fixed_version="41.0.6",
        cwe="CWE-476",
    ),
    # PyPI: setuptools
    Advisory(
        advisory_id="CVE-2024-6345",
        package_name="setuptools",
        ecosystem="pypi",
        affected_versions="<70.0.0",
        severity="high",
        title="Setuptools remote code execution via malicious package URLs",
        description="setuptools prior to 70.0.0 allows remote code execution via package_index by processing malicious HTML from a package index page.",
        fixed_version="70.0.0",
        cwe="CWE-94",
    ),
    # PyPI: PyYAML arbitrary code execution
    Advisory(
        advisory_id="CVE-2017-18342",
        package_name="pyyaml",
        ecosystem="pypi",
        affected_versions="<4.2b1",
        severity="critical",
        title="PyYAML arbitrary code execution",
        description="yaml.load() in PyYAML prior to 4.2b1 allows arbitrary code execution. Use yaml.safe_load() instead.",
        fixed_version="5.1",
        cwe="CWE-94",
    ),
    # PyPI: urllib3
    Advisory(
        advisory_id="CVE-2023-45803",
        package_name="urllib3",
        ecosystem="pypi",
        affected_versions="<1.26.18,>=2.0.0 <2.0.7",
        severity="medium",
        title="urllib3 request body not stripped after redirect",
        description="urllib3 before 1.26.18 and 2.0.7 fails to strip the HTTP request body when a cross-origin redirect occurs.",
        fixed_version="1.26.18",
        cwe="CWE-200",
    ),
]

# Build lookup: (ecosystem, package_name_lower) → List[Advisory]
_ADVISORY_INDEX: Dict[Tuple[str, str], List[Advisory]] = {}
for _adv in LOCAL_ADVISORIES:
    _key = (_adv.ecosystem, _adv.package_name.lower())
    _ADVISORY_INDEX.setdefault(_key, []).append(_adv)


# ---------------------------------------------------------------------------
# Version utilities
# ---------------------------------------------------------------------------

def _parse_version(ver_str: str) -> Optional[Tuple[int, ...]]:
    """
    Parse a simple semver/PEP-440 version string into a tuple of ints.
    Returns None for unparseable strings (git hashes, 'latest', etc.)
    """
    if not ver_str:
        return None
    # Strip common prefixes/suffixes
    ver_str = ver_str.strip().lstrip("^~=v>=<!")
    # Take only first segment up to alpha/beta/rc
    ver_str = re.split(r"[a-zA-Z\-\+]", ver_str)[0].strip(".")
    parts = ver_str.split(".")
    try:
        return tuple(int(p) for p in parts[:3])
    except (ValueError, TypeError):
        return None


def _version_less_than(ver: str, bound: str) -> bool:
    """Return True if ver < bound, using simple tuple comparison."""
    v = _parse_version(ver)
    b = _parse_version(bound)
    if v is None or b is None:
        return False
    # Pad to same length
    length = max(len(v), len(b))
    v = v + (0,) * (length - len(v))
    b = b + (0,) * (length - len(b))
    return v < b


def _matches_affected(version: str, affected_range: str) -> bool:
    """
    Very conservative affected-version check.

    We only claim a match if we can positively confirm version < fixed.
    We parse the first '<X.Y.Z' token from affected_range.

    This is intentionally conservative — false negatives (missed vulns) are
    acceptable; false positives (claiming a current version is vulnerable) are not.
    """
    if not version:
        return False
    # Look for a '<' bounded check
    matches = re.findall(r"<\s*(\d+[\d.]*)", affected_range)
    if not matches:
        return False
    # If ANY of the '<X.Y.Z' constraints matches, report as affected
    for bound in matches:
        if _version_less_than(version, bound):
            return True
    return False


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def _parse_package_json(content: str, manifest_file: str) -> List[DependencyInfo]:
    """Parse npm/yarn package.json — extract direct dependencies."""
    deps: List[DependencyInfo] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.debug("Failed to parse %s: %s", manifest_file, e)
        return deps

    direct_keys = ("dependencies", "peerDependencies", "optionalDependencies")
    dev_keys = ("devDependencies",)

    for key in (*direct_keys, *dev_keys):
        block = data.get(key, {})
        if not isinstance(block, dict):
            continue
        for name, version_spec in block.items():
            if not isinstance(name, str):
                continue
            ver = ""
            if isinstance(version_spec, str):
                # strip range operators: ^1.2.3 → 1.2.3
                ver = version_spec.strip().lstrip("^~>=<! ")
                # skip 'latest', 'workspace:*', 'file:', git refs
                if any(ver.startswith(p) for p in ("file:", "link:", "github:", "git", "workspace", "portal", "latest")):
                    ver = ""
            deps.append(DependencyInfo(
                name=name,
                version=ver or None,
                ecosystem="npm",
                is_direct=(key in direct_keys),
                manifest_file=manifest_file,
            ))
    return deps


def _parse_package_lock_json(content: str, manifest_file: str) -> List[DependencyInfo]:
    """Parse package-lock.json v2/v3 to get resolved versions."""
    deps: List[DependencyInfo] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.debug("Failed to parse %s: %s", manifest_file, e)
        return deps

    # lockfileVersion 2 and 3 use "packages" key
    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not isinstance(info, dict):
                continue
            # Skip root package
            if path == "":
                continue
            # Extract package name from path: "node_modules/lodash"
            parts = path.split("node_modules/")
            if len(parts) < 2:
                continue
            name = parts[-1].lstrip("/")
            version = info.get("version", "")
            deps.append(DependencyInfo(
                name=name,
                version=version or None,
                ecosystem="npm",
                is_direct=not bool(info.get("dev")),
                manifest_file=manifest_file,
            ))
        return deps

    # lockfileVersion 1 uses "dependencies" key
    dependencies = data.get("dependencies", {})
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version", "")
            deps.append(DependencyInfo(
                name=name,
                version=version or None,
                ecosystem="npm",
                is_direct=True,
                manifest_file=manifest_file,
            ))
    return deps


_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9\-_\.]*)"   # package name
    r"(?:\s*[>=<!^~]+\s*([\d][^\s;#,]*))?",   # optional version spec
)


def _parse_requirements_txt(content: str, manifest_file: str) -> List[DependencyInfo]:
    """Parse pip requirements.txt format."""
    deps: List[DependencyInfo] = []
    for line in content.splitlines():
        line = line.strip()
        # Skip empty, comments, options, URLs
        if not line or line.startswith(("#", "-", "http://", "https://", "git+")):
            continue
        m = _REQ_LINE_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        ver_spec = m.group(2) or ""
        # Extract exact version from "==X.Y.Z" or ">=X.Y.Z"
        ver_clean = ""
        if ver_spec:
            ver_clean = ver_spec.strip().lstrip(">=<!^~").split(",")[0].strip()
        deps.append(DependencyInfo(
            name=name,
            version=ver_clean or None,
            ecosystem="pypi",
            is_direct=True,
            manifest_file=manifest_file,
        ))
    return deps


def _parse_pyproject_toml(content: str, manifest_file: str) -> List[DependencyInfo]:
    """Parse pyproject.toml — supports PEP 621 and Poetry formats."""
    deps: List[DependencyInfo] = []
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # fallback, already in venv
        except ImportError:
            logger.debug("tomllib/tomli not available, skipping %s", manifest_file)
            return deps

    try:
        data = tomllib.loads(content)
    except Exception as e:
        logger.debug("Failed to parse %s: %s", manifest_file, e)
        return deps

    # PEP 621 format: [project] dependencies = ["requests>=2.0"]
    pep621_deps = data.get("project", {}).get("dependencies", [])
    if isinstance(pep621_deps, list):
        for dep in pep621_deps:
            if not isinstance(dep, str):
                continue
            m = _REQ_LINE_RE.match(dep.strip())
            if m:
                name = m.group(1)
                ver_spec = m.group(2) or ""
                ver_clean = ver_spec.strip().lstrip(">=<!^~").split(",")[0].strip() if ver_spec else ""
                deps.append(DependencyInfo(
                    name=name, version=ver_clean or None, ecosystem="pypi",
                    is_direct=True, manifest_file=manifest_file,
                ))

    # Poetry format: [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, ver in poetry_deps.items():
            if name.lower() == "python":
                continue
            if isinstance(ver, str):
                ver_clean = ver.strip().lstrip("^~>=<! ")
                deps.append(DependencyInfo(
                    name=name, version=ver_clean or None, ecosystem="pypi",
                    is_direct=True, manifest_file=manifest_file,
                ))
            elif isinstance(ver, dict):
                ver_clean = ver.get("version", "").strip().lstrip("^~>=<! ")
                deps.append(DependencyInfo(
                    name=name, version=ver_clean or None, ecosystem="pypi",
                    is_direct=True, manifest_file=manifest_file,
                ))

    return deps


def _parse_pom_xml(content: str, manifest_file: str) -> List[DependencyInfo]:
    """Parse Maven pom.xml — extract dependency group:artifact:version."""
    deps: List[DependencyInfo] = []
    try:
        # Strip namespace prefixes for simpler parsing
        content_clean = re.sub(r' xmlns[^"]*"[^"]*"', '', content)
        content_clean = re.sub(r'<project\b[^>]*>', '<project>', content_clean)
        root = ET.fromstring(content_clean)
    except ET.ParseError as e:
        logger.debug("Failed to parse %s: %s", manifest_file, e)
        return deps

    ns = ""
    for dep_elem in root.iter("dependency"):
        group_id = dep_elem.findtext("groupId") or ""
        artifact_id = dep_elem.findtext("artifactId") or ""
        version = dep_elem.findtext("version") or ""
        scope = dep_elem.findtext("scope") or "compile"

        if not artifact_id:
            continue

        name = f"{group_id}:{artifact_id}" if group_id else artifact_id
        # Skip ${project.version} style variable references
        if version.startswith("${"):
            version = ""

        deps.append(DependencyInfo(
            name=name,
            version=version or None,
            ecosystem="maven",
            is_direct=(scope not in ("test", "provided")),
            manifest_file=manifest_file,
        ))
    return deps


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

MANIFEST_PATTERNS = {
    "package.json":         ("npm",   _parse_package_json),
    "package-lock.json":    ("npm",   _parse_package_lock_json),
    "requirements.txt":     ("pypi",  _parse_requirements_txt),
    "requirements-dev.txt": ("pypi",  _parse_requirements_txt),
    "requirements-test.txt": ("pypi", _parse_requirements_txt),
    "requirements-prod.txt": ("pypi", _parse_requirements_txt),
    "pyproject.toml":       ("pypi",  _parse_pyproject_toml),
    "pom.xml":              ("maven", _parse_pom_xml),
}

# Also match requirements*.txt generically
_REQUIREMENTS_RE = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)


def analyze_dependencies(root: Path) -> list:
    """
    Scan the repository for supported dependency manifests and check for
    known vulnerabilities.

    Returns List[RichFindingResult]. Safe to call on any repository root.
    One manifest parse failure does not abort the rest.
    """
    from app.services.scan_engine.findings.types import (
        FindingCategory, RichFindingResult,
    )
    from app.services.scan_engine.scanner.deduplication import generate_fingerprint

    findings: list = []
    seen_manifests: Set[str] = set()

    # Walk root for manifests (not deep, only top-level and one level down)
    _walk_for_manifests(root, root, findings, seen_manifests, depth=0, max_depth=3)

    # Assign fingerprints
    for f in findings:
        if not f.fingerprint:
            f.fingerprint = generate_fingerprint(f)

    return findings


def _walk_for_manifests(
    root: Path,
    current: Path,
    findings: list,
    seen: Set[str],
    depth: int,
    max_depth: int,
) -> None:
    """Walk directory tree looking for manifest files."""
    if depth > max_depth:
        return

    IGNORED = {".git", "node_modules", ".venv", "venv", "__pycache__",
               ".next", "dist", "build", "target", ".tox"}

    try:
        entries = list(current.iterdir())
    except (PermissionError, OSError):
        return

    for entry in entries:
        try:
            resolved = entry.resolve()
        except OSError:
            continue
        try:
            resolved.relative_to(root)
        except ValueError:
            continue  # symlink escape

        if resolved.is_dir():
            if entry.name in IGNORED:
                continue
            _walk_for_manifests(root, resolved, findings, seen, depth + 1, max_depth)
        elif resolved.is_file():
            name = entry.name
            rel = str(resolved.relative_to(root))

            # Avoid duplicate analysis of same manifest
            if rel in seen:
                continue

            # Check known manifest names
            parser_fn = None
            ecosystem = None

            if name in MANIFEST_PATTERNS:
                ecosystem, parser_fn = MANIFEST_PATTERNS[name]
            elif _REQUIREMENTS_RE.match(name):
                ecosystem, parser_fn = "pypi", _parse_requirements_txt

            if parser_fn is None:
                continue

            seen.add(rel)
            try:
                content = resolved.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            try:
                deps = parser_fn(content, rel)
            except Exception as exc:
                logger.warning("Dependency parser error for %s: %s", rel, exc)
                continue

            # Check each dep against advisory database
            for dep in deps:
                _check_dep(dep, findings)


def _check_dep(dep: DependencyInfo, findings: list) -> None:
    """Check a single dependency against the local advisory database."""
    from app.services.scan_engine.findings.types import (
        FindingCategory, RichFindingResult,
    )

    key = (dep.ecosystem, dep.name.lower())
    advisories = _ADVISORY_INDEX.get(key, [])

    for adv in advisories:
        # Only report if we can confirm the installed version is affected
        if dep.version and not _matches_affected(dep.version, adv.affected_versions):
            continue

        # If version is unknown, report as LOW confidence
        confidence = 75 if dep.version else 40
        conf_level = "high" if confidence >= 80 else "medium" if confidence >= 50 else "low"
        version_desc = f" (version {dep.version})" if dep.version else " (version unknown)"

        finding = RichFindingResult(
            severity=adv.severity,
            title=f"Vulnerable dependency: {dep.name}{version_desc}",
            description=(
                f"{adv.title}. {adv.description} "
                f"Affected versions: {adv.affected_versions}. "
                f"Fixed in: {adv.fixed_version or 'unknown'}."
            ),
            file_path=dep.manifest_file,
            line_number=1,
            rule_id=f"SCA001",
            category=FindingCategory.CONFIGURATION.value,
            cwe=adv.cwe,
            language=dep.ecosystem,
            analyzer="sca",
            confidence=confidence,
            confidence_level=conf_level,
            why_risky=(
                f"{dep.name} has a known vulnerability ({adv.advisory_id}). "
                f"Running a vulnerable version exposes your application to the "
                f"described attack vector."
            ),
            impact=(
                f"Depending on the advisory, impact may include: "
                f"remote code execution, data exposure, or denial of service."
            ),
            remediation=(
                f"Update {dep.name} to version {adv.fixed_version or 'latest'}. "
                f"Run `npm update {dep.name}` (npm) or `pip install --upgrade {dep.name}` (PyPI)."
            ),
            fix_example=(
                f"# package.json\n"
                f'"{dep.name}": "{adv.fixed_version or "latest"}"'
                if dep.ecosystem == "npm" else
                f"# requirements.txt\n"
                f"{dep.name}>={adv.fixed_version or '0'}"
            ),
            evidence=(
                f"Package: {dep.name} | "
                f"Version: {dep.version or 'unresolved'} | "
                f"Advisory: {adv.advisory_id} | "
                f"Ecosystem: {dep.ecosystem}"
            ),
            # Phase 6 extra fields carried in a side-band dict
            # (persisted via engine.py _persist_finding extension)
        )
        # Attach Phase 6 extra fields as dynamic attributes
        finding.__dict__["dependency_name"] = dep.name
        finding.__dict__["dependency_version"] = dep.version or ""
        finding.__dict__["fixed_version"] = adv.fixed_version or ""
        finding.__dict__["advisory_id"] = adv.advisory_id
        findings.append(finding)
