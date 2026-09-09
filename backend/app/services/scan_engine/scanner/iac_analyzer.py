"""
Infrastructure-as-Code (IaC) Security Analyzer — Phase 6.

Analyzes:
  - Dockerfile
  - docker-compose.yml / compose.yaml / docker-compose.yaml
  - GitHub Actions workflows (.github/workflows/*.yml)
  - Kubernetes YAML manifests
  - Terraform (.tf) files

Each check has an explicit rule_id, evidence-based confidence, and
context-aware severity. Rules are conservative: we don't claim vulnerability
without evidence.

No code is executed. Parsing is safe (regex + PyYAML + line scanning).
PyYAML uses safe_load exclusively.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# YAML safe loading helper
# ---------------------------------------------------------------------------

def _yaml_safe_load(content: str) -> Optional[Any]:
    """Load YAML using safe_load. Returns None on parse error."""
    try:
        import yaml  # PyYAML
        return yaml.safe_load(content)
    except Exception as exc:
        logger.debug("YAML parse error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# IaC Rule metadata
# ---------------------------------------------------------------------------

IAC_RULE_META: Dict[str, Dict] = {
    "IAC001": {
        "title": "Dockerfile: running as root user",
        "severity": "medium",
        "cwe": "CWE-250",
        "category": "configuration",
        "why_risky": "Running as root inside a container means a container breakout grants root on the host.",
        "remediation": "Add `USER nonroot` or `USER 1000` before the ENTRYPOINT/CMD instruction.",
        "fix_example": "USER nonroot\nCMD [\"app\"]",
    },
    "IAC002": {
        "title": "Dockerfile: privileged mode or dangerous capability",
        "severity": "high",
        "cwe": "CWE-250",
        "category": "configuration",
        "why_risky": "Privileged containers have access to all host devices and can escape container isolation.",
        "remediation": "Remove --privileged or cap-add ALL. Use only the minimal required capabilities.",
        "fix_example": "# docker-compose\nsecurity_opt:\n  - no-new-privileges:true",
    },
    "IAC003": {
        "title": "Dockerfile: secret or credential in ENV or ARG",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "why_risky": "Secrets in Dockerfile ENV/ARG are baked into the image layers and visible via docker inspect.",
        "remediation": "Use Docker secrets, BuildKit --secret mounts, or environment variables at runtime.",
        "fix_example": "# Use runtime secrets instead:\nRUN --mount=type=secret,id=api_key cat /run/secrets/api_key",
    },
    "IAC004": {
        "title": "Docker Compose: hardcoded password in environment",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "why_risky": "Hardcoded passwords in compose files are committed to version control and visible to all repo readers.",
        "remediation": "Use environment variable substitution (${MY_PASSWORD}) or a .env file excluded from version control.",
        "fix_example": "environment:\n  - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}",
    },
    "IAC005": {
        "title": "Docker Compose: exposed sensitive port",
        "severity": "medium",
        "cwe": "CWE-200",
        "category": "configuration",
        "why_risky": "Exposing database or admin ports to 0.0.0.0 makes them accessible from any network interface.",
        "remediation": "Bind ports to 127.0.0.1: `- '127.0.0.1:5432:5432'`",
        "fix_example": "ports:\n  - '127.0.0.1:5432:5432'",
    },
    "IAC006": {
        "title": "GitHub Actions: dangerous pull_request_target usage",
        "severity": "high",
        "cwe": "CWE-78",
        "category": "configuration",
        "why_risky": "pull_request_target runs with write access even for forks. Combined with code checkout, this enables code injection.",
        "remediation": "Avoid checking out PR head code in pull_request_target workflows. Use environment protection rules.",
        "fix_example": "on:\n  pull_request:  # use pull_request instead of pull_request_target",
    },
    "IAC007": {
        "title": "GitHub Actions: write-all or excessive permissions",
        "severity": "medium",
        "cwe": "CWE-269",
        "category": "configuration",
        "why_risky": "Granting write-all permissions gives every job in the workflow full write access to the repository.",
        "remediation": "Use least-privilege permissions. Explicitly grant only needed permissions per job.",
        "fix_example": "permissions:\n  contents: read\n  pull-requests: write",
    },
    "IAC008": {
        "title": "GitHub Actions: secret exposed in run step",
        "severity": "high",
        "cwe": "CWE-532",
        "category": "secrets",
        "why_risky": "Printing secrets to logs or using them in ways that might be echoed can expose credentials.",
        "remediation": "Never echo secrets. Use GitHub's secret masking: `${{ secrets.MY_SECRET }}`.",
        "fix_example": "- run: ./deploy.sh\n  env:\n    API_KEY: ${{ secrets.API_KEY }}",
    },
    "IAC009": {
        "title": "Kubernetes: container running as root",
        "severity": "medium",
        "cwe": "CWE-250",
        "category": "configuration",
        "why_risky": "Containers running as root increase blast radius if compromised.",
        "remediation": "Set securityContext.runAsNonRoot: true and securityContext.runAsUser: <uid>.",
        "fix_example": "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
    },
    "IAC010": {
        "title": "Kubernetes: privileged container",
        "severity": "high",
        "cwe": "CWE-250",
        "category": "configuration",
        "why_risky": "Privileged Kubernetes containers have full access to the host node.",
        "remediation": "Set securityContext.privileged: false (the default). Never set it to true.",
        "fix_example": "securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false",
    },
    "IAC011": {
        "title": "Kubernetes: hostNetwork or hostPID enabled",
        "severity": "high",
        "cwe": "CWE-284",
        "category": "configuration",
        "why_risky": "hostNetwork/hostPID allows containers to see the host's network/process namespace.",
        "remediation": "Remove hostNetwork: true and hostPID: true from pod specs.",
        "fix_example": "spec:\n  hostNetwork: false\n  hostPID: false",
    },
    "IAC012": {
        "title": "Terraform: unrestricted ingress (0.0.0.0/0)",
        "severity": "high",
        "cwe": "CWE-284",
        "category": "configuration",
        "why_risky": "A security group allowing ingress from 0.0.0.0/0 exposes the resource to the entire internet.",
        "remediation": "Restrict cidr_blocks to known IP ranges. Use least-privilege network policies.",
        "fix_example": "ingress {\n  cidr_blocks = [\"10.0.0.0/8\"]\n}",
    },
    "IAC013": {
        "title": "Terraform: hardcoded secret in resource",
        "severity": "high",
        "cwe": "CWE-798",
        "category": "secrets",
        "why_risky": "Secrets in Terraform files are stored in state and committed to version control.",
        "remediation": "Use terraform variable with sensitive = true, or use a secrets manager data source.",
        "fix_example": "variable \"db_password\" {\n  sensitive = true\n}\n\nresource \"...\" {\n  password = var.db_password\n}",
    },
    "IAC014": {
        "title": "GitHub Actions: untrusted action pinned to mutable tag",
        "severity": "medium",
        "cwe": "CWE-494",
        "category": "configuration",
        "why_risky": "Using `uses: action/name@v2` (mutable tag) allows the action owner to push malicious code.",
        "remediation": "Pin actions to a full commit SHA: `uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675`.",
        "fix_example": "uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
    },
    "IAC015": {
        "title": "GitHub Actions: command injection via untrusted input in run step",
        "severity": "high",
        "cwe": "CWE-78",
        "category": "command_injection",
        "why_risky": "Using ${{ github.event.* }} or ${{ github.head_ref }} directly in run steps allows code injection.",
        "remediation": "Use an intermediate env variable: `env: TITLE: ${{ github.event.issue.title }}` then reference `$TITLE`.",
        "fix_example": "- name: Use title safely\n  env:\n    ISSUE_TITLE: ${{ github.event.issue.title }}\n  run: echo \"$ISSUE_TITLE\"",
    },
}


# ---------------------------------------------------------------------------
# Dockerfile analyzer
# ---------------------------------------------------------------------------

_SECRET_NAMES_RE = re.compile(
    r"(?:API_KEY|SECRET|PASSWORD|PASSWD|TOKEN|AUTH|PRIVATE_KEY|ACCESS_KEY"
    r"|DB_PASS|DATABASE_URL)",
    re.IGNORECASE,
)

# Matches ENV KEY=value or ARG KEY=value with a value that looks like a secret
_DOCKERFILE_ENV_SECRET_RE = re.compile(
    r"^(ENV|ARG)\s+"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*"  # optional earlier pairs
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]?)([^'\"\s]{8,})\3",
    re.IGNORECASE,
)

_DOCKERFILE_USER_RE = re.compile(r"^USER\s+(\S+)", re.IGNORECASE)
_DOCKERFILE_FROM_RE = re.compile(r"^FROM\s+\S+", re.IGNORECASE)


def analyze_dockerfile(content: str, file_path: str) -> list:
    """Analyze a Dockerfile for security issues."""
    from app.services.scan_engine.findings.types import FindingCategory, RichFindingResult

    findings: list = []
    lines = content.splitlines()
    has_user_instruction = False
    last_from_line = 0

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Track FROM instructions
        if _DOCKERFILE_FROM_RE.match(stripped):
            last_from_line = lineno
            has_user_instruction = False  # reset per stage

        # Check USER instruction
        m = _DOCKERFILE_USER_RE.match(stripped)
        if m:
            user = m.group(1).lower()
            if user not in ("0", "root"):
                has_user_instruction = True
            continue

        # Check ENV/ARG with secret-looking values
        m = _DOCKERFILE_ENV_SECRET_RE.match(stripped)
        if m:
            var_name = m.group(2)
            value = m.group(4)
            if _SECRET_NAMES_RE.search(var_name) and len(value) >= 8:
                # Exclude ${VAR} style substitution (already a variable reference)
                if not value.startswith("${"):
                    meta = IAC_RULE_META["IAC003"]
                    f = _make_iac_finding(
                        file_path=file_path,
                        line=lineno,
                        rule_id="IAC003",
                        evidence=f"ENV/ARG {var_name}=***",
                        confidence=80,
                        **meta,
                    )
                    findings.append(f)

    # Check for missing USER instruction (running as root by default)
    if last_from_line > 0 and not has_user_instruction:
        meta = IAC_RULE_META["IAC001"]
        f = _make_iac_finding(
            file_path=file_path,
            line=last_from_line,
            rule_id="IAC001",
            evidence="No USER instruction found; container runs as root by default",
            confidence=70,
            **meta,
        )
        findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Docker Compose analyzer
# ---------------------------------------------------------------------------

_PASSWORD_ENV_RE = re.compile(
    r"(password|passwd|secret|api.?key|access.?key|db_pass)\s*=\s*([^${\n\s]{4,})",
    re.IGNORECASE,
)

_SENSITIVE_PORTS = {
    "5432",   # PostgreSQL
    "3306",   # MySQL
    "6379",   # Redis
    "27017",  # MongoDB
    "9200",   # Elasticsearch
    "2181",   # ZooKeeper
    "8500",   # Consul
    "9092",   # Kafka
}


def analyze_docker_compose(content: str, file_path: str) -> list:
    """Analyze docker-compose YAML for security issues."""
    from app.services.scan_engine.findings.types import FindingCategory, RichFindingResult

    findings: list = []
    lines = content.splitlines()

    # Line-by-line scan for hardcoded passwords
    for lineno, line in enumerate(lines, start=1):
        m = _PASSWORD_ENV_RE.search(line)
        if m:
            value = m.group(2).strip()
            # Skip variable substitution patterns
            if value.startswith("${") or value.startswith("$"):
                continue
            # Skip obvious placeholders
            if len(value) < 4 or re.match(r"^(changeme|password|secret|example)", value, re.IGNORECASE):
                continue
            meta = IAC_RULE_META["IAC004"]
            f = _make_iac_finding(
                file_path=file_path,
                line=lineno,
                rule_id="IAC004",
                evidence=f"{m.group(1)}=***",
                confidence=75,
                **meta,
            )
            findings.append(f)

    # Check for sensitive ports exposed to 0.0.0.0
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Match ports like "5432:5432" or "0.0.0.0:5432:5432" (NOT 127.0.0.1:...)
        port_m = re.search(r"['\"]?(?:0\.0\.0\.0:)?(\d+):\d+['\"]?", stripped)
        if port_m:
            port = port_m.group(1)
            if port in _SENSITIVE_PORTS:
                # Only flag if NOT bound to 127.0.0.1
                if "127.0.0.1" not in stripped:
                    meta = IAC_RULE_META["IAC005"]
                    f = _make_iac_finding(
                        file_path=file_path,
                        line=lineno,
                        rule_id="IAC005",
                        evidence=f"Port {port} exposed to 0.0.0.0",
                        confidence=70,
                        **meta,
                    )
                    findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# GitHub Actions analyzer
# ---------------------------------------------------------------------------

_GITHUB_EVENT_INJECT_RE = re.compile(
    r"\$\{\{\s*github\.event\."
    r"(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body"
    r"|head_commit\.message|pages\.[^}]+)",
    re.IGNORECASE,
)

_GITHUB_SECRETS_RE = re.compile(
    r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}"
)

_GACTIONS_USES_RE = re.compile(r"^\s+(?:-\s+)?uses:\s+([^\s@#]+)@([^\s#]+)")


def analyze_github_actions(content: str, file_path: str) -> list:
    """Analyze GitHub Actions workflow YAML for security issues."""
    from app.services.scan_engine.findings.types import FindingCategory, RichFindingResult

    findings: list = []
    lines = content.splitlines()
    data = _yaml_safe_load(content)

    # Check top-level permissions
    if isinstance(data, dict):
        perms = data.get("permissions")
        if perms == "write-all" or (isinstance(perms, str) and perms.lower() == "write-all"):
            meta = IAC_RULE_META["IAC007"]
            f = _make_iac_finding(
                file_path=file_path,
                line=1,
                rule_id="IAC007",
                evidence="permissions: write-all",
                confidence=95,
                **meta,
            )
            findings.append(f)

        # Check for pull_request_target
        on_block = data.get("on", data.get(True, {}))  # 'on' is True in some YAML parsers
        if isinstance(on_block, dict) and "pull_request_target" in on_block:
            meta = IAC_RULE_META["IAC006"]
            f = _make_iac_finding(
                file_path=file_path,
                line=1,
                rule_id="IAC006",
                evidence="trigger: pull_request_target",
                confidence=75,
                **meta,
            )
            findings.append(f)

    # Line-by-line checks
    in_run_block = False
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Detect command injection via untrusted github.event inputs in run steps
        if _GITHUB_EVENT_INJECT_RE.search(line):
            meta = IAC_RULE_META["IAC015"]
            f = _make_iac_finding(
                file_path=file_path,
                line=lineno,
                rule_id="IAC015",
                evidence=stripped[:120],
                confidence=80,
                **meta,
            )
            findings.append(f)

        # Check for mutable tag actions (not pinned to SHA)
        m = _GACTIONS_USES_RE.match(line)
        if m:
            action_name = m.group(1)
            tag = m.group(2).strip()
            # SHA is 40 hex chars; anything else is mutable
            if not re.match(r"^[0-9a-f]{40}$", tag, re.IGNORECASE):
                # Only warn for non-local actions (local start with ./)
                if not action_name.startswith("./") and not action_name.startswith("docker://"):
                    meta = IAC_RULE_META["IAC014"]
                    f = _make_iac_finding(
                        file_path=file_path,
                        line=lineno,
                        rule_id="IAC014",
                        evidence=f"uses: {action_name}@{tag}",
                        confidence=60,
                        **meta,
                    )
                    findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Kubernetes YAML analyzer
# ---------------------------------------------------------------------------

def analyze_kubernetes(content: str, file_path: str) -> list:
    """Analyze Kubernetes manifest YAML for security issues."""
    findings: list = []
    data = _yaml_safe_load(content)

    if not isinstance(data, dict):
        return findings

    kind = data.get("kind", "")
    if kind not in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"):
        return findings

    _check_k8s_containers(data, file_path, findings)
    return findings


def _check_k8s_containers(data: dict, file_path: str, findings: list) -> None:
    """Recursively check containers in a Kubernetes manifest."""
    # Navigate to spec.template.spec or spec for Pods
    spec = data.get("spec", {})
    if not isinstance(spec, dict):
        return

    template_spec = spec.get("template", {}).get("spec", spec)
    if not isinstance(template_spec, dict):
        return

    # Check pod-level settings
    if template_spec.get("hostNetwork") is True:
        meta = IAC_RULE_META["IAC011"]
        f = _make_iac_finding(
            file_path=file_path,
            line=1,
            rule_id="IAC011",
            evidence="hostNetwork: true",
            confidence=95,
            **meta,
        )
        findings.append(f)

    if template_spec.get("hostPID") is True:
        meta = IAC_RULE_META["IAC011"]
        f = _make_iac_finding(
            file_path=file_path,
            line=1,
            rule_id="IAC011",
            evidence="hostPID: true",
            confidence=95,
            **meta,
        )
        findings.append(f)

    containers = template_spec.get("containers", [])
    if not isinstance(containers, list):
        return

    for container in containers:
        if not isinstance(container, dict):
            continue

        sc = container.get("securityContext", {})
        if not isinstance(sc, dict):
            sc = {}

        # Check for privileged: true
        if sc.get("privileged") is True:
            meta = IAC_RULE_META["IAC010"]
            f = _make_iac_finding(
                file_path=file_path,
                line=1,
                rule_id="IAC010",
                evidence=f"container '{container.get('name', '?')}' privileged: true",
                confidence=95,
                **meta,
            )
            findings.append(f)

        # Check for running as root
        run_as_non_root = sc.get("runAsNonRoot")
        run_as_user = sc.get("runAsUser")

        if run_as_non_root is False or run_as_user == 0:
            meta = IAC_RULE_META["IAC009"]
            f = _make_iac_finding(
                file_path=file_path,
                line=1,
                rule_id="IAC009",
                evidence=f"container '{container.get('name', '?')}' runAsRoot",
                confidence=90,
                **meta,
            )
            findings.append(f)


# ---------------------------------------------------------------------------
# Terraform analyzer
# ---------------------------------------------------------------------------

_TF_INGRESS_CIDR_RE = re.compile(
    r"""cidr_blocks\s*=\s*\[["']0\.0\.0\.0/0["']\]""",
    re.IGNORECASE,
)

_TF_SECRET_RE = re.compile(
    r"""(?:password|secret|api_key|access_key|private_key|token)\s*=\s*['"]([^'"]{8,})['"]""",
    re.IGNORECASE,
)


def analyze_terraform(content: str, file_path: str) -> list:
    """Analyze Terraform HCL files for security issues."""
    findings: list = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Check for unrestricted ingress
        if _TF_INGRESS_CIDR_RE.search(line):
            meta = IAC_RULE_META["IAC012"]
            f = _make_iac_finding(
                file_path=file_path,
                line=lineno,
                rule_id="IAC012",
                evidence=stripped[:120],
                confidence=90,
                **meta,
            )
            findings.append(f)

        # Check for hardcoded secrets
        m = _TF_SECRET_RE.search(line)
        if m:
            value = m.group(1)
            # Skip variable references
            if not value.startswith("${") and not value.startswith("var."):
                meta = IAC_RULE_META["IAC013"]
                f = _make_iac_finding(
                    file_path=file_path,
                    line=lineno,
                    rule_id="IAC013",
                    evidence=re.sub(r"(['\"])([^'\"]{4,})(['\"])", r"\1***\3", stripped[:120]),
                    confidence=80,
                    **meta,
                )
                findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Shared finding factory
# ---------------------------------------------------------------------------

def _make_iac_finding(
    file_path: str,
    line: int,
    rule_id: str,
    evidence: str,
    confidence: int,
    title: str,
    severity: str,
    cwe: str,
    category: str,
    why_risky: str,
    remediation: str,
    fix_example: str,
    **kwargs,
) -> Any:
    """Create a RichFindingResult for an IaC issue."""
    import hashlib
    from app.services.scan_engine.findings.types import FindingCategory, RichFindingResult

    conf_level = "high" if confidence >= 80 else "medium" if confidence >= 50 else "low"
    line_bucket = (line // 5) * 5
    raw_fp = f"{rule_id}:{file_path}:{line_bucket}"
    fingerprint = hashlib.sha256(raw_fp.encode()).hexdigest()[:16]

    # Map category string to FindingCategory value
    cat_map = {
        "configuration": FindingCategory.CONFIGURATION.value,
        "secrets": FindingCategory.SECRETS.value,
        "command_injection": FindingCategory.COMMAND_INJECTION.value,
    }
    cat_val = cat_map.get(category, FindingCategory.CONFIGURATION.value)

    return RichFindingResult(
        severity=severity,
        title=title,
        description=f"{why_risky}",
        file_path=file_path,
        line_number=line,
        rule_id=rule_id,
        category=cat_val,
        cwe=cwe,
        language="yaml" if any(file_path.endswith(e) for e in (".yml", ".yaml")) else "terraform",
        analyzer="iac",
        confidence=confidence,
        confidence_level=conf_level,
        why_risky=why_risky,
        remediation=remediation,
        fix_example=fix_example,
        evidence=evidence,
        fingerprint=fingerprint,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

# Match filenames
_DOCKERFILE_RE = re.compile(r"^Dockerfile(\.[A-Za-z0-9._-]+)?$")
_COMPOSE_RE = re.compile(r"^docker-compose(\.[A-Za-z0-9._-]+)?\.ya?ml$|^compose\.ya?ml$", re.IGNORECASE)
_GITHUB_ACTIONS_RE = re.compile(r"\.github[/\\]workflows[/\\].*\.ya?ml$")
_K8S_FIELDS_RE = re.compile(r"(?:apiVersion|kind|metadata|spec):", re.IGNORECASE)
_TF_RE = re.compile(r"\.tf$", re.IGNORECASE)

_IGNORED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".next", "dist", "build", "target", ".tox",
}


def analyze_iac(root: Path) -> list:
    """
    Scan the repository for IaC security issues.

    Returns List[RichFindingResult].
    Handles parse errors gracefully per file.
    """
    from app.services.scan_engine.scanner.deduplication import deduplicate

    all_findings: list = []
    _walk_iac(root, root, all_findings)
    return deduplicate(all_findings)


def _walk_iac(root: Path, current: Path, findings: list) -> None:
    """Walk directory tree scanning IaC files."""
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
            continue

        if resolved.is_dir():
            if entry.name in _IGNORED_DIRS:
                continue
            _walk_iac(root, resolved, findings)
        elif resolved.is_file():
            rel = str(resolved.relative_to(root))
            _analyze_iac_file(resolved, rel, findings)


def _analyze_iac_file(path: Path, rel: str, findings: list) -> None:
    """Analyze a single file for IaC issues."""
    name = path.name
    try:
        size = path.stat().st_size
        if size > 512 * 1024:
            return
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    try:
        if _DOCKERFILE_RE.match(name):
            findings.extend(analyze_dockerfile(content, rel))
        elif _COMPOSE_RE.match(name):
            findings.extend(analyze_docker_compose(content, rel))
        elif _GITHUB_ACTIONS_RE.search(rel):
            findings.extend(analyze_github_actions(content, rel))
        elif _TF_RE.search(rel):
            findings.extend(analyze_terraform(content, rel))
        elif name.endswith((".yml", ".yaml")):
            # Check if it looks like a Kubernetes manifest
            if _K8S_FIELDS_RE.search(content[:500]):
                k8s_findings = analyze_kubernetes(content, rel)
                if k8s_findings:
                    findings.extend(k8s_findings)
    except Exception as exc:
        logger.warning("IaC analyzer error for %s: %s", rel, exc)
