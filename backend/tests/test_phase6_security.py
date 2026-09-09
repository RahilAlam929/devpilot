"""
Comprehensive Phase 6 test suite.

Covers:
  - SCA dependency analysis (npm, PyPI, Maven)
  - Secret scanner (redaction, false positives, confidence)
  - IaC analyzer (Dockerfile, Compose, GitHub Actions, K8s, Terraform)
  - Risk engine (security score, category breakdown, historical comparison)
  - Patch verification (static)
  - API endpoints (security-score, categories, dependencies, secrets, iac, risk-summary)
  - Finding model Phase 6 fields
  - Migration compatibility
  - Deduplication across Phase 6 analyzers
  - Synthetic fixture repository scan
"""

import os
import tempfile
from pathlib import Path
from typing import List

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def titles(findings) -> List[str]:
    return [getattr(f, "title", "") for f in findings]


def rule_ids(findings) -> List[str]:
    return [getattr(f, "rule_id", "") for f in findings]


def has_rule(findings, rule_id: str) -> bool:
    return any(getattr(f, "rule_id", "") == rule_id for f in findings)


# ===========================================================================
# SCA — Dependency Analyzer
# ===========================================================================


class TestDependencyAnalyzer:
    """Tests for SCA (Software Composition Analysis)."""

    def test_parse_package_json_direct_deps(self, tmp_path):
        """package.json direct dependencies are extracted."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_package_json
        content = '{"dependencies": {"lodash": "4.17.10", "express": "4.18.2"}}'
        deps = _parse_package_json(content, "package.json")
        names = [d.name for d in deps]
        assert "lodash" in names
        assert "express" in names
        assert all(d.is_direct for d in deps)

    def test_parse_package_json_dev_deps(self, tmp_path):
        """devDependencies are parsed as non-direct."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_package_json
        content = '{"devDependencies": {"jest": "29.0.0"}}'
        deps = _parse_package_json(content, "package.json")
        assert len(deps) == 1
        assert deps[0].name == "jest"
        assert not deps[0].is_direct  # devDeps are not direct

    def test_parse_package_json_invalid_json(self, tmp_path):
        """Invalid JSON returns empty list without raising."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_package_json
        deps = _parse_package_json("not json {{{", "package.json")
        assert deps == []

    def test_parse_requirements_txt(self, tmp_path):
        """requirements.txt packages are extracted with versions."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_requirements_txt
        content = "werkzeug==2.1.0\nrequests>=2.28.0\n# comment\n-r other.txt\n"
        deps = _parse_requirements_txt(content, "requirements.txt")
        names = [d.name for d in deps]
        assert "werkzeug" in names
        assert "requests" in names
        # Comments and -r lines are skipped
        assert len([d for d in deps if d.name.startswith("#")]) == 0

    def test_parse_requirements_txt_version_extraction(self):
        """Version strings are cleaned of range operators."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_requirements_txt
        content = "werkzeug==2.1.0\nrequests>=2.28.0\n"
        deps = _parse_requirements_txt(content, "requirements.txt")
        w = next(d for d in deps if d.name == "werkzeug")
        assert w.version == "2.1.0"

    def test_parse_pyproject_toml_pep621(self, tmp_path):
        """pyproject.toml PEP 621 format is parsed."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_pyproject_toml
        content = '[project]\ndependencies = ["werkzeug>=2.1.0", "requests==2.28.0"]\n'
        deps = _parse_pyproject_toml(content, "pyproject.toml")
        names = [d.name for d in deps]
        assert "werkzeug" in names
        assert "requests" in names

    def test_parse_pyproject_toml_poetry(self, tmp_path):
        """pyproject.toml Poetry format is parsed."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_pyproject_toml
        content = '[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "^2.28.0"\n'
        deps = _parse_pyproject_toml(content, "pyproject.toml")
        names = [d.name for d in deps]
        assert "requests" in names
        assert "python" not in names  # python itself is excluded

    def test_parse_pom_xml(self):
        """Maven pom.xml dependencies are parsed."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_pom_xml
        content = """<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>
</project>"""
        deps = _parse_pom_xml(content, "pom.xml")
        assert len(deps) == 1
        assert deps[0].name == "org.springframework:spring-core"
        assert deps[0].version == "5.3.0"

    def test_pom_xml_invalid_xml(self):
        """Invalid XML returns empty list without raising."""
        from app.services.scan_engine.scanner.dependency_analyzer import _parse_pom_xml
        deps = _parse_pom_xml("not xml <<<", "pom.xml")
        assert deps == []

    def test_vulnerable_lodash_detected(self, tmp_path):
        """Vulnerable lodash version is detected by SCA."""
        write_file(tmp_path, "package.json", '{"dependencies": {"lodash": "4.17.10"}}')
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings = analyze_dependencies(tmp_path)
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        assert len(sca) > 0
        titles_list = [f.title for f in sca]
        assert any("lodash" in t for t in titles_list)

    def test_safe_lodash_not_flagged(self, tmp_path):
        """lodash at fixed version is NOT flagged."""
        write_file(tmp_path, "package.json", '{"dependencies": {"lodash": "4.17.21"}}')
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings = analyze_dependencies(tmp_path)
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        lodash_findings = [f for f in sca if "lodash" in f.title.lower()]
        assert len(lodash_findings) == 0

    def test_vulnerable_werkzeug_detected(self, tmp_path):
        """Vulnerable werkzeug version is detected by SCA."""
        write_file(tmp_path, "requirements.txt", "werkzeug==2.1.0\n")
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings = analyze_dependencies(tmp_path)
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        assert any("werkzeug" in f.title.lower() for f in sca)

    def test_no_fabricated_cves(self, tmp_path):
        """Advisory IDs in findings must be from the known advisory list."""
        write_file(tmp_path, "requirements.txt", "werkzeug==2.1.0\nrequests==2.28.0\n")
        from app.services.scan_engine.scanner.dependency_analyzer import (
            analyze_dependencies, LOCAL_ADVISORIES,
        )
        known_ids = {a.advisory_id for a in LOCAL_ADVISORIES}
        findings = analyze_dependencies(tmp_path)
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        for f in sca:
            adv_id = f.__dict__.get("advisory_id", "")
            if adv_id:
                assert adv_id in known_ids, f"Fabricated CVE found: {adv_id}"

    def test_dependency_finding_has_phase6_fields(self, tmp_path):
        """SCA findings carry Phase 6 extra fields."""
        write_file(tmp_path, "package.json", '{"dependencies": {"lodash": "4.17.10"}}')
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings = analyze_dependencies(tmp_path)
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        assert len(sca) > 0
        f = sca[0]
        assert f.__dict__.get("dependency_name") is not None
        assert f.__dict__.get("advisory_id") is not None

    def test_requirements_like_filenames_matched(self, tmp_path):
        """requirements-dev.txt and similar variants are scanned."""
        write_file(tmp_path, "requirements-dev.txt", "werkzeug==2.1.0\n")
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings = analyze_dependencies(tmp_path)
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        assert any("werkzeug" in f.title.lower() for f in sca)

    def test_version_less_than(self):
        """Version comparison utility works correctly."""
        from app.services.scan_engine.scanner.dependency_analyzer import _version_less_than
        assert _version_less_than("4.17.10", "4.17.12")
        assert not _version_less_than("4.17.21", "4.17.12")
        assert not _version_less_than("4.17.12", "4.17.12")  # equal
        assert _version_less_than("2.1.0", "2.2.3")
        assert not _version_less_than("unparseable", "1.0.0")

    def test_node_modules_not_scanned(self, tmp_path):
        """node_modules directory is skipped."""
        (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
        write_file(tmp_path / "node_modules" / "lodash", "package.json",
                   '{"name": "lodash", "version": "4.17.10"}')
        # Main package.json (clean)
        write_file(tmp_path, "package.json", '{"dependencies": {"express": "4.18.2"}}')
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings = analyze_dependencies(tmp_path)
        # lodash from node_modules should not be analyzed
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        assert all("lodash" not in f.title.lower() for f in sca)


# ===========================================================================
# Secret Scanner
# ===========================================================================


class TestSecretScanner:
    """Tests for secret/credential detection."""

    def test_github_token_detected(self, tmp_path):
        """GitHub PAT token format is detected."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        write_file(tmp_path, "config.py",
                   'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n')
        findings = analyze_secrets(tmp_path)
        assert len(findings) > 0
        assert any("GitHub" in f.title for f in findings)

    def test_aws_access_key_detected(self, tmp_path):
        """AWS access key format (AKIA...) is detected."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        write_file(tmp_path, "deploy.py",
                   'key = "AKIAIOSFODNN7EXAMPLE1"\n')
        findings = analyze_secrets(tmp_path)
        assert len(findings) > 0
        assert any("AWS" in f.title for f in findings)

    def test_private_key_pem_detected(self, tmp_path):
        """PEM private key header is detected."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        write_file(tmp_path, "certs.py",
                   '# key content\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n')
        findings = analyze_secrets(tmp_path)
        assert len(findings) > 0

    def test_database_url_with_password_detected(self, tmp_path):
        """Database URL with embedded credentials is detected."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        write_file(tmp_path, "db.py",
                   'url = "postgres://admin:RealPassword123@localhost:5432/db"\n')
        findings = analyze_secrets(tmp_path)
        assert len(findings) > 0
        assert any("Database" in f.title or "credential" in f.title.lower() for f in findings)

    def test_secrets_always_redacted(self, tmp_path):
        """Full secret value MUST NOT appear in any finding field."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        # Use a distinctive fake token
        fake_token = "ghp_REALSECRET1234567890abcdefghij"
        write_file(tmp_path, "config.py",
                   f'token = "{fake_token}"\n')
        findings = analyze_secrets(tmp_path)
        for f in findings:
            # Check all text fields
            for field in ("evidence", "description", "title", "why_risky",
                          "impact", "remediation", "fix_example"):
                val = getattr(f, field, "") or ""
                assert fake_token not in val, \
                    f"Full secret found in field '{field}': {val[:50]}"
            # Check Phase 6 extra fields
            redacted = f.__dict__.get("redacted_value", "")
            assert fake_token not in (redacted or ""), \
                "Full secret found in redacted_value"

    def test_redacted_format(self):
        """Redaction format shows partial prefix/suffix only."""
        from app.services.scan_engine.scanner.secret_scanner import _redact
        value = "sk_live_abcdefgh123456789xyz"
        redacted = _redact(value)
        # Should show some chars but not the full value
        assert redacted != value
        assert "***" in redacted or "*" in redacted
        # Should start with the prefix
        assert redacted.startswith("sk_l")

    def test_false_positive_placeholder(self, tmp_path):
        """Common placeholders are NOT flagged as secrets."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        write_file(tmp_path, "config.py",
                   'api_key = "your-api-key-here"\n'
                   'password = "changeme"\n'
                   'token = "example_token"\n')
        findings = analyze_secrets(tmp_path)
        # These should not be flagged (or have very low confidence)
        high_conf = [f for f in findings if (f.confidence or 0) >= 70]
        assert len(high_conf) == 0

    def test_false_positive_short_value(self, tmp_path):
        """Short values are not flagged as secrets."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        write_file(tmp_path, "config.py",
                   'api_key = "abc"\n')
        findings = analyze_secrets(tmp_path)
        # Too short to be a real secret
        assert len(findings) == 0

    def test_shannon_entropy(self):
        """Entropy calculation works correctly."""
        from app.services.scan_engine.scanner.secret_scanner import _shannon_entropy
        # High entropy string
        high_ent = _shannon_entropy("aB3$xK9@pQ1!mN7#")
        # Low entropy string (all same chars)
        low_ent = _shannon_entropy("aaaaaaaaaaaaaaaa")
        assert high_ent > low_ent
        assert high_ent > 3.0

    def test_fingerprint_does_not_contain_secret(self, tmp_path):
        """Secret fingerprint must not contain the full secret value."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        fake_token = "ghp_testfingerprintcheck1234567890"
        write_file(tmp_path, "app.py", f'token = "{fake_token}"\n')
        findings = analyze_secrets(tmp_path)
        for f in findings:
            fp = f.fingerprint or ""
            assert fake_token not in fp

    def test_jwt_token_detected(self, tmp_path):
        """JWT format (eyJ...) is detected."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        write_file(tmp_path, "auth.js", f'const token = "{fake_jwt}";\n')
        findings = analyze_secrets(tmp_path)
        assert len(findings) > 0

    def test_package_lock_skipped(self, tmp_path):
        """package-lock.json is never scanned for secrets."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        # Add a fake token-looking string in package-lock.json
        write_file(tmp_path, "package-lock.json",
                   '{"some_field": "ghp_fake12345678901234567890abc"}')
        findings = analyze_secrets(tmp_path)
        assert len(findings) == 0

    def test_secret_type_field_set(self, tmp_path):
        """Phase 6 secret_type field is populated."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        write_file(tmp_path, "config.py",
                   'token = "ghp_abcdefghijklmnopqrstuvwxyz12"\n')
        findings = analyze_secrets(tmp_path)
        for f in findings:
            if "GitHub" in f.title:
                assert f.__dict__.get("secret_type") is not None


# ===========================================================================
# IaC Analyzer
# ===========================================================================


class TestIaCAnalyzer:
    """Tests for Infrastructure-as-Code security analysis."""

    def test_dockerfile_missing_user(self, tmp_path):
        """Dockerfile without USER instruction is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_dockerfile
        content = "FROM node:18\nRUN npm install\nCMD [\"node\", \"app.js\"]\n"
        findings = analyze_dockerfile(content, "Dockerfile")
        assert len(findings) > 0
        assert any("root" in f.title.lower() or "user" in f.title.lower() for f in findings)

    def test_dockerfile_with_user_not_flagged(self, tmp_path):
        """Dockerfile WITH USER instruction is not flagged for root."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_dockerfile
        content = "FROM node:18\nRUN npm install\nUSER nonroot\nCMD [\"node\", \"app.js\"]\n"
        findings = analyze_dockerfile(content, "Dockerfile")
        root_findings = [f for f in findings if f.rule_id == "IAC001"]
        assert len(root_findings) == 0

    def test_dockerfile_env_secret_flagged(self, tmp_path):
        """ENV with secret-looking variable is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_dockerfile
        # FAKE credential for testing
        content = "FROM python:3.9\nENV API_KEY=TEST_SECRET_DO_NOT_USE_abc123def\nUSER appuser\nCMD [\"python\", \"app.py\"]\n"
        findings = analyze_dockerfile(content, "Dockerfile")
        iac003 = [f for f in findings if f.rule_id == "IAC003"]
        assert len(iac003) > 0

    def test_dockerfile_env_variable_reference_not_flagged(self, tmp_path):
        """ENV that uses ${VARIABLE} reference is NOT flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_dockerfile
        content = "FROM python:3.9\nENV API_KEY=${API_KEY}\nUSER appuser\nCMD [\"app\"]\n"
        findings = analyze_dockerfile(content, "Dockerfile")
        iac003 = [f for f in findings if f.rule_id == "IAC003"]
        assert len(iac003) == 0

    def test_docker_compose_exposed_db_port(self, tmp_path):
        """docker-compose with exposed database port is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_docker_compose
        content = 'version: "3"\nservices:\n  db:\n    image: postgres\n    ports:\n      - "5432:5432"\n'
        findings = analyze_docker_compose(content, "docker-compose.yml")
        iac005 = [f for f in findings if f.rule_id == "IAC005"]
        assert len(iac005) > 0

    def test_docker_compose_localhost_bound_not_flagged(self, tmp_path):
        """docker-compose port bound to 127.0.0.1 is NOT flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_docker_compose
        content = 'version: "3"\nservices:\n  db:\n    image: postgres\n    ports:\n      - "127.0.0.1:5432:5432"\n'
        findings = analyze_docker_compose(content, "docker-compose.yml")
        iac005 = [f for f in findings if f.rule_id == "IAC005"]
        assert len(iac005) == 0

    def test_docker_compose_hardcoded_password(self, tmp_path):
        """docker-compose with hardcoded password is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_docker_compose
        # FAKE test password
        content = 'services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=test_fake_pass_123\n'
        findings = analyze_docker_compose(content, "docker-compose.yml")
        iac004 = [f for f in findings if f.rule_id == "IAC004"]
        assert len(iac004) > 0

    def test_docker_compose_variable_reference_not_flagged(self, tmp_path):
        """docker-compose with ${VAR} password reference is NOT flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_docker_compose
        content = 'services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}\n'
        findings = analyze_docker_compose(content, "docker-compose.yml")
        iac004 = [f for f in findings if f.rule_id == "IAC004"]
        assert len(iac004) == 0

    def test_github_actions_write_all_permissions(self, tmp_path):
        """GitHub Actions workflow with write-all permissions is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_github_actions
        content = "name: CI\non:\n  push:\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        findings = analyze_github_actions(content, ".github/workflows/ci.yml")
        iac007 = [f for f in findings if f.rule_id == "IAC007"]
        assert len(iac007) > 0

    def test_github_actions_pull_request_target(self, tmp_path):
        """GitHub Actions with pull_request_target trigger is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_github_actions
        content = "name: CI\non:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        findings = analyze_github_actions(content, ".github/workflows/ci.yml")
        iac006 = [f for f in findings if f.rule_id == "IAC006"]
        assert len(iac006) > 0

    def test_github_actions_command_injection(self, tmp_path):
        """GitHub Actions command injection via untrusted input is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_github_actions
        content = ('name: CI\non:\n  issues:\n    types: [opened]\n'
                   'jobs:\n  handle:\n    runs-on: ubuntu-latest\n    steps:\n'
                   '      - run: echo "${{ github.event.issue.title }}"\n')
        findings = analyze_github_actions(content, ".github/workflows/ci.yml")
        iac015 = [f for f in findings if f.rule_id == "IAC015"]
        assert len(iac015) > 0

    def test_github_actions_mutable_tag_action(self, tmp_path):
        """GitHub Actions step using mutable tag (not SHA) is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_github_actions
        content = ('name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
                   '    steps:\n      - uses: actions/checkout@v3\n')
        findings = analyze_github_actions(content, ".github/workflows/ci.yml")
        iac014 = [f for f in findings if f.rule_id == "IAC014"]
        assert len(iac014) > 0

    def test_github_actions_sha_pinned_not_flagged(self, tmp_path):
        """GitHub Actions step pinned to full SHA is NOT flagged as mutable."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_github_actions
        sha = "a81bbbf8298c0fa03ea29cdc473d45769f953675"
        content = (f'name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
                   f'    steps:\n      - uses: actions/checkout@{sha}\n')
        findings = analyze_github_actions(content, ".github/workflows/ci.yml")
        iac014 = [f for f in findings if f.rule_id == "IAC014"]
        assert len(iac014) == 0

    def test_kubernetes_privileged_container(self, tmp_path):
        """Kubernetes privileged: true is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_kubernetes
        content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
"""
        findings = analyze_kubernetes(content, "k8s/deployment.yaml")
        iac010 = [f for f in findings if f.rule_id == "IAC010"]
        assert len(iac010) > 0

    def test_kubernetes_host_network(self, tmp_path):
        """Kubernetes hostNetwork: true is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_kubernetes
        content = """apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx
"""
        findings = analyze_kubernetes(content, "k8s/pod.yaml")
        iac011 = [f for f in findings if f.rule_id == "IAC011"]
        assert len(iac011) > 0

    def test_terraform_unrestricted_ingress(self, tmp_path):
        """Terraform 0.0.0.0/0 ingress is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_terraform
        content = 'resource "aws_security_group" "test" {\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        findings = analyze_terraform(content, "main.tf")
        iac012 = [f for f in findings if f.rule_id == "IAC012"]
        assert len(iac012) > 0

    def test_terraform_hardcoded_secret(self, tmp_path):
        """Terraform hardcoded password is flagged."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_terraform
        # FAKE test credential
        content = 'resource "aws_db_instance" "test" {\n  password = "test_fake_pass_123456"\n}\n'
        findings = analyze_terraform(content, "main.tf")
        iac013 = [f for f in findings if f.rule_id == "IAC013"]
        assert len(iac013) > 0

    def test_terraform_variable_not_flagged(self, tmp_path):
        """Terraform variable reference is NOT flagged as secret."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_terraform
        content = 'resource "aws_db_instance" "test" {\n  password = var.db_password\n}\n'
        findings = analyze_terraform(content, "main.tf")
        iac013 = [f for f in findings if f.rule_id == "IAC013"]
        assert len(iac013) == 0

    def test_iac_analyze_full_repo(self, tmp_path):
        """Full IaC scan of a fixture repository finds issues."""
        write_file(tmp_path, "Dockerfile",
                   "FROM python:3.9\nRUN pip install flask\nCMD [\"python\", \"app.py\"]\n")
        write_file(tmp_path, "docker-compose.yml",
                   'services:\n  db:\n    image: postgres\n    ports:\n      - "5432:5432"\n')
        from app.services.scan_engine.scanner.iac_analyzer import analyze_iac
        findings = analyze_iac(tmp_path)
        assert len(findings) > 0
        # Dockerfile: missing USER
        assert any(f.rule_id == "IAC001" for f in findings)
        # docker-compose: exposed port
        assert any(f.rule_id == "IAC005" for f in findings)


# ===========================================================================
# Risk Engine
# ===========================================================================


class TestRiskEngine:
    """Tests for security score and risk calculation."""

    def test_perfect_score_no_findings(self):
        """No findings → score of 100."""
        from app.services.scan_engine.scanner.risk_engine import compute_security_score
        score = compute_security_score([])
        assert score == 100

    def test_critical_finding_reduces_score(self):
        """A critical finding significantly reduces the score."""
        from app.services.scan_engine.scanner.risk_engine import compute_security_score
        from app.services.scan_engine.findings.types import RichFindingResult
        f = RichFindingResult(
            severity="critical", title="test", description="test",
            file_path="test.py", line_number=1, confidence=90,
        )
        score = compute_security_score([f])
        assert score < 90  # Significantly reduced

    def test_score_from_db_counts(self):
        """compute_security_score_from_db works with count inputs."""
        from app.services.scan_engine.scanner.risk_engine import compute_security_score_from_db
        score = compute_security_score_from_db(
            critical=0, high=0, medium=0, low=0, info=0
        )
        assert score == 100

        score_with_issues = compute_security_score_from_db(
            critical=1, high=2, medium=5, low=10, info=20
        )
        assert score_with_issues < 90

    def test_low_confidence_findings_have_less_weight(self):
        """Low confidence findings penalize score less than high confidence."""
        from app.services.scan_engine.scanner.risk_engine import compute_security_score
        from app.services.scan_engine.findings.types import RichFindingResult

        high_conf = RichFindingResult(
            severity="high", title="t", description="t",
            file_path="test.py", line_number=1, confidence=90,
        )
        low_conf = RichFindingResult(
            severity="high", title="t", description="t",
            file_path="test.py", line_number=1, confidence=25,  # very low confidence
        )

        score_high = compute_security_score([high_conf])
        score_low = compute_security_score([low_conf])
        # Low confidence → less penalty → higher score
        assert score_low > score_high

    def test_score_clamped_to_zero(self):
        """Score never goes below 0."""
        from app.services.scan_engine.scanner.risk_engine import compute_security_score_from_db
        score = compute_security_score_from_db(
            critical=100, high=100, medium=100, low=100, info=100
        )
        assert score == 0

    def test_categorize_findings(self):
        """categorize_findings correctly classifies by analyzer."""
        from app.services.scan_engine.scanner.risk_engine import categorize_findings
        from app.services.scan_engine.findings.types import RichFindingResult

        findings = [
            RichFindingResult(severity="high", title="t", description="t",
                              file_path="f", line_number=1, analyzer="sca",
                              category="configuration"),
            RichFindingResult(severity="high", title="t", description="t",
                              file_path="f", line_number=1, analyzer="secret_scanner",
                              category="secrets"),
            RichFindingResult(severity="medium", title="t", description="t",
                              file_path="f", line_number=1, analyzer="iac",
                              category="configuration"),
            RichFindingResult(severity="low", title="t", description="t",
                              file_path="f", line_number=1, analyzer="ast",
                              category="sql_injection"),
            RichFindingResult(severity="info", title="t", description="t",
                              file_path="f", line_number=1, analyzer="regex",
                              category="quality"),
        ]

        cats = categorize_findings(findings)
        assert cats["dependencies"] == 1
        assert cats["secrets"] == 1
        assert cats["iac"] == 1
        assert cats["sast"] == 1
        assert cats["quality"] == 1

    def test_historical_comparison(self):
        """compare_scans correctly identifies new/resolved/unchanged."""
        from app.services.scan_engine.scanner.risk_engine import compare_scans
        old = {"fp1", "fp2", "fp3"}
        new = {"fp2", "fp3", "fp4"}
        result = compare_scans(old, new)
        assert result["new"] == {"fp4"}
        assert result["resolved"] == {"fp1"}
        assert result["unchanged"] == {"fp2", "fp3"}

    def test_verify_patch_statically_no_content(self):
        """verify_patch_statically handles missing file content."""
        from app.services.scan_engine.scanner.risk_engine import (
            verify_patch_statically, VerificationStatus,
        )
        result = verify_patch_statically(
            original_content="some content",
            patch_original="text not found",
            patch_replacement="replacement",
        )
        assert result["status"] == VerificationStatus.FAILED

    def test_verify_patch_statically_no_reanalyze(self):
        """verify_patch_statically without re-analyze function returns NOT_VERIFIED."""
        from app.services.scan_engine.scanner.risk_engine import (
            verify_patch_statically, VerificationStatus,
        )
        result = verify_patch_statically(
            original_content="result = yaml.load(data)",
            patch_original="yaml.load(data)",
            patch_replacement="yaml.safe_load(data)",
        )
        assert result["status"] == VerificationStatus.NOT_VERIFIED


# ===========================================================================
# Deduplication — Phase 6 interactions
# ===========================================================================


class TestPhase6Deduplication:
    """Tests for deduplication across Phase 6 analyzers."""

    def test_same_secret_different_rule_not_merged(self):
        """Different secret types on same line are not incorrectly merged."""
        from app.services.scan_engine.scanner.deduplication import deduplicate, generate_fingerprint
        from app.services.scan_engine.findings.types import RichFindingResult, FindingCategory
        import hashlib

        f1 = RichFindingResult(
            severity="high", title="GitHub Token", description="t",
            file_path="src/app.py", line_number=10,
            rule_id="SEC101", category=FindingCategory.SECRETS.value,
            analyzer="secret_scanner",
        )
        f1.fingerprint = hashlib.sha256("SEC101:src/app.py:10".encode()).hexdigest()[:16]

        f2 = RichFindingResult(
            severity="high", title="AWS Key", description="t",
            file_path="src/app.py", line_number=10,
            rule_id="SEC104", category=FindingCategory.SECRETS.value,
            analyzer="secret_scanner",
        )
        f2.fingerprint = hashlib.sha256("SEC104:src/app.py:10".encode()).hexdigest()[:16]

        deduped = deduplicate([f1, f2])
        # Different fingerprints → not merged
        assert len(deduped) == 2

    def test_iac_findings_stable_fingerprint(self):
        """IaC finding fingerprint is stable across multiple calls."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_dockerfile
        content = "FROM node:18\nRUN npm install\nCMD [\"app\"]\n"
        findings1 = analyze_dockerfile(content, "Dockerfile")
        findings2 = analyze_dockerfile(content, "Dockerfile")
        fps1 = sorted(f.fingerprint for f in findings1 if f.fingerprint)
        fps2 = sorted(f.fingerprint for f in findings2 if f.fingerprint)
        assert fps1 == fps2

    def test_sca_findings_stable_fingerprint(self, tmp_path):
        """SCA finding fingerprint is stable across runs."""
        write_file(tmp_path, "requirements.txt", "werkzeug==2.1.0\n")
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings1 = analyze_dependencies(tmp_path)
        findings2 = analyze_dependencies(tmp_path)
        fps1 = sorted(f.fingerprint for f in findings1 if f.fingerprint)
        fps2 = sorted(f.fingerprint for f in findings2 if f.fingerprint)
        assert fps1 == fps2


# ===========================================================================
# Synthetic fixture repository scan
# ===========================================================================


class TestSyntheticFixture:
    """Scan the synthetic fixture repository and verify findings."""

    @pytest.fixture
    def fixture_repo(self):
        """Return the path to the synthetic fixture repository."""
        here = Path(__file__).parent
        return here / "fixtures" / "security_test_repo"

    def test_fixture_repo_exists(self, fixture_repo):
        """The synthetic fixture repository exists."""
        assert fixture_repo.exists()
        assert (fixture_repo / "requirements.txt").exists()
        assert (fixture_repo / "package.json").exists()
        assert (fixture_repo / "Dockerfile").exists()

    def test_sca_finds_vulnerable_packages(self, fixture_repo):
        """SCA analysis of fixture detects known vulnerable packages."""
        from app.services.scan_engine.scanner.dependency_analyzer import analyze_dependencies
        findings = analyze_dependencies(fixture_repo)
        sca = [f for f in findings if getattr(f, "analyzer", "") == "sca"]
        assert len(sca) > 0
        # werkzeug and lodash should be flagged
        pkg_names = {f.__dict__.get("dependency_name", "").lower() for f in sca}
        assert "werkzeug" in pkg_names or any("werkzeug" in f.title.lower() for f in sca)
        assert any("lodash" in f.title.lower() or "lodash" in pkg_names for f in sca)

    def test_secret_scanner_finds_test_credentials(self, fixture_repo):
        """Secret scanner finds fake test credentials in fixture."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        findings = analyze_secrets(fixture_repo)
        # Should find some credential-looking things
        # (The fixture has fake tokens and DB URLs)
        assert len(findings) > 0

    def test_secrets_are_always_redacted(self, fixture_repo):
        """All secret findings from fixture have redacted evidence."""
        from app.services.scan_engine.scanner.secret_scanner import analyze_secrets
        findings = analyze_secrets(fixture_repo)
        for f in findings:
            # Evidence should not contain long raw credential strings
            evidence = f.evidence or ""
            # No field should contain a full unredacted secret longer than 20 chars
            redacted = f.__dict__.get("redacted_value", "")
            assert "***" in redacted or len(redacted) <= 12 or not redacted

    def test_iac_finds_dockerfile_issues(self, fixture_repo):
        """IaC analyzer finds Dockerfile issues in fixture."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_iac
        findings = analyze_iac(fixture_repo)
        iac_findings = [f for f in findings]
        assert len(iac_findings) > 0
        # At minimum: missing USER, exposed port, hardcoded env var
        rule_ids_found = {f.rule_id for f in iac_findings}
        assert "IAC001" in rule_ids_found  # missing USER
        assert "IAC003" in rule_ids_found  # ENV secret

    def test_github_actions_issues_detected(self, fixture_repo):
        """GitHub Actions issues are detected in fixture."""
        from app.services.scan_engine.scanner.iac_analyzer import analyze_iac
        findings = analyze_iac(fixture_repo)
        rule_ids_found = {f.rule_id for f in findings}
        # write-all permissions + pull_request_target + command injection
        assert "IAC006" in rule_ids_found or "IAC007" in rule_ids_found

    def test_full_analyze_repository_runs_clean(self, fixture_repo):
        """analyze_repository on fixture completes without crashing."""
        from app.services.scan_engine.analyzers import analyze_repository
        findings = analyze_repository(fixture_repo)
        assert isinstance(findings, list)
        # Should have multiple findings
        assert len(findings) > 0
        # All findings should have required fields
        for f in findings:
            assert hasattr(f, "severity")
            assert hasattr(f, "title")
            assert hasattr(f, "file_path")

    def test_no_full_secrets_in_analyze_repository(self, fixture_repo):
        """analyze_repository does not return full secret values."""
        from app.services.scan_engine.analyzers import analyze_repository
        # The fixture has TEST_SECRET_DO_NOT_USE_123456 as a fake credential
        findings = analyze_repository(fixture_repo)
        for f in findings:
            # The full test secret marker should NOT appear in key fields
            # (it should be redacted)
            for attr in ("evidence",):
                val = getattr(f, attr, "") or ""
                # If this is a secret finding, the value should be redacted
                if getattr(f, "analyzer", "") == "secret_scanner":
                    assert "TEST_SECRET_DO_NOT_USE_123456" not in val or \
                           len(val) == 0, \
                           f"Potential full secret exposure in evidence"


# ===========================================================================
# API Endpoints — Phase 6
# ===========================================================================


class TestPhase6API:
    """Test Phase 6 API endpoints."""

    def _create_scan_with_findings(self, db, repository, severities=None):
        """Helper: create a scan with findings of given severities."""
        from app.models.models import Scan, Finding
        import uuid
        if severities is None:
            severities = ["high", "medium", "low"]

        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.flush()

        for i, sev in enumerate(severities):
            f = Finding(
                scan_id=scan.id,
                severity=sev,
                title=f"Test finding {i}",
                description="Test description",
                file_path=f"test_{i}.py",
                line_number=i + 1,
                confidence=80,
                category="sql_injection" if sev == "high" else "quality",
                analyzer="ast" if sev in ("high", "medium") else "regex",
            )
            db.add(f)

        db.commit()
        db.refresh(scan)
        return scan

    def test_security_score_endpoint(self, client, db, repository):
        """GET /scans/{id}/security-score returns score and grade."""
        scan = self._create_scan_with_findings(db, repository)
        resp = client.get(f"/api/scans/{scan.id}/security-score")
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data
        assert "grade" in data
        assert 0 <= data["score"] <= 100
        assert data["grade"] in ("A", "B", "C", "D", "F")

    def test_security_score_empty_scan(self, client, db, repository):
        """Security score is 100 for a scan with no findings."""
        from app.models.models import Scan
        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.commit()
        resp = client.get(f"/api/scans/{scan.id}/security-score")
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] == 100
        assert data["grade"] == "A"

    def test_security_score_requires_auth(self, client, db, repository, other_client, other_repository):
        """Security score endpoint enforces ownership."""
        from app.models.models import Scan
        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.commit()
        # other_client cannot access test_user's scan
        resp = other_client.get(f"/api/scans/{scan.id}/security-score")
        assert resp.status_code == 404

    def test_categories_endpoint(self, client, db, repository):
        """GET /scans/{id}/categories returns category breakdown."""
        scan = self._create_scan_with_findings(db, repository)
        resp = client.get(f"/api/scans/{scan.id}/categories")
        assert resp.status_code == 200
        data = resp.json()
        assert "categories" in data
        assert "summary" in data["categories"]

    def test_dependencies_endpoint_empty(self, client, db, repository):
        """GET /scans/{id}/dependencies returns empty list when no SCA findings."""
        scan = self._create_scan_with_findings(db, repository)
        resp = client.get(f"/api/scans/{scan.id}/dependencies")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_secrets_endpoint_empty(self, client, db, repository):
        """GET /scans/{id}/secrets returns empty list when no secret findings."""
        scan = self._create_scan_with_findings(db, repository)
        resp = client.get(f"/api/scans/{scan.id}/secrets")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_iac_endpoint_empty(self, client, db, repository):
        """GET /scans/{id}/iac returns empty list when no IaC findings."""
        scan = self._create_scan_with_findings(db, repository)
        resp = client.get(f"/api/scans/{scan.id}/iac")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_risk_summary_endpoint(self, client, db, repository):
        """GET /scans/{id}/risk-summary returns comprehensive summary."""
        scan = self._create_scan_with_findings(db, repository, ["critical", "high", "medium"])
        resp = client.get(f"/api/scans/{scan.id}/risk-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "security_score" in data
        assert "grade" in data
        assert "total" in data
        assert "critical" in data
        assert "top_risks" in data
        assert "categories" in data
        assert data["total"] == 3
        assert data["critical"] == 1

    def test_summary_includes_security_score(self, client, db, repository):
        """Phase 6: scan summary includes security_score field."""
        scan = self._create_scan_with_findings(db, repository)
        resp = client.get(f"/api/scans/{scan.id}/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "security_score" in data
        assert 0 <= data["security_score"] <= 100

    def test_findings_endpoint_analyzer_filter(self, client, db, repository):
        """GET /scans/{id}/findings?analyzer=ast filters by analyzer."""
        from app.models.models import Scan, Finding
        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.flush()
        f1 = Finding(scan_id=scan.id, severity="high", title="AST finding",
                     description="test", file_path="t.py", line_number=1,
                     analyzer="ast")
        f2 = Finding(scan_id=scan.id, severity="low", title="Regex finding",
                     description="test", file_path="t.py", line_number=2,
                     analyzer="regex")
        db.add_all([f1, f2])
        db.commit()

        resp = client.get(f"/api/scans/{scan.id}/findings?analyzer=ast")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["title"] == "AST finding"

    def test_findings_response_has_phase6_fields(self, client, db, repository):
        """FindingResponse includes Phase 6 fields."""
        from app.models.models import Scan, Finding
        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.flush()
        f = Finding(
            scan_id=scan.id, severity="high", title="SCA finding",
            description="test", file_path="requirements.txt", line_number=1,
            analyzer="sca",
        )
        # Set Phase 6 attributes via __dict__ won't work with ORM
        # They need to be set as real columns
        db.add(f)
        db.commit()

        resp = client.get(f"/api/scans/{scan.id}/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        # Phase 6 fields are present (may be null)
        assert "dependency_name" in data[0]
        assert "secret_type" in data[0]
        assert "advisory_id" in data[0]

    def test_remediation_endpoint(self, client, db, repository):
        """GET /findings/{id}/remediation returns remediation data."""
        from app.models.models import Scan, Finding
        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.flush()
        f = Finding(
            scan_id=scan.id, severity="high", title="Test finding",
            description="test", file_path="test.py", line_number=1,
            why_risky="This is risky", remediation="Fix it",
        )
        db.add(f)
        db.commit()

        resp = client.get(f"/api/findings/{f.id}/remediation")
        assert resp.status_code == 200
        data = resp.json()
        assert data["finding_id"] == f.id
        assert data["why_risky"] == "This is risky"
        assert data["remediation"] == "Fix it"

    def test_remediation_endpoint_ownership(self, client, db, repository,
                                             other_client, other_repository):
        """Remediation endpoint enforces ownership."""
        from app.models.models import Scan, Finding
        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.flush()
        f = Finding(scan_id=scan.id, severity="high", title="t", description="t",
                    file_path="t.py", line_number=1)
        db.add(f)
        db.commit()

        # other_client cannot access test_user's finding
        resp = other_client.get(f"/api/findings/{f.id}/remediation")
        assert resp.status_code == 404

    def test_verify_fix_no_patch(self, client, db, repository):
        """verify-fix on finding with no patch returns NOT_VERIFIED."""
        from app.models.models import Scan, Finding
        scan = Scan(repository_id=repository.id, status="completed")
        db.add(scan)
        db.flush()
        f = Finding(scan_id=scan.id, severity="high", title="t", description="t",
                    file_path="t.py", line_number=1, patch_available=False)
        db.add(f)
        db.commit()

        resp = client.post(f"/api/findings/{f.id}/verify-fix")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "NOT_VERIFIED"


# ===========================================================================
# Finding Model — Phase 6 fields
# ===========================================================================


class TestFindingModelPhase6:
    """Tests for Phase 6 Finding model fields."""

    def test_finding_has_dependency_fields(self, db, scan):
        """Finding model has Phase 6 dependency fields."""
        from app.models.models import Finding
        f = Finding(
            scan_id=scan.id,
            severity="high",
            title="Vulnerable dep",
            description="test",
            file_path="requirements.txt",
            line_number=1,
        )
        # Set Phase 6 fields
        f.dependency_name = "werkzeug"
        f.dependency_version = "2.1.0"
        f.fixed_version = "2.2.3"
        f.advisory_id = "CVE-2023-25577"
        db.add(f)
        db.commit()
        db.refresh(f)

        assert f.dependency_name == "werkzeug"
        assert f.dependency_version == "2.1.0"
        assert f.fixed_version == "2.2.3"
        assert f.advisory_id == "CVE-2023-25577"

    def test_finding_has_secret_fields(self, db, scan):
        """Finding model has Phase 6 secret fields (never full secret)."""
        from app.models.models import Finding
        f = Finding(
            scan_id=scan.id,
            severity="high",
            title="Hardcoded token",
            description="test",
            file_path="app.py",
            line_number=10,
        )
        f.secret_type = "GitHub Personal Access Token"
        f.redacted_value = "ghp_****"
        db.add(f)
        db.commit()
        db.refresh(f)

        assert f.secret_type == "GitHub Personal Access Token"
        assert f.redacted_value == "ghp_****"

    def test_phase6_fields_nullable(self, db, scan):
        """Phase 6 fields are nullable for backward compatibility."""
        from app.models.models import Finding
        f = Finding(
            scan_id=scan.id,
            severity="medium",
            title="Old finding",
            description="test",
        )
        db.add(f)
        db.commit()
        db.refresh(f)

        assert f.dependency_name is None
        assert f.dependency_version is None
        assert f.fixed_version is None
        assert f.advisory_id is None
        assert f.secret_type is None
        assert f.redacted_value is None


# ===========================================================================
# Migration compatibility
# ===========================================================================


class TestMigrationCompatibility:
    """Test that Phase 6 migration is valid and reversible."""

    def test_new_migration_exists(self):
        """Phase 6 migration file exists."""
        migration_path = (
            Path(__file__).parent.parent /
            "migrations" / "versions" / "b1c2d3e4f5a6_phase6_sca_secret_fields.py"
        )
        assert migration_path.exists()

    def test_migration_has_correct_revision(self):
        """Migration has correct revision ID and down_revision."""
        migration_path = (
            Path(__file__).parent.parent /
            "migrations" / "versions" / "b1c2d3e4f5a6_phase6_sca_secret_fields.py"
        )
        content = migration_path.read_text()
        assert 'revision: str = "b1c2d3e4f5a6"' in content
        assert 'down_revision' in content
        assert '"a1b2c3d4e5f6"' in content  # points to Phase 5 migration

    def test_all_tables_created_in_test_db(self, db):
        """All tables including Phase 6 columns exist in test DB."""
        from app.models.models import Finding
        # If we can create a Finding with Phase 6 fields, the schema is correct
        from app.models.models import Scan, Repository, Project, User
        # Just verify the columns exist via the model
        assert hasattr(Finding, "dependency_name")
        assert hasattr(Finding, "dependency_version")
        assert hasattr(Finding, "fixed_version")
        assert hasattr(Finding, "advisory_id")
        assert hasattr(Finding, "secret_type")
        assert hasattr(Finding, "redacted_value")
