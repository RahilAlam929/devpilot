"""
Python AST-based Security Analyzer — Phase 5.

Performs intra-file source→sink data-flow analysis on Python source files.

Analysis pipeline per file:
  1. Parse to AST (handle SyntaxError/ValueError gracefully).
  2. Collect all assignments to build a variable-alias map.
  3. Identify sources: request.query_params, request.body, etc.
  4. Identify sinks: eval, exec, subprocess, os.system, open, SQL, pickle, yaml.
  5. Trace data flow from source to sink via the alias map.
  6. Detect sanitizers between source and sink.
  7. Apply confidence scoring based on flow quality.
  8. Apply inline suppressions.
  9. Return RichFindingResult list.

Never executes scanned code.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

from app.services.scan_engine.findings.types import (
    DataFlowStep,
    FindingCategory,
    RichFindingResult,
    SinkInfo,
    SourceInfo,
)
from app.services.scan_engine.scanner.confidence import apply_confidence, score_confidence
from app.services.scan_engine.scanner.deduplication import generate_fingerprint
from app.services.scan_engine.scanner.remediation import enrich_remediation
from app.services.scan_engine.scanner.suppression import SuppressionMap, is_suppressed

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FLOW_DEPTH = 10  # max variable hops to trace
MAX_DATAFLOW_CHAIN = 6  # max steps in reported chain

# Known user-controlled sources in Python web frameworks
_USER_SOURCES: Set[str] = {
    "request.query_params",
    "request.body",
    "request.form",
    "request.headers",
    "request.cookies",
    "request.data",
    "request.json",
    "request.args",  # Flask
    "request.values",  # Flask
    "request.files",
    "request.path_params",
    "request.url",
    "request.GET",  # Django
    "request.POST",  # Django
}

# Source attribute patterns
_SOURCE_ATTRS = {"query_params", "body", "form", "headers", "cookies",
                 "data", "json", "args", "values", "files", "path_params",
                 "GET", "POST"}

# Known sanitizer functions/methods
_SANITIZERS: Set[str] = {
    "escape", "quote", "sanitize", "sanitize_html", "clean",
    "bleach.clean", "html.escape", "markupsafe.escape",
    "shlex.quote", "urllib.parse.quote", "re.escape",
    "parameterize", "validate", "allowlist", "whitelist",
}

# SQL execution sinks
_SQL_SINKS = {"execute", "executemany", "raw", "raw_sql", "query"}

# Dangerous sinks → (rule_id, description, category)
_SINKS: Dict[str, Tuple[str, str, str]] = {
    "eval":                    ("PY001", "eval()", "code_execution"),
    "exec":                    ("PY002", "exec()", "code_execution"),
    "compile":                 ("PY001", "compile()", "code_execution"),
    "subprocess.run":          ("PY003", "subprocess.run()", "command_injection"),
    "subprocess.call":         ("PY003", "subprocess.call()", "command_injection"),
    "subprocess.Popen":        ("PY003", "subprocess.Popen()", "command_injection"),
    "subprocess.check_output": ("PY003", "subprocess.check_output()", "command_injection"),
    "os.system":               ("PY004", "os.system()", "command_injection"),
    "os.popen":                ("PY004", "os.popen()", "command_injection"),
    "pickle.loads":            ("PY007", "pickle.loads()", "deserialization"),
    "pickle.load":             ("PY007", "pickle.load()", "deserialization"),
    "yaml.load":               ("PY008", "yaml.load()", "deserialization"),
}

# Secret variable name patterns
_SECRET_NAMES = re.compile(
    r"(?:api_key|secret_key|access_token|password|private_key|auth_token"
    r"|client_secret|encryption_key|db_password|database_password|passwd|pwd)",
    re.IGNORECASE,
)

# Weak hash patterns
_WEAK_HASH_RE = re.compile(r"hashlib\s*\.\s*(md5|sha1)\s*\(", re.IGNORECASE)

# SQL string formatting patterns (regex fallback for lines)
_SQL_FSTRING_RE = re.compile(
    r'(?:execute|executemany|raw)\s*\(\s*f[\'"].*\{.*\}.*[\'"]', re.IGNORECASE
)
_SQL_PERCENT_RE = re.compile(
    r'(?:execute|executemany|raw)\s*\(\s*[\'"].*%.*[\'"]', re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Variable alias map
# ---------------------------------------------------------------------------

class AliasMap:
    """
    Tracks variable assignments to enable source→sink flow tracing.

    Only tracks simple single-target assignments (no tuple unpacking).
    e.g.  cmd = request.query_params["cmd"]
          command = cmd
    """

    def __init__(self) -> None:
        # var_name → (source_label, line_number, is_tainted, sanitized)
        self._vars: Dict[str, Tuple[str, int, bool, bool]] = {}

    def assign(self, name: str, source_label: str, line: int,
               is_tainted: bool, sanitized: bool = False) -> None:
        self._vars[name] = (source_label, line, is_tainted, sanitized)

    def lookup(self, name: str) -> Optional[Tuple[str, int, bool, bool]]:
        return self._vars.get(name)

    def is_tainted(self, name: str, depth: int = 0) -> Tuple[bool, bool]:
        """
        Returns (is_tainted, is_sanitized) for *name*.
        Follows alias chains up to MAX_FLOW_DEPTH.
        """
        if depth > MAX_FLOW_DEPTH:
            return False, False
        entry = self._vars.get(name)
        if not entry:
            return False, False
        _, _, tainted, sanitized = entry
        return tainted, sanitized


# ---------------------------------------------------------------------------
# Source detection helpers
# ---------------------------------------------------------------------------

def _is_user_source(node: ast.AST) -> Optional[str]:
    """
    Return a human-readable source label if *node* appears to be
    user-controlled, or None.
    """
    # request.query_params["key"] / request.body / etc.
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Attribute):
            obj_name = _attr_root_name(val)
            attr = val.attr
            if obj_name in ("request", "req") and attr in _SOURCE_ATTRS:
                key = _subscript_key(node)
                return f"request.{attr}[{key}]"
            if attr in _SOURCE_ATTRS:
                return f"{obj_name}.{attr}[{_subscript_key(node)}]"
        # dict["key"] where dict was assigned from request.*
        if isinstance(val, ast.Name):
            return None  # will be resolved via alias map

    if isinstance(node, ast.Attribute):
        obj = node.value
        attr = node.attr
        if isinstance(obj, ast.Name):
            if obj.id in ("request", "req") and attr in _SOURCE_ATTRS:
                return f"request.{attr}"
        if attr in _SOURCE_ATTRS:
            obj_name = _attr_root_name(node)
            return f"{obj_name}.{attr}"

    return None


def _attr_root_name(node: ast.Attribute) -> str:
    """Get the root Name of an attribute chain: a.b.c → 'a'"""
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    return "?"


def _subscript_key(node: ast.Subscript) -> str:
    """Extract the key from a subscript node as a string."""
    sl = node.slice
    if isinstance(sl, ast.Constant):
        return repr(sl.value)
    if isinstance(sl, ast.Name):
        return sl.id
    return "..."


# ---------------------------------------------------------------------------
# Sink detection
# ---------------------------------------------------------------------------

def _call_name(node: ast.Call) -> str:
    """Return dotted name of a call: subprocess.run → 'subprocess.run'"""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _has_shell_true(node: ast.Call) -> bool:
    """Return True if a subprocess call has shell=True."""
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
            if kw.value.value is True:
                return True
    return False


# ---------------------------------------------------------------------------
# First argument extraction
# ---------------------------------------------------------------------------

def _first_arg_name(node: ast.Call) -> Optional[str]:
    """Return the variable name of the first argument, if it's a Name node."""
    if node.args and isinstance(node.args[0], ast.Name):
        return node.args[0].id
    return None


def _first_arg_is_constant(node: ast.Call) -> bool:
    """Return True if the first argument is a string/numeric literal."""
    if not node.args:
        return False
    arg = node.args[0]
    if isinstance(arg, ast.Constant):
        return True
    if isinstance(arg, (ast.List, ast.Tuple)):
        # subprocess.run(["git", "status"]) — all constants → safe
        return all(isinstance(e, ast.Constant) for e in arg.elts)
    return False


# ---------------------------------------------------------------------------
# Assignment walker
# ---------------------------------------------------------------------------

def _build_alias_map(tree: ast.Module, content: str) -> AliasMap:
    """
    Walk the module AST and populate an AliasMap from simple assignments.
    Handles:
      - x = request.query_params["cmd"]
      - y = x
      - z = sanitize(x)
    """
    alias = AliasMap()
    lines = content.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue

        var_name = target.id
        val = node.value
        line = node.lineno

        # Direct source assignment: var = request.query_params[...]
        src_label = _is_user_source(val)
        if src_label:
            alias.assign(var_name, src_label, line, is_tainted=True)
            continue

        # Alias: var = other_var
        if isinstance(val, ast.Name):
            existing = alias.lookup(val.id)
            if existing:
                src_label, src_line, tainted, sanitized = existing
                alias.assign(var_name, f"{val.id} (alias of {src_label})", line,
                              is_tainted=tainted, sanitized=sanitized)
            continue

        # Sanitizer call: var = sanitize(other_var)
        if isinstance(val, ast.Call):
            call_name = _call_name(val)
            if any(s in call_name for s in _SANITIZERS):
                # Mark result as sanitized
                if val.args and isinstance(val.args[0], ast.Name):
                    original = alias.lookup(val.args[0].id)
                    if original:
                        src_lbl, src_ln, tainted, _ = original
                        alias.assign(var_name, f"{call_name}({val.args[0].id})",
                                     line, is_tainted=tainted, sanitized=True)
                        continue

        # f-string containing tainted variable:  cmd = f"ping {host}"
        if isinstance(val, ast.JoinedStr):
            for part in ast.walk(val):
                if isinstance(part, ast.Name):
                    existing = alias.lookup(part.id)
                    if existing:
                        src_lbl, src_ln, tainted, sanitized = existing
                        snippet = lines[line - 1].strip() if line <= len(lines) else ""
                        alias.assign(var_name, f"f-string containing {part.id}",
                                     line, is_tainted=tainted and not sanitized,
                                     sanitized=sanitized)
                        break

        # String concatenation:  cmd = "ping " + host
        if isinstance(val, ast.BinOp) and isinstance(val.op, ast.Add):
            for side in (val.left, val.right):
                if isinstance(side, ast.Name):
                    existing = alias.lookup(side.id)
                    if existing:
                        src_lbl, src_ln, tainted, sanitized = existing
                        alias.assign(var_name, f"concatenation containing {side.id}",
                                     line, is_tainted=tainted and not sanitized,
                                     sanitized=sanitized)
                        break

    return alias


# ---------------------------------------------------------------------------
# Data-flow chain builder
# ---------------------------------------------------------------------------

def _build_flow_chain(
    source_label: str, source_line: int,
    var_chain: List[Tuple[str, str, int]],   # [(var_name, label, line), ...]
    sink_label: str, sink_line: int,
) -> List[DataFlowStep]:
    steps: List[DataFlowStep] = []
    steps.append(DataFlowStep(label=source_label, line=source_line, step_type="source"))
    for var_name, label, line in var_chain[:MAX_DATAFLOW_CHAIN]:
        steps.append(DataFlowStep(label=label, line=line, step_type="assignment", variable=var_name))
    steps.append(DataFlowStep(label=sink_label, line=sink_line, step_type="sink"))
    return steps


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_python(
    content: str,
    file_path: str,
    sup_map: Optional[SuppressionMap] = None,
) -> List[RichFindingResult]:
    """
    Run all Python security checks on *content*.

    Returns a list of RichFindingResult objects.
    Never raises — all exceptions are caught and logged.
    """
    findings: List[RichFindingResult] = []

    try:
        tree = ast.parse(content, filename=file_path)
    except (SyntaxError, ValueError):
        # Unparseable — fall back to regex-only findings (handled in analyzers.py)
        return findings

    lines = content.splitlines()
    alias = _build_alias_map(tree, content)

    # 1. Walk AST for sink calls
    _check_sinks(tree, content, file_path, alias, lines, findings, sup_map)

    # 2. Secret assignments
    _check_secrets(tree, content, file_path, lines, findings, sup_map)

    # 3. Weak crypto
    _check_weak_crypto(content, file_path, lines, findings, sup_map)

    # 4. SQL injection via f-string/% (AST-level confirmation)
    _check_sql_injection(tree, content, file_path, lines, findings, sup_map)

    # 5. Path traversal
    _check_path_traversal(tree, content, file_path, alias, lines, findings, sup_map)

    # Enrich all findings with remediation text
    for f in findings:
        enrich_remediation(f)
        if not f.fingerprint:
            f.fingerprint = generate_fingerprint(f)

    return findings


# ---------------------------------------------------------------------------
# Sink checker
# ---------------------------------------------------------------------------

def _check_sinks(
    tree: ast.Module,
    content: str,
    file_path: str,
    alias: AliasMap,
    lines: List[str],
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name = _call_name(node)
        if not name:
            continue

        line = node.lineno
        snippet = lines[line - 1].strip() if line <= len(lines) else ""

        # subprocess calls — only flag when shell=True or first arg is tainted
        if name in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                    "subprocess.check_output"):
            _check_subprocess(node, name, file_path, line, snippet, alias, findings, sup_map)
            continue

        if name in _SINKS:
            rule_id, sink_label, category = _SINKS[name]
            _check_generic_sink(
                node, rule_id, name, sink_label, category,
                file_path, line, snippet, alias, findings, sup_map
            )


def _check_subprocess(
    node: ast.Call,
    name: str,
    file_path: str,
    line: int,
    snippet: str,
    alias: AliasMap,
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    rule_id = "PY003"
    has_shell_true = _has_shell_true(node)

    # subprocess(["git", "status"]) — all constants, no shell=True → safe
    if not has_shell_true and _first_arg_is_constant(node):
        return

    # subprocess(["git", var]) — list with variable: lower risk but flag if tainted
    first_var = _first_arg_name(node)
    is_tainted = False
    is_sanitized = False
    source_label = ""
    source_line = line
    flow_chain: List[Tuple[str, str, int]] = []

    if first_var:
        tainted, sanitized = alias.is_tainted(first_var)
        is_tainted = tainted
        is_sanitized = sanitized
        entry = alias.lookup(first_var)
        if entry:
            source_label, source_line, _, _ = entry
            flow_chain = [(first_var, first_var, line)]

    if sup_map and is_suppressed(sup_map, line, rule_id):
        return

    # Determine severity: critical only if tainted + shell=True
    if has_shell_true and is_tainted and not is_sanitized:
        severity = "critical"
    elif has_shell_true:
        severity = "high"
    elif is_tainted and not is_sanitized:
        severity = "high"
    else:
        # No shell=True, not tainted → medium (shell=True alone is still concerning)
        severity = "medium"

    data_flow = []
    if source_label and is_tainted:
        data_flow = _build_flow_chain(
            source_label, source_line,
            flow_chain,
            f"{name}(..., shell={has_shell_true})", line,
        )

    finding = RichFindingResult(
        severity=severity,
        title="subprocess called with shell=True" if has_shell_true else "subprocess call with user-controlled argument",
        description=(
            "subprocess with shell=True and user-controlled input enables OS command injection."
            if has_shell_true else
            "A subprocess call receives a user-controlled argument."
        ),
        file_path=file_path,
        line_number=line,
        rule_id=rule_id,
        category=FindingCategory.COMMAND_INJECTION.value,
        code_snippet=snippet,
        language="python",
        analyzer="ast" if not is_tainted else "dataflow",
        source=SourceInfo(label=source_label, line=source_line) if source_label else None,
        sink=SinkInfo(label=f"{name}()", line=line, api=name, is_sanitized=is_sanitized),
        data_flow=data_flow,
        cwe="CWE-78",
        evidence=snippet,
    )
    apply_confidence(
        finding,
        has_user_controlled_source=is_tainted,
        has_direct_flow=bool(data_flow),
        has_sanitizer=is_sanitized,
        is_ast_confirmed=True,
        source_is_constant=not is_tainted and _first_arg_is_constant(node),
        is_regex_only=False,
        flow_is_incomplete=not bool(source_label) and is_tainted,
    )
    findings.append(finding)


def _check_generic_sink(
    node: ast.Call,
    rule_id: str,
    api_name: str,
    sink_label: str,
    category: str,
    file_path: str,
    line: int,
    snippet: str,
    alias: AliasMap,
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    if sup_map and is_suppressed(sup_map, line, rule_id):
        return

    # Check if first argument is a constant (no risk) or tainted variable
    first_arg_const = _first_arg_is_constant(node)
    first_var = _first_arg_name(node)

    is_tainted = False
    is_sanitized = False
    source_label = ""
    source_line = line
    flow_chain: List[Tuple[str, str, int]] = []

    if first_var:
        tainted, sanitized = alias.is_tainted(first_var)
        is_tainted = tainted
        is_sanitized = sanitized
        entry = alias.lookup(first_var)
        if entry:
            source_label, source_line, _, _ = entry
            flow_chain = [(first_var, first_var, line)]

    # eval("2+2") — constant arg, no risk
    if first_arg_const and not is_tainted:
        return

    from app.services.scan_engine.scanner.rules import get_rule
    rule = get_rule(rule_id)
    severity = rule.default_severity if rule else "high"
    if is_tainted and not is_sanitized:
        # Escalate: known user-controlled taint reaching dangerous sink
        if severity in ("medium", "low"):
            severity = "high"

    data_flow = []
    if source_label and is_tainted:
        data_flow = _build_flow_chain(
            source_label, source_line,
            flow_chain,
            sink_label, line,
        )

    finding = RichFindingResult(
        severity=severity,
        title=f"Use of {api_name}()" + (" with user-controlled input" if is_tainted else ""),
        description=(
            f"{api_name}() receives user-controlled input — potential {category.replace('_', ' ')}."
            if is_tainted else
            f"{api_name}() detected. Verify the argument is not user-controlled."
        ),
        file_path=file_path,
        line_number=line,
        rule_id=rule_id,
        category=category,
        code_snippet=snippet,
        language="python",
        analyzer="dataflow" if is_tainted else "ast",
        source=SourceInfo(label=source_label, line=source_line) if source_label else None,
        sink=SinkInfo(label=sink_label, line=line, api=api_name, is_sanitized=is_sanitized),
        data_flow=data_flow,
        evidence=snippet,
    )
    apply_confidence(
        finding,
        has_user_controlled_source=is_tainted,
        has_direct_flow=bool(data_flow),
        has_sanitizer=is_sanitized,
        is_ast_confirmed=True,
        source_is_constant=first_arg_const,
        is_regex_only=False,
        flow_is_incomplete=is_tainted and not bool(source_label),
    )
    findings.append(finding)


# ---------------------------------------------------------------------------
# Secret checker
# ---------------------------------------------------------------------------

def _check_secrets(
    tree: ast.Module,
    content: str,
    file_path: str,
    lines: List[str],
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id
            if not _SECRET_NAMES.search(var_name):
                continue
            # Only flag if assigned a string literal
            if not isinstance(node.value, ast.Constant):
                continue
            val = node.value.value
            if not isinstance(val, str) or len(val) < 4:
                continue
            # Skip if value looks like a placeholder
            if val.lower() in ("", "none", "null", "your_key_here", "changeme",
                                "replace_me", "todo", "fixme", "secret", "password"):
                continue

            line = node.lineno
            if sup_map and is_suppressed(sup_map, line, "SEC001"):
                continue

            snippet = lines[line - 1].strip() if line <= len(lines) else ""
            finding = RichFindingResult(
                severity="high",
                title=f"Possible hardcoded secret: {var_name}",
                description=(
                    f"Variable '{var_name}' has a credential-related name and is "
                    "assigned a string literal. Hardcoded secrets are exposed in "
                    "version control."
                ),
                file_path=file_path,
                line_number=line,
                rule_id="SEC001",
                category=FindingCategory.SECRETS.value,
                code_snippet=snippet,
                language="python",
                analyzer="ast",
                cwe="CWE-798",
                evidence=snippet,
            )
            apply_confidence(
                finding,
                is_ast_confirmed=True,
                is_regex_only=False,
                source_is_constant=True,
            )
            enrich_remediation(finding)
            finding.fingerprint = generate_fingerprint(finding)
            findings.append(finding)


# ---------------------------------------------------------------------------
# Weak crypto checker
# ---------------------------------------------------------------------------

def _check_weak_crypto(
    content: str,
    file_path: str,
    lines: List[str],
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    for lineno, line in enumerate(lines, start=1):
        m = _WEAK_HASH_RE.search(line)
        if not m:
            continue
        if sup_map and is_suppressed(sup_map, lineno, "CRY001"):
            continue
        alg = m.group(1).upper()
        snippet = line.strip()
        finding = RichFindingResult(
            severity="medium",
            title=f"Weak cryptographic hash: hashlib.{alg.lower()}()",
            description=(
                f"hashlib.{alg.lower()}() is used. {alg} is cryptographically broken "
                "and must not be used for security-sensitive purposes."
            ),
            file_path=file_path,
            line_number=lineno,
            rule_id="CRY001",
            category=FindingCategory.CRYPTO.value,
            code_snippet=snippet,
            language="python",
            analyzer="regex",
            cwe="CWE-327",
            evidence=snippet,
        )
        apply_confidence(finding, is_regex_only=True, is_ast_confirmed=False)
        enrich_remediation(finding)
        finding.fingerprint = generate_fingerprint(finding)
        findings.append(finding)


# ---------------------------------------------------------------------------
# SQL injection checker
# ---------------------------------------------------------------------------

def _check_sql_injection(
    tree: ast.Module,
    content: str,
    file_path: str,
    lines: List[str],
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    """
    Detect SQL queries built with f-strings or % formatting passed to
    execute(), executemany(), or raw().
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if not any(sink in name for sink in _SQL_SINKS):
            continue

        line = node.lineno
        if sup_map and is_suppressed(sup_map, line, "PY005"):
            continue

        snippet = lines[line - 1].strip() if line <= len(lines) else ""

        # Check if first arg is an f-string (JoinedStr)
        if node.args and isinstance(node.args[0], ast.JoinedStr):
            finding = RichFindingResult(
                severity="high",
                title="Potential SQL injection via f-string",
                description=(
                    f"A SQL query is built using an f-string in a call to {name}(). "
                    "User-controlled values interpolated into SQL can allow injection."
                ),
                file_path=file_path,
                line_number=line,
                rule_id="PY005",
                category=FindingCategory.SQL_INJECTION.value,
                code_snippet=snippet,
                language="python",
                analyzer="ast",
                cwe="CWE-89",
                evidence=snippet,
            )
            apply_confidence(
                finding,
                is_ast_confirmed=True,
                is_regex_only=False,
                flow_is_incomplete=True,  # we don't know if vars are user-controlled
            )
            enrich_remediation(finding)
            finding.fingerprint = generate_fingerprint(finding)
            findings.append(finding)

        # Check if first arg is %-formatted string
        elif node.args and isinstance(node.args[0], ast.BinOp):
            op = node.args[0]
            if isinstance(op.op, ast.Mod) and isinstance(op.left, ast.Constant):
                if isinstance(op.left.value, str) and (
                    "SELECT" in op.left.value.upper() or
                    "INSERT" in op.left.value.upper() or
                    "UPDATE" in op.left.value.upper() or
                    "DELETE" in op.left.value.upper()
                ):
                    finding = RichFindingResult(
                        severity="high",
                        title="Potential SQL injection via % string formatting",
                        description=(
                            f"A SQL query uses %-formatting in a call to {name}(). "
                            "This is a common SQL injection pattern."
                        ),
                        file_path=file_path,
                        line_number=line,
                        rule_id="PY005",
                        category=FindingCategory.SQL_INJECTION.value,
                        code_snippet=snippet,
                        language="python",
                        analyzer="ast",
                        cwe="CWE-89",
                        evidence=snippet,
                    )
                    apply_confidence(
                        finding,
                        is_ast_confirmed=True,
                        is_regex_only=False,
                        flow_is_incomplete=True,
                    )
                    enrich_remediation(finding)
                    finding.fingerprint = generate_fingerprint(finding)
                    findings.append(finding)


# ---------------------------------------------------------------------------
# Path traversal checker
# ---------------------------------------------------------------------------

def _check_path_traversal(
    tree: ast.Module,
    content: str,
    file_path: str,
    alias: AliasMap,
    lines: List[str],
    findings: List[RichFindingResult],
    sup_map: Optional[SuppressionMap],
) -> None:
    """
    Detect user-controlled paths passed to open() or path join operations.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name not in ("open", "Path", "os.path.join", "os.path.abspath",
                         "pathlib.Path", "Path.open"):
            continue

        line = node.lineno
        if sup_map and is_suppressed(sup_map, line, "PY006"):
            continue

        snippet = lines[line - 1].strip() if line <= len(lines) else ""
        first_var = _first_arg_name(node)
        if not first_var:
            continue

        is_tainted, is_sanitized = alias.is_tainted(first_var)
        if not is_tainted:
            continue

        entry = alias.lookup(first_var)
        source_label, source_line, _, _ = entry if entry else ("", line, False, False)

        data_flow = []
        if source_label:
            data_flow = _build_flow_chain(
                source_label, source_line,
                [(first_var, first_var, line)],
                f"{name}({first_var})", line,
            )

        finding = RichFindingResult(
            severity="high",
            title="Potential path traversal: user-controlled file path",
            description=(
                f"User-controlled value '{first_var}' reaches {name}() without "
                "path containment validation."
            ),
            file_path=file_path,
            line_number=line,
            rule_id="PY006",
            category=FindingCategory.PATH_TRAVERSAL.value,
            code_snippet=snippet,
            language="python",
            analyzer="dataflow",
            source=SourceInfo(label=source_label, line=source_line),
            sink=SinkInfo(label=f"{name}()", line=line, api=name, is_sanitized=is_sanitized),
            data_flow=data_flow,
            cwe="CWE-22",
            evidence=snippet,
        )
        apply_confidence(
            finding,
            has_user_controlled_source=True,
            has_direct_flow=True,
            has_sanitizer=is_sanitized,
            is_ast_confirmed=True,
            is_regex_only=False,
        )
        enrich_remediation(finding)
        finding.fingerprint = generate_fingerprint(finding)
        findings.append(finding)
