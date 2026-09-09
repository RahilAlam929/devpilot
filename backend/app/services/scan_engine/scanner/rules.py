"""
DevPilot Phase 5 — Security Rule Registry.

Each SecurityRule carries full metadata:
  rule_id, category, severity, CWE, supported_languages,
  description, why_risky, impact, remediation, fix_example, references.

Rules are deliberately not implemented as regex patterns here.
The rule registry is the METADATA store. Pattern matching lives in the
language-specific analyzers (python_analyzer.py, js_analyzer.py) which
look up metadata from this registry by rule_id.

This design separates what to look for from how to report it,
enabling consistent remediation text regardless of how a rule fires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Rule descriptor
# ---------------------------------------------------------------------------


@dataclass
class SecurityRule:
    rule_id: str
    title: str
    description: str
    category: str
    supported_languages: Set[str]
    cwe: Optional[str]
    default_severity: str          # "critical"|"high"|"medium"|"low"|"info"
    base_confidence: int           # 0-100 starting confidence before adjustments
    why_risky: str
    impact: str
    remediation: str
    fix_example: Optional[str] = None
    references: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, SecurityRule] = {}


def register(rule: SecurityRule) -> SecurityRule:
    _REGISTRY[rule.rule_id] = rule
    return rule


def get_rule(rule_id: str) -> Optional[SecurityRule]:
    return _REGISTRY.get(rule_id)


def all_rules() -> List[SecurityRule]:
    return list(_REGISTRY.values())


# ---------------------------------------------------------------------------
# CODE EXECUTION
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="PY001",
    title="Use of eval() with user-controlled input",
    description="eval() executes arbitrary Python code from a string. When the argument contains user-controlled data, this is a critical remote-code-execution vulnerability.",
    category="code_execution",
    supported_languages={"python"},
    cwe="CWE-95",
    default_severity="high",
    base_confidence=70,
    why_risky="eval() compiles and executes a string as Python code at runtime. If any part of that string originates from user input (HTTP params, form fields, cookies, file content from an untrusted source), an attacker can run arbitrary code on the server.",
    impact="Complete server compromise. An attacker can read files, exfiltrate secrets, install backdoors, pivot to internal systems, or destroy data.",
    remediation=(
        "1. Remove eval() entirely — almost all legitimate uses have safe alternatives.\n"
        "2. For data parsing, use ast.literal_eval() which only evaluates Python literals.\n"
        "3. For mathematical expressions, use a dedicated safe parser library.\n"
        "4. Never pass user-supplied strings to eval()."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "result = eval(request.query_params['expr'])\n\n"
        "# SAFE — only evaluates Python literals (str, int, list, dict, etc.):\n"
        "import ast\n"
        "result = ast.literal_eval(request.query_params['expr'])"
    ),
    references=["https://cwe.mitre.org/data/definitions/95.html"],
))

register(SecurityRule(
    rule_id="PY002",
    title="Use of exec() with user-controlled input",
    description="exec() executes arbitrary Python statements. User-controlled input reaching exec() is a critical code-injection vulnerability.",
    category="code_execution",
    supported_languages={"python"},
    cwe="CWE-95",
    default_severity="high",
    base_confidence=65,
    why_risky="exec() executes arbitrary Python statements. Unlike eval(), exec() can execute complete programs including import statements, function definitions, and system calls.",
    impact="Complete server compromise equivalent to eval(). Full remote code execution.",
    remediation=(
        "1. Eliminate exec() from application code entirely.\n"
        "2. If dynamic code execution is genuinely required, use a sandboxed interpreter.\n"
        "3. Never build the exec() argument from user input."
    ),
    fix_example=None,
    references=["https://cwe.mitre.org/data/definitions/95.html"],
))

register(SecurityRule(
    rule_id="JS001",
    title="Use of eval() in JavaScript/TypeScript",
    description="eval() executes arbitrary JavaScript from a string. It bypasses the JavaScript engine's optimizations and is a code-injection vector.",
    category="code_execution",
    supported_languages={"javascript", "typescript"},
    cwe="CWE-95",
    default_severity="high",
    base_confidence=60,
    why_risky="eval() compiles and executes JavaScript from a string at runtime. If the string contains user-controlled data, an attacker can execute arbitrary JavaScript in the application's context.",
    impact="In server-side Node.js: full server compromise. In browser-side code: XSS and session hijacking.",
    remediation=(
        "1. Remove eval() entirely — use JSON.parse() for data, or structured alternatives.\n"
        "2. Use Function constructors only with fully-trusted static strings.\n"
        "3. Use Content Security Policy to block eval() in browsers."
    ),
    fix_example=(
        "// UNSAFE:\n"
        "const result = eval(userInput);\n\n"
        "// SAFE — parse JSON data:\n"
        "const result = JSON.parse(userInput);"
    ),
    references=["https://cwe.mitre.org/data/definitions/95.html"],
))

register(SecurityRule(
    rule_id="JS002",
    title="Use of Function() constructor as code execution",
    description="new Function(str) constructs and executes JavaScript from a string, equivalent to eval().",
    category="code_execution",
    supported_languages={"javascript", "typescript"},
    cwe="CWE-95",
    default_severity="high",
    base_confidence=65,
    why_risky="The Function() constructor creates a new function from a string, effectively executing arbitrary code similar to eval().",
    impact="Code injection / remote code execution if string is user-controlled.",
    remediation="Replace with explicit function definitions. Never construct functions from user-supplied strings.",
    fix_example=None,
    references=["https://cwe.mitre.org/data/definitions/95.html"],
))

# ---------------------------------------------------------------------------
# COMMAND INJECTION
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="PY003",
    title="subprocess called with shell=True and user-controlled input",
    description="subprocess with shell=True passes the command through the shell interpreter. User-controlled input can inject arbitrary shell commands.",
    category="command_injection",
    supported_languages={"python"},
    cwe="CWE-78",
    default_severity="critical",
    base_confidence=80,
    why_risky="shell=True passes the command to /bin/sh (or cmd.exe on Windows). An attacker can append '; rm -rf /' or similar shell metacharacters to execute arbitrary OS commands.",
    impact="Full operating system command execution with the privileges of the web application process. Data exfiltration, service disruption, pivoting.",
    remediation=(
        "1. Set shell=False (the default) and pass a list of arguments.\n"
        "2. Validate and allowlist any user-supplied values.\n"
        "3. Use shlex.quote() only as a last resort when shell=True is unavoidable."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "cmd = request.query_params['cmd']\n"
        "subprocess.run(cmd, shell=True)\n\n"
        "# SAFE — argument list, no shell:\n"
        "# Allowlist permitted commands:\n"
        "ALLOWED = {'ls', 'pwd', 'date'}\n"
        "cmd = request.query_params['cmd']\n"
        "if cmd not in ALLOWED:\n"
        "    raise ValueError('Invalid command')\n"
        "subprocess.run([cmd], shell=False)"
    ),
    references=["https://cwe.mitre.org/data/definitions/78.html"],
))

register(SecurityRule(
    rule_id="PY004",
    title="os.system() with user-controlled input",
    description="os.system() passes a command string to the shell. User input reaching this call enables OS command injection.",
    category="command_injection",
    supported_languages={"python"},
    cwe="CWE-78",
    default_severity="high",
    base_confidence=70,
    why_risky="os.system() invokes the shell to run a command string. It is equivalent to subprocess.run(cmd, shell=True) with the same injection risks.",
    impact="OS command injection — full code execution under the server process user.",
    remediation=(
        "1. Replace os.system() with subprocess.run([...], shell=False).\n"
        "2. Never include user-supplied values in the command without strict validation."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "os.system(f'ping {host}')\n\n"
        "# SAFE:\n"
        "import re\n"
        "if not re.match(r'^[a-zA-Z0-9.-]+$', host):\n"
        "    raise ValueError('Invalid host')\n"
        "subprocess.run(['ping', '-c', '1', host], shell=False, timeout=10)"
    ),
    references=["https://cwe.mitre.org/data/definitions/78.html"],
))

register(SecurityRule(
    rule_id="JS003",
    title="child_process.exec() with user-controlled input",
    description="child_process.exec() passes a command to the shell. User-controlled input enables OS command injection.",
    category="command_injection",
    supported_languages={"javascript", "typescript"},
    cwe="CWE-78",
    default_severity="critical",
    base_confidence=75,
    why_risky="child_process.exec() invokes /bin/sh to run the command string. Shell metacharacters in user input can execute arbitrary OS commands.",
    impact="Full OS command execution on the Node.js server.",
    remediation=(
        "1. Use child_process.execFile() or child_process.spawn() with an argument array.\n"
        "2. Never interpolate user input into shell command strings."
    ),
    fix_example=(
        "// UNSAFE:\n"
        "exec(`git clone ${userUrl}`);\n\n"
        "// SAFE — argument array:\n"
        "const { execFile } = require('child_process');\n"
        "execFile('git', ['clone', '--', userUrl], callback);"
    ),
    references=["https://cwe.mitre.org/data/definitions/78.html"],
))

# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="JS004",
    title="dangerouslySetInnerHTML with potentially unsanitized content",
    description="dangerouslySetInnerHTML bypasses React's XSS protections. If the value contains untrusted HTML, the browser will execute any embedded scripts.",
    category="xss",
    supported_languages={"javascript", "typescript"},
    cwe="CWE-79",
    default_severity="high",
    base_confidence=65,
    why_risky="React normally escapes HTML in JSX expressions. dangerouslySetInnerHTML bypasses this protection and passes the HTML string directly to the browser's HTML parser. Any `<script>` tags or event handlers in the string will execute.",
    impact="Cross-Site Scripting (XSS). An attacker who can control the HTML string can steal session cookies, perform actions on behalf of the user, redirect to phishing pages.",
    remediation=(
        "1. Sanitize the HTML with a trusted library (e.g. DOMPurify) before passing it.\n"
        "2. Prefer React's normal JSX rendering which automatically escapes values.\n"
        "3. If you must render HTML, ensure the source is fully trusted (your own CMS)."
    ),
    fix_example=(
        "// UNSAFE:\n"
        "<div dangerouslySetInnerHTML={{ __html: userHtml }} />\n\n"
        "// SAFE — sanitize first:\n"
        "import DOMPurify from 'dompurify';\n"
        "const clean = DOMPurify.sanitize(userHtml);\n"
        "<div dangerouslySetInnerHTML={{ __html: clean }} />"
    ),
    references=["https://cwe.mitre.org/data/definitions/79.html", "https://github.com/cure53/DOMPurify"],
))

register(SecurityRule(
    rule_id="JS005",
    title="Direct innerHTML assignment",
    description="Assigning to .innerHTML without sanitization can introduce XSS if the value contains untrusted HTML.",
    category="xss",
    supported_languages={"javascript", "typescript"},
    cwe="CWE-79",
    default_severity="medium",
    base_confidence=55,
    why_risky="innerHTML causes the browser's HTML parser to process the string. Scripts and event handlers in the string will execute.",
    impact="Cross-Site Scripting (XSS) if value originates from user input.",
    remediation=(
        "1. For plain text, use .textContent instead of .innerHTML.\n"
        "2. For HTML, sanitize with DOMPurify before assigning."
    ),
    fix_example=(
        "// UNSAFE:\n"
        "el.innerHTML = userInput;\n\n"
        "// SAFE for plain text:\n"
        "el.textContent = userInput;\n\n"
        "// SAFE for HTML:\n"
        "el.innerHTML = DOMPurify.sanitize(userInput);"
    ),
    references=["https://cwe.mitre.org/data/definitions/79.html"],
))

register(SecurityRule(
    rule_id="JS006",
    title="document.write() usage",
    description="document.write() can introduce XSS and blocks the HTML parser. It is deprecated and unsafe.",
    category="xss",
    supported_languages={"javascript", "typescript"},
    cwe="CWE-79",
    default_severity="medium",
    base_confidence=50,
    why_risky="document.write() inserts raw HTML into the page, bypassing any sanitization. It also blocks the HTML parser.",
    impact="XSS if any argument contains user-controlled content.",
    remediation="Replace with safe DOM manipulation: createElement(), textContent, or innerHTML with DOMPurify.",
    fix_example=None,
    references=["https://cwe.mitre.org/data/definitions/79.html"],
))

# ---------------------------------------------------------------------------
# SQL INJECTION
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="PY005",
    title="SQL query constructed with string formatting",
    description="Building SQL queries using f-strings, % formatting, or string concatenation with user-controlled values enables SQL injection.",
    category="sql_injection",
    supported_languages={"python"},
    cwe="CWE-89",
    default_severity="high",
    base_confidence=70,
    why_risky="String-formatted SQL queries allow an attacker to inject SQL syntax. A single-quote character in user input can break out of string literals and modify query logic.",
    impact="Data exfiltration, authentication bypass, data modification, or deletion. In some configurations, OS command execution via database features (xp_cmdshell, COPY TO).",
    remediation=(
        "1. Use parameterized queries / prepared statements exclusively.\n"
        "2. Pass user values as separate parameters, never by formatting them into the query string.\n"
        "3. Use an ORM's query builder (SQLAlchemy select(), filter()) instead of raw SQL."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "db.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n\n"
        "# SAFE — parameterized:\n"
        "from sqlalchemy import text\n"
        "db.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})"
    ),
    references=["https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/www-community/attacks/SQL_Injection"],
))

# ---------------------------------------------------------------------------
# PATH TRAVERSAL
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="PY006",
    title="Path traversal: user-controlled file path",
    description="Using user-supplied input to construct file system paths without containment validation enables directory traversal attacks.",
    category="path_traversal",
    supported_languages={"python"},
    cwe="CWE-22",
    default_severity="high",
    base_confidence=60,
    why_risky="An attacker can use '../../../etc/passwd' or URL-encoded variants to access files outside the intended directory.",
    impact="Arbitrary file read (source code, configuration, secrets, private keys). In write contexts: arbitrary file write leading to code execution.",
    remediation=(
        "1. Resolve the user-supplied path and verify it is within the expected base directory.\n"
        "2. Use Path.resolve() and check it starts with the base path.\n"
        "3. Reject any path containing '..' components before resolution."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "filename = request.query_params['file']\n"
        "with open(os.path.join('/var/data', filename)) as f:\n"
        "    content = f.read()\n\n"
        "# SAFE:\n"
        "from pathlib import Path\n"
        "BASE = Path('/var/data').resolve()\n"
        "requested = (BASE / filename).resolve()\n"
        "if not str(requested).startswith(str(BASE)):\n"
        "    raise ValueError('Invalid path')\n"
        "content = requested.read_text()"
    ),
    references=["https://cwe.mitre.org/data/definitions/22.html"],
))

# ---------------------------------------------------------------------------
# DESERIALIZATION
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="PY007",
    title="Unsafe pickle deserialization",
    description="pickle.load/loads can execute arbitrary code when deserializing untrusted data.",
    category="deserialization",
    supported_languages={"python"},
    cwe="CWE-502",
    default_severity="high",
    base_confidence=75,
    why_risky="The pickle format embeds executable Python bytecode. Deserializing attacker-controlled pickle data executes that bytecode with full Python privileges.",
    impact="Remote code execution. The pickle '__reduce__' protocol can invoke any callable, including os.system().",
    remediation=(
        "1. Never deserialize pickle data from untrusted sources.\n"
        "2. Use JSON, MessagePack, or Protocol Buffers for data exchange.\n"
        "3. If pickle must be used, sign and verify the data with HMAC before loading."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "data = pickle.loads(request.body)\n\n"
        "# SAFE — use JSON for data exchange:\n"
        "import json\n"
        "data = json.loads(request.body)"
    ),
    references=["https://cwe.mitre.org/data/definitions/502.html", "https://docs.python.org/3/library/pickle.html#restricting-globals"],
))

register(SecurityRule(
    rule_id="PY008",
    title="Unsafe yaml.load() without safe loader",
    description="yaml.load() without Loader=yaml.SafeLoader can deserialize arbitrary Python objects and execute code.",
    category="deserialization",
    supported_languages={"python"},
    cwe="CWE-502",
    default_severity="high",
    base_confidence=80,
    why_risky="PyYAML's default Loader can deserialize arbitrary Python objects using the '!!' YAML tag syntax. A YAML document can embed Python constructor calls.",
    impact="Remote code execution when parsing attacker-controlled YAML.",
    remediation=(
        "1. Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).\n"
        "2. These loaders only process standard YAML types (str, int, list, dict) and cannot construct arbitrary Python objects."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "data = yaml.load(user_yaml)\n\n"
        "# SAFE:\n"
        "data = yaml.safe_load(user_yaml)\n"
        "# OR:\n"
        "data = yaml.load(user_yaml, Loader=yaml.SafeLoader)"
    ),
    references=["https://cwe.mitre.org/data/definitions/502.html", "https://pyyaml.org/wiki/PyYAMLDocumentation"],
))

# ---------------------------------------------------------------------------
# SECRETS
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="SEC001",
    title="Possible hardcoded secret or credential",
    description="A variable associated with secrets has been assigned a string literal. Hardcoded secrets are exposed in version control, logs, and error messages.",
    category="secrets",
    supported_languages={"python", "javascript", "typescript", "java", "go", "ruby", "php"},
    cwe="CWE-798",
    default_severity="high",
    base_confidence=60,
    why_risky="Hardcoded credentials are visible to anyone with repository access (past and present contributors, CI/CD systems). They cannot be rotated without code changes.",
    impact="Credential theft. Depending on the secret: unauthorized API access, database access, system access.",
    remediation=(
        "1. Remove the hardcoded secret from source code immediately.\n"
        "2. Rotate the secret — assume it has been compromised.\n"
        "3. Load secrets from environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).\n"
        "4. Add the secret pattern to .gitignore and git-secrets pre-commit hooks."
    ),
    fix_example=(
        "# UNSAFE:\n"
        "API_KEY = 'sk-abc123secretvalue'\n\n"
        "# SAFE:\n"
        "import os\n"
        "API_KEY = os.environ['API_KEY']  # or use python-dotenv"
    ),
    references=["https://cwe.mitre.org/data/definitions/798.html"],
))

register(SecurityRule(
    rule_id="SEC002",
    title="Possible secret value in log statement",
    description="A logging call appears to log a value associated with a secret or credential. Secrets in logs are a serious exposure risk.",
    category="secrets",
    supported_languages={"python", "javascript", "typescript"},
    cwe="CWE-532",
    default_severity="medium",
    base_confidence=55,
    why_risky="Log files are often less protected than application code. They may be accessible to monitoring tools, log aggregators, support staff, or attackers. Console output in browsers is visible to DevTools, XSS attacks, and browser extensions.",
    impact="Secret/credential exposure via log files, browser DevTools, monitoring dashboards, or log-forwarding pipelines.",
    remediation=(
        "1. Never log secrets, tokens, or passwords.\n"
        "2. Log only non-sensitive identifiers (user ID, request ID).\n"
        "3. Mask or redact sensitive values before logging.\n"
        "4. Remove debug console statements before production deployment."
    ),
    fix_example=(
        "// UNSAFE:\n"
        "console.log('Token:', authToken);\n\n"
        "// SAFE:\n"
        "console.log('Authentication successful');\n"
        "// Or:\n"
        "console.log('User ID:', userId);  // log identifier, not secret"
    ),
    references=["https://cwe.mitre.org/data/definitions/532.html"],
))

# ---------------------------------------------------------------------------
# CRYPTOGRAPHY
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="CRY001",
    title="Weak cryptographic hash algorithm",
    description="MD5 and SHA-1 are cryptographically broken and must not be used for security-sensitive purposes.",
    category="crypto",
    supported_languages={"python", "javascript", "typescript"},
    cwe="CWE-327",
    default_severity="medium",
    base_confidence=65,
    why_risky="MD5 and SHA-1 are vulnerable to collision attacks. MD5 has been shown to produce practical collisions in seconds on modern hardware. SHA-1 is deprecated by NIST.",
    impact="Hash collisions can lead to signature forgery, certificate spoofing, or bypass of integrity checks.",
    remediation=(
        "1. Replace MD5/SHA-1 with SHA-256 or SHA-3 for security purposes.\n"
        "2. For password hashing, use bcrypt, scrypt, or Argon2 — NOT any SHA variant.\n"
        "3. MD5/SHA-1 are acceptable for non-security uses like checksums/deduplication."
    ),
    fix_example=(
        "# UNSAFE for security:\n"
        "digest = hashlib.md5(data).hexdigest()\n\n"
        "# SAFE:\n"
        "digest = hashlib.sha256(data).hexdigest()"
    ),
    references=["https://cwe.mitre.org/data/definitions/327.html", "https://csrc.nist.gov/projects/hash-functions"],
))

# ---------------------------------------------------------------------------
# QUALITY
# ---------------------------------------------------------------------------

register(SecurityRule(
    rule_id="QA001",
    title="Unfinished-work marker (TODO/FIXME)",
    description="A TODO, FIXME, HACK, or XXX comment indicates unfinished or potentially broken code.",
    category="quality",
    supported_languages=set(),  # all languages
    cwe=None,
    default_severity="info",
    base_confidence=90,
    why_risky="Unresolved markers may indicate missing validation, incomplete error handling, or acknowledged technical debt that introduces bugs.",
    impact="Potential functional bugs or missing security controls depending on context.",
    remediation="Resolve the indicated issue or convert to a tracked issue in your issue tracker.",
    fix_example=None,
    references=[],
))

register(SecurityRule(
    rule_id="QA002",
    title="Debug print statement",
    description="A debug print() call was left in production code.",
    category="quality",
    supported_languages={"python"},
    cwe=None,
    default_severity="low",
    base_confidence=80,
    why_risky="print() statements in production code may leak sensitive information to stdout/logs and indicate the code has not been properly reviewed.",
    impact="Potential information disclosure via server logs.",
    remediation="Replace with structured logging: import logging; logging.debug('message').",
    fix_example="# Replace print(value) with:\nimport logging\nlogger = logging.getLogger(__name__)\nlogger.debug('%s', value)",
    references=[],
))

register(SecurityRule(
    rule_id="QA003",
    title="console statement in production code",
    description="A console.log/debug/warn/error call was left in production JavaScript/TypeScript code.",
    category="quality",
    supported_languages={"javascript", "typescript"},
    cwe=None,
    default_severity="low",
    base_confidence=85,
    why_risky="Console statements in production code may expose non-obvious implementation details and indicate the code was not properly reviewed before deployment.",
    impact="Potential information disclosure in browser DevTools or server logs.",
    remediation=(
        "Remove console statements or replace with a structured logging library (pino, winston) "
        "that supports log levels and can be disabled in production builds.\n\n"
        "If the logged value could be sensitive (tokens, passwords, user objects), treat this as "
        "a potential information disclosure issue (SEC002)."
    ),
    fix_example=None,
    references=[],
))

register(SecurityRule(
    rule_id="QA004",
    title="Broad exception handling",
    description="Catching the base Exception class suppresses unexpected errors and makes debugging harder.",
    category="quality",
    supported_languages={"python"},
    cwe=None,
    default_severity="medium",
    base_confidence=85,
    why_risky="Overly broad exception handling can mask programming errors, hide security issues, and allow the application to continue in an inconsistent state.",
    impact="Silent failure, potential data corruption, security bypasses in error paths.",
    remediation="Catch the specific exception types you expect. Let unexpected exceptions propagate.",
    fix_example=(
        "# AVOID:\n"
        "except Exception:\n"
        "    pass\n\n"
        "# PREFER:\n"
        "except (ValueError, KeyError) as exc:\n"
        "    logger.warning('Expected error: %s', exc)"
    ),
    references=[],
))

register(SecurityRule(
    rule_id="QA005",
    title="Circular import detected",
    description="A circular import dependency was found between internal modules.",
    category="quality",
    supported_languages={"python"},
    cwe=None,
    default_severity="high",
    base_confidence=90,
    why_risky="Circular imports cause unpredictable module initialization order, subtle AttributeError/ImportError at runtime, and indicate architectural coupling issues.",
    impact="Runtime ImportError or AttributeError; difficult-to-debug initialization failures.",
    remediation=(
        "1. Break the cycle by moving shared code to a third module both can import.\n"
        "2. Use lazy imports (import inside a function) as a temporary workaround.\n"
        "3. Use dependency injection instead of direct imports."
    ),
    fix_example=None,
    references=[],
))

register(SecurityRule(
    rule_id="QA006",
    title="Mutable default argument",
    description="A function parameter uses a mutable object (list, dict, set) as its default value.",
    category="quality",
    supported_languages={"python"},
    cwe=None,
    default_severity="medium",
    base_confidence=95,
    why_risky="The default value is created once when the function is defined and shared across all calls. Mutations in one call affect subsequent calls.",
    impact="Subtle data-sharing bugs that are very hard to diagnose.",
    remediation="Use None as the default and create the mutable object inside the function body.",
    fix_example=(
        "# UNSAFE:\n"
        "def append_item(item, items=[]):\n"
        "    items.append(item)\n"
        "    return items\n\n"
        "# SAFE:\n"
        "def append_item(item, items=None):\n"
        "    if items is None:\n"
        "        items = []\n"
        "    items.append(item)\n"
        "    return items"
    ),
    references=[],
))

register(SecurityRule(
    rule_id="QA007",
    title="Bare except clause",
    description="'except:' with no type catches BaseException including KeyboardInterrupt and SystemExit.",
    category="quality",
    supported_languages={"python"},
    cwe=None,
    default_severity="medium",
    base_confidence=95,
    why_risky="Bare except catches everything including signals. This can prevent clean shutdown and mask critical errors.",
    impact="Cannot interrupt the process normally; hides programming errors.",
    remediation="Use 'except Exception:' at minimum, or preferably a specific exception type.",
    fix_example=None,
    references=[],
))

register(SecurityRule(
    rule_id="QA008",
    title="Assert used for security or validation",
    description="assert statements are disabled when Python runs with -O optimization flag.",
    category="quality",
    supported_languages={"python"},
    cwe=None,
    default_severity="low",
    base_confidence=70,
    why_risky="Optimized Python (-O flag) removes assert statements. If asserts are used for input validation or security checks, those checks disappear in production.",
    impact="Security bypasses if asserts guard access controls or input validation.",
    remediation="Use explicit if/raise statements for security-critical checks.",
    fix_example=(
        "# UNSAFE:\n"
        "assert user.is_admin, 'Not authorized'\n\n"
        "# SAFE:\n"
        "if not user.is_admin:\n"
        "    raise PermissionError('Not authorized')"
    ),
    references=[],
))
