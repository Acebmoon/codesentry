# rules_db.py
# Rule database: every check CodeSentry can perform lives here.

import re
from dataclasses import dataclass
from typing import Optional, FrozenSet

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

CODE_EXTS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".c", ".cpp", ".cc",
    ".h", ".hpp", ".cs", ".php", ".rb", ".go", ".rs", ".sh", ".lua", ".gd",
})
PY = frozenset({".py"})
JS = frozenset({".js", ".ts", ".jsx", ".tsx"})
C_LIKE = frozenset({".c", ".cpp", ".cc", ".h", ".hpp"})
JAVA = frozenset({".java", ".kt"})
CONFIG_EXTS = frozenset({".json", ".yml", ".yaml", ".ini", ".cfg", ".conf",
                         ".properties", ".toml", ".xml", ".env"})


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    cwe: str
    pattern: "re.Pattern"
    fix: str
    secret: bool = False
    exts: Optional[FrozenSet[str]] = None  # None = every scanned file


def _r(rid, name, sev, cwe, regex, fix, secret=False, exts=None):
    return Rule(rid, name, sev, cwe, re.compile(regex), fix, secret, exts)


RULES = [
    # ------------------------------------------------------------ secrets
    _r("CS-SEC-001", "AWS access key", "HIGH", "CWE-798",
       r"\bAKIA[0-9A-Z]{16}\b",
       "Revoke the key and load credentials from environment/secret manager.", True),
    _r("CS-SEC-002", "Private key committed", "HIGH", "CWE-798",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
       "Remove the key from the repo, rotate it, and store it outside version control.", True),
    _r("CS-SEC-003", "GitHub token", "HIGH", "CWE-798",
       r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
       "Revoke the token on GitHub and use CI secrets instead.", True),
    _r("CS-SEC-004", "Slack token", "HIGH", "CWE-798",
       r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
       "Revoke the token and store it in a secret manager.", True),
    _r("CS-SEC-005", "Google API key", "HIGH", "CWE-798",
       r"\bAIza[0-9A-Za-z_\-]{35}\b",
       "Restrict/rotate the key and load it from environment variables.", True),
    _r("CS-SEC-006", "JSON Web Token in source", "MEDIUM", "CWE-798",
       r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
       "Do not hardcode tokens; issue them at runtime.", True),
    _r("CS-SEC-007", "Hardcoded password / secret", "HIGH", "CWE-798",
       r"(?i)\b(?:password|passwd|pwd|senha|secret|api[_-]?key|token|auth)\w*\s*[:=]\s*['\"][^'\"\s]{6,}['\"]",
       "Read secrets from environment variables or a secret manager.", True),
    _r("CS-SEC-008", "Credentials inside URL", "MEDIUM", "CWE-798",
       r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+",
       "Pass credentials separately from the connection string.", True),
    # ------------------------------------------------------------ injection
    _r("CS-INJ-001", "eval/exec call", "HIGH", "CWE-95",
       r"(?<![\w.])(?:eval|exec)\s*\(",
       "Avoid eval/exec; use safe parsers (e.g. ast.literal_eval, json).", exts=PY | JS | CODE_EXTS),
    _r("CS-INJ-002", "OS command execution", "HIGH", "CWE-78",
       r"\bos\.(?:system|popen)\s*\(",
       "Use subprocess with an argument list and no shell.", exts=PY),
    _r("CS-INJ-003", "subprocess with shell=True", "HIGH", "CWE-78",  # codesentry:ignore
       r"shell\s*=\s*True",
       "Pass arguments as a list and drop shell=True.", exts=PY),  # codesentry:ignore
    _r("CS-INJ-004", "Runtime.exec / ProcessBuilder", "MEDIUM", "CWE-78",
       r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
       "Validate input and avoid building commands from user data.", exts=JAVA),
    _r("CS-INJ-005", "SQL built by concatenation/formatting", "HIGH", "CWE-89",
       r"(?i)\b(?:select|insert|update|delete)\b[^\n]{0,80}(?:\+\s*\w+|%s|\{\w*\}|\"\s*%|\.format\()",  # codesentry:ignore
       "Use parameterized queries / prepared statements.", exts=CODE_EXTS),
    _r("CS-INJ-006", "innerHTML / document.write", "MEDIUM", "CWE-79",
       r"\.innerHTML\s*=|document\.write\s*\(",
       "Use textContent or a sanitizer to prevent XSS.", exts=JS | frozenset({".html"})),
    # ------------------------------------------------------------ deserialization
    _r("CS-DES-001", "pickle load", "HIGH", "CWE-502",
       r"\bpickle\.loads?\s*\(",
       "Never unpickle untrusted data; use JSON or a safe format.", exts=PY),
    _r("CS-DES-002", "yaml.load without SafeLoader", "MEDIUM", "CWE-502",
       r"\byaml\.load\s*\((?![^)]*Safe)",
       "Use yaml.safe_load.", exts=PY),
    # ------------------------------------------------------------ crypto / TLS
    _r("CS-CRY-001", "Weak hash (MD5/SHA-1)", "MEDIUM", "CWE-327",
       r"hashlib\.(?:md5|sha1)\b|MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"",
       "Use SHA-256+ (or bcrypt/argon2 for passwords).", exts=PY | JAVA),
    _r("CS-CRY-002", "TLS verification disabled", "HIGH", "CWE-295",
       r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true",
       "Keep certificate verification enabled.", exts=CODE_EXTS),
    _r("CS-CRY-003", "Non-crypto RNG for secrets", "LOW", "CWE-338",
       r"(?i)(?:token|password|secret|key)\w*\s*=.*\brandom\.",
       "Use the secrets module / a CSPRNG.", exts=PY),
    # ------------------------------------------------------------ memory safety
    _r("CS-MEM-001", "Unsafe C function", "HIGH", "CWE-120",
       r"\b(?:gets|strcpy|sprintf|strcat)\s*\(",
       "Use bounded versions (fgets, strncpy, snprintf, strncat).", exts=C_LIKE),
    # ------------------------------------------------------------ configuration
    _r("CS-CFG-001", "Debug mode enabled", "MEDIUM", "CWE-489",
       r"(?i)\bdebug\s*[:=]\s*(?:true|1)\b",
       "Disable debug in production builds.", exts=CODE_EXTS | CONFIG_EXTS),
    _r("CS-CFG-002", "Binding to 0.0.0.0", "LOW", "CWE-668",
       r"0\.0\.0\.0",
       "Bind to localhost unless public exposure is intended.", exts=CODE_EXTS | CONFIG_EXTS),
]

# Values that are clearly placeholders, not real secrets.
PLACEHOLDER_HINTS = ("changeme", "your_", "your-", "example", "xxxx", "<", "${",
                     "{{", "placeholder", "dummy", "test", "todo", "password123")
