# rules_db.py
# Rule database: every check CodeSentry can perform lives here.

import re
from dataclasses import dataclass
from typing import Callable, Optional, FrozenSet

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
    # Extra test on each match; returning False drops it. For what a regex
    # cannot say alone (placeholders, passphrases).
    check: Optional[Callable[["re.Match"], bool]] = None
    # Secret rules mask the `secret` group of the match (or the whole match).
    # `reveal` keeps that many leading characters when they are a fixed public
    # prefix that only names the token type ("AKIA", "ghp_").
    reveal: int = 0


def _r(rid, name, sev, cwe, regex, fix, secret=False, exts=None, check=None, reveal=0):
    return Rule(rid, name, sev, cwe, re.compile(regex), fix, secret, exts, check, reveal)


# ------------------------------------------------------------ placeholders
# Short hints that also live inside real words ("Contest", "latest", "todos")
# only count as a whole token of the value; "<" only at its start
# ("<your-password>"). The other hints still count anywhere in the value.
_WORD_HINTS = frozenset({"test", "todo"})
_PREFIX_HINTS = frozenset({"<"})


def is_placeholder(value: str) -> bool:
    """True when a secret's value is clearly a placeholder (see PLACEHOLDER_HINTS)."""
    low = value.strip().lower()
    tokens = set(re.split(r"[^a-z0-9]+", low))
    for hint in PLACEHOLDER_HINTS:
        if hint in _WORD_HINTS:
            if hint in tokens:
                return True
        elif hint in _PREFIX_HINTS:
            if low.startswith(hint):
                return True
        elif hint in low:
            return True
    return False


_PASSWORD_KEY = re.compile(r"(?i)pass|pwd|senha|secret")
_STRONG_CHAR = re.compile(r"[0-9@#$%^&*_+=~|\\/<>\[\]{}]")
_AUTH_SCHEME = re.compile(r"(?i)(?:bearer|basic|token)\s+\S{8,}")
# A version is never a secret: "@tokenizer/token": "^0.3.0" in a lockfile.
_VERSION = re.compile(r"(?:[~^]|[<>]=?|=|v)?\d+(?:\.(?:\d+|[x*]))+(?:[-+][0-9A-Za-z.-]+)?")


def _quoted_key_opens_an_entry(m: "re.Match") -> bool:
    """A quoted key must start a map entry ({"k": v}, a new line, or after "," "(" "["),
    so a ternary such as `sms ? 'sms-token' : 'screen'` is not read as a key."""
    s, start = m.string, m.start("key")
    if start == 0 or s[start - 1] not in "'\"":
        return True
    before = s[:start - 1].rstrip()
    return not before or before[-1] in "{,(["


def _hardcoded_secret(m: "re.Match") -> bool:
    """CS-SEC-007: keep real values and passphrases; drop placeholders and UI text."""
    value = m.group("secret").strip()
    if not value or is_placeholder(value) or _VERSION.fullmatch(value):
        return False
    if not _quoted_key_opens_an_entry(m):
        return False
    if not any(c.isspace() for c in value):
        return True
    if _AUTH_SCHEME.fullmatch(value):  # "Bearer 9f8a7b6c5d4e3f2a"
        return True
    # A value with spaces is a passphrase only under a password key, with a
    # digit or symbol, and when it does not read like a sentence: this keeps
    # "minha senha forte 2024" and drops "Senha incorreta" or "Use at least
    # 8 characters with 1 digit".
    return (bool(_PASSWORD_KEY.search(m.group("key"))) and bool(_STRONG_CHAR.search(value))
            and len(value.split()) <= 6 and value[-1] not in ".?!:;,")


def _url_credentials(m: "re.Match") -> bool:
    """CS-SEC-008: skip documentation URLs such as https://user:<password>@example.com."""
    return not any(is_placeholder(m.group(g)) for g in ("user", "secret", "host"))


RULES = [
    # ------------------------------------------------------------ secrets
    _r("CS-SEC-001", "AWS access key", "HIGH", "CWE-798",
       r"\b(?P<secret>AKIA[0-9A-Z]{16})\b",
       "Revoke the key and load credentials from environment/secret manager.", True, reveal=4),
    _r("CS-SEC-002", "Private key committed", "HIGH", "CWE-798",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
       "Remove the key from the repo, rotate it, and store it outside version control.", True),
    _r("CS-SEC-003", "GitHub token", "HIGH", "CWE-798",
       r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{30,})\b",
       "Revoke the token on GitHub and use CI secrets instead.", True, reveal=4),
    _r("CS-SEC-004", "Slack token", "HIGH", "CWE-798",
       r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})\b",
       "Revoke the token and store it in a secret manager.", True, reveal=4),
    _r("CS-SEC-005", "Google API key", "HIGH", "CWE-798",
       r"\b(?P<secret>AIza[0-9A-Za-z_\-]{35})\b",
       "Restrict/rotate the key and load it from environment variables.", True, reveal=4),
    _r("CS-SEC-006", "JSON Web Token in source", "MEDIUM", "CWE-798",
       r"\b(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
       "Do not hardcode tokens; issue them at runtime.", True, reveal=3),
    # The key may be quoted ({"password": ...}), prefixed (DB_PASSWORD,
    # client_secret, x-api-key) or camelCase (clientSecret); the keyword must
    # start the key or follow "_", "-" or a lower-to-upper case change. The
    # bounded repeats keep the scan linear on long minified lines.
    _r("CS-SEC-007", "Hardcoded password / secret", "HIGH", "CWE-798",
       r"(?<![A-Za-z0-9])(?P<key>(?:[A-Za-z0-9_-]{0,40}?(?:[_-]|(?<=[a-z0-9])(?=[A-Z])))?"
       r"(?i:password|passwd|pwd|senha|secret|api[_-]?key|token|auth)\w{0,40})"
       r"['\"]?\s*[:=]\s*(?P<q>['\"])(?P<secret>[^'\"\n]{6,1000})(?P=q)",
       "Read secrets from environment variables or a secret manager.", True,
       check=_hardcoded_secret),
    _r("CS-SEC-008", "Credentials inside URL", "MEDIUM", "CWE-798",
       # The scheme starts at a boundary and is short: an unanchored "[a-z]...*://"
       # retried at every letter made long lines quadratic.
       r"(?<![a-zA-Z0-9+.-])[a-zA-Z][a-zA-Z0-9+.-]{0,30}://"
       r"(?P<user>[^/\s:@]+):(?P<secret>[^/\s:@]+)@(?P<host>[^/\s]+)",
       "Pass credentials separately from the connection string.", True,
       check=_url_credentials),
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
       r"(?i)(?:token|password|secret|key)\w{0,40}\s*=.*\brandom\.",  # bounded: linear on long lines
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
       r"(?<![\d.])0\.0\.0\.0(?!\.?\d)",  # not inside 10.0.0.0/8 or 0.0.0.01
       "Bind to localhost unless public exposure is intended.", exts=CODE_EXTS | CONFIG_EXTS),
]

# Values that are clearly placeholders, not real secrets. How each hint is
# matched against a value is in is_placeholder().
PLACEHOLDER_HINTS =("changeme", "your_", "your-", "example", "xxxx", "<", "${",
                     "{{", "placeholder", "dummy", "test", "todo", "password123")
