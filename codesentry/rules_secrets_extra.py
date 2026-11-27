# rules_secrets_extra.py
# Extra rule pack: more token formats and hardcoded keys (CS-SEC-009 and up).

import re

from .rules_db import make_rule as _r, is_placeholder, _VERSION, _INTERPOLATED

CONFIG_NET = frozenset({".config"})

# Config files where values are usually written without quotes (.env, INI, .properties, YAML, TOML).
CONFIG_FILES = frozenset({".env", ".ini", ".cfg", ".conf", ".properties", ".toml", ".yaml", ".yml"})
# Keys that describe the auth setup instead of holding a secret: token_url, auth_mode, password_file...
_DESCRIBES = re.compile(r"(?i)(?:type|mode|method|provider|scheme|url|uri|endpoint|host|port|file|path|dir"
                        r"|header|name|user|username|enabled|required|ttl|timeout|expiry|expires|length"
                        r"|version|format|algorithm|issuer|audience|realm|domain|policy|rotation|prefix)$")
_NOT_A_SECRET = re.compile(r"(?i)true|false|yes|no|on|off|null|none|nil|enabled|disabled|required|optional|default")


def _config_secret(m: "re.Match") -> bool:
    """CS-SEC-023: an unquoted value under a secret key, unless it is clearly not a secret."""
    value, key = m.group("secret"), m.group("key")
    if _DESCRIBES.search(key) or _NOT_A_SECRET.fullmatch(value) or value.isdigit():
        return False
    if is_placeholder(value) or _VERSION.fullmatch(value) or _INTERPOLATED.fullmatch(value):
        return False
    # A YAML tag or alias (!vault, *ref) and an example cut short ("sk-ant-...") are not the secret.
    return not (value.startswith(("!", "&", "*")) or value.endswith("..."))

SECRET_RULES = [
    _r("CS-SEC-009", "Stripe live API key", "HIGH", "CWE-798",
       r"\b(?P<secret>[sr]k_live_[0-9A-Za-z]{24,})\b",
       "Roll the key in the Stripe dashboard and load it from a secret manager.", True, reveal=8),
    _r("CS-SEC-010", "SendGrid API key", "HIGH", "CWE-798",
       r"\b(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b",
       "Delete the key in SendGrid and create a new one outside the repo.", True, reveal=3),
    _r("CS-SEC-011", "npm access token", "HIGH", "CWE-798",
       r"\b(?P<secret>npm_[A-Za-z0-9]{36})\b",
       "Revoke the token on npmjs.com and use CI secrets.", True, reveal=4),
    _r("CS-SEC-012", "GitLab personal access token", "HIGH", "CWE-798",
       r"\b(?P<secret>glpat-[A-Za-z0-9_-]{20,})",
       "Revoke the token in GitLab and use CI variables.", True, reveal=6),
    _r("CS-SEC-013", "Slack incoming webhook URL", "HIGH", "CWE-798",
       r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})",
       "Rotate the webhook in Slack; anyone with the URL can post to the channel.", True),
    _r("CS-SEC-014", "Discord webhook URL", "MEDIUM", "CWE-798",
       r"(?P<secret>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_-]{50,})",
       "Delete and recreate the webhook; keep the URL out of source control.", True),
    _r("CS-SEC-015", "Telegram bot token", "HIGH", "CWE-798",
       r"\b(?P<secret>\d{8,10}:AA[0-9A-Za-z_-]{33})\b",
       "Revoke the token with @BotFather and load the new one from the environment.", True),
    _r("CS-SEC-016", "Google OAuth client secret", "HIGH", "CWE-798",
       r"\b(?P<secret>GOCSPX-[A-Za-z0-9_-]{28})",
       "Reset the client secret in Google Cloud Console.", True, reveal=6),
    _r("CS-SEC-017", "Azure storage account key", "HIGH", "CWE-798",
       r"AccountKey=(?P<secret>[A-Za-z0-9+/]{60,}={0,2})",
       "Regenerate the key and use managed identities or Key Vault.", True),
    _r("CS-SEC-018", "AI provider API key", "HIGH", "CWE-798",
       r"\b(?P<secret>sk-ant-[A-Za-z0-9_-]{40,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|hf_[A-Za-z0-9]{34})\b",
       "Revoke the key at the provider and load it from an environment variable.", True, reveal=3),
    _r("CS-SEC-019", "Shopify / DigitalOcean token", "HIGH", "CWE-798",
       r"\b(?P<secret>shp(?:at|ca|pa)_[a-f0-9]{32}|dop_v1_[a-f0-9]{64})\b",
       "Revoke the token and store its replacement in a secret manager.", True, reveal=4),
    _r("CS-SEC-020", "PGP private key block", "HIGH", "CWE-798",
       r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
       "Remove the key from the repo, revoke it and generate a new one.", True),
    _r("CS-SEC-021", "Hardcoded HTTP Basic credentials", "MEDIUM", "CWE-798",
       r"(?i)Authorization[\"']?\s*[:=,]\s*[\"']Basic\s+(?P<secret>[A-Za-z0-9+/]{12,}={0,2})[\"']",
       "Build the header at runtime from credentials kept in a secret manager.", True),
    _r("CS-SEC-022", "Hardcoded ASP.NET machineKey", "HIGH", "CWE-798",
       r"<machineKey\s[^>]*(?:validationKey|decryptionKey)\s*=\s*[\"'](?P<secret>[0-9A-Fa-f]{32,})[\"']",
       "Generate keys per environment and keep them out of source; a leaked key allows forged ViewState.",
       True, exts=CONFIG_NET | frozenset({".aspx"})),
    # CS-SEC-007 needs quotes around the value, and config files mostly have none: DB_PASSWORD=... in
    # .env, password: ... in YAML, db.password=... in .properties. The keyword must end the key or be
    # followed by a separator or a camelCase change (token_ttl, apiKeyValue), so tokenizer and author
    # do not count. A commented-out line still counts: the secret is still in the file.
    _r("CS-SEC-023", "Hardcoded secret in a config file", "HIGH", "CWE-798",
       r"^\s*(?:[#;]\s*)?(?:-\s+)?(?:export\s+)?"
       r"(?P<key>(?:[A-Za-z0-9_.-]{0,40}?(?:[_.-]|(?<=[a-z0-9])(?=[A-Z])))?"
       r"(?i:password|passwd|pwd|senha|secret|api[_-]?key|token|auth)"
       r"(?:(?:[_.-]|(?<=[a-z0-9])(?=[A-Z]))[A-Za-z0-9_.-]{0,40})?)"
       r"\s*[:=]\s*(?P<secret>[^\s'\"]{6,200})(?:\s+[#;].*)?\s*$",
       "Keep real values out of committed config files; load them from the environment or a secret manager.",
       True, exts=CONFIG_FILES, check=_config_secret),
]
