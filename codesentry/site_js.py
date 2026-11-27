# site_js.py
# What the page and its own JavaScript give away: embedded tokens, internal addresses,
# source maps, and the libraries (with versions) that can be checked against OSV.dev.

import base64
import json
import re
import urllib.error
import urllib.parse
from typing import List, Tuple

from .scan_engine import Finding
from .site_http import open_url

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
_INTERNAL = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?[^\s\"'`<>)]*")
_MAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")

# (npm package, regex with the version in group 1)
_LIBS: List[Tuple[str, "re.Pattern"]] = [(n, re.compile(rx)) for n, rx in (
    ("jquery", r"jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)"),
    ("jquery", r"jquery[-.@/](\d+\.\d+\.\d+)(?:\.min)?(?:\.js)?"),
    ("bootstrap", r"Bootstrap v(\d+\.\d+\.\d+)"),
    ("bootstrap", r"bootstrap[@/-](\d+\.\d+\.\d+)"),
    ("lodash", r"lodash[@/-](\d+\.\d+\.\d+)"),
    ("moment", r"moment(?:\.js)?\s*(?:version\s*:\s*|[@/-])(\d+\.\d+\.\d+)"),
    ("angular", r"AngularJS v(\d+\.\d+\.\d+)"),
    ("vue", r"Vue\.js v(\d+\.\d+\.\d+)"),
    ("vue", r"vue[@/-](\d+\.\d+\.\d+)"),
    ("react", r"@license React v(\d+\.\d+\.\d+)"),
    ("react", r"\breact(?:-dom)?[@/-](\d+\.\d+\.\d+)"),
    ("axios", r"axios v(\d+\.\d+\.\d+)"),
    ("axios", r"axios[@/-](\d+\.\d+\.\d+)"),
    ("handlebars", r"[Hh]andlebars(?:\.js)?[ @/v-]+(\d+\.\d+\.\d+)"),
    ("underscore", r"Underscore\.js (\d+\.\d+\.\d+)"),
    ("dompurify", r"DOMPurify (\d+\.\d+\.\d+)"),
    ("dompurify", r"dompurify[@/-](\d+\.\d+\.\d+)"),
    ("chart.js", r"Chart\.js v(\d+\.\d+\.\d+)"),
    ("marked", r"marked v(\d+\.\d+\.\d+)"),
    ("socket.io-client", r"Socket\.IO v(\d+\.\d+\.\d+)"),
    ("d3", r"\bd3[@/-]v?(\d+\.\d+\.\d+)"),
    ("core-js", r"core-js[@/-](\d+\.\d+\.\d+)"),
    ("highlight.js", r"highlight\.js[@/ v-]+(\d+\.\d+\.\d+)"),
)]


def find_libraries(text: str) -> List[Tuple[str, str]]:
    found = []
    for name, rx in _LIBS:
        for m in rx.finditer(text):
            item = (name, m.group(1))
            if item not in found:
                found.append(item)
    return found[:20]


def _payload(segment: str) -> dict:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _mask(token: str) -> str:
    return token[:4] + "****"


def scan_tokens(label: str, text: str) -> List[Finding]:
    """Tokens in the page or its scripts. Supabase keys are told apart by their role."""
    out: List[Finding] = []
    seen = set()
    for m in _JWT.finditer(text):
        token = m.group(0)
        if token in seen:
            continue
        seen.add(token)
        data = _payload(m.group(1))
        role = str(data.get("role", ""))
        iss = str(data.get("iss", ""))
        if role == "service_role":
            out.append(Finding("CS-WEB-030", "Supabase service_role key in client code", "HIGH", "CWE-798", label, 1,
                               _mask(token), "Revoke and rotate it now: this key bypasses Row Level Security. "
                                             "It must only live on a server."))
        elif role == "anon" and "supabase" in iss:
            out.append(Finding("CS-WEB-031", "Supabase anon key in client code", "LOW", "CWE-200", label, 1,
                               _mask(token), "The anon key is public by design: make sure Row Level Security is "
                                             "enabled with policies on every table."))
        else:
            out.append(Finding("CS-WEB-032", "JWT embedded in client code", "MEDIUM", "CWE-798", label, 1,
                               _mask(token), "Do not ship tokens in the page; issue them at runtime."))
    return out


def scan_internal(label: str, text: str) -> List[Finding]:
    hits = []
    for m in _INTERNAL.finditer(text):
        if m.group(0) not in hits:
            hits.append(m.group(0))
    if not hits:
        return []
    return [Finding("CS-WEB-033", "Internal address in client code", "LOW", "CWE-200", label, 1,
                    ", ".join(h[:50] for h in hits[:3]),
                    "Remove development URLs and private addresses from production builds.")]


def scan_source_map(script_url: str, text: str, ctx) -> List[Finding]:
    """A source map left on the server hands out the original, readable source code."""
    m = _MAP_COMMENT.search(text[-2000:])
    if not m or m.group(1).startswith("data:"):
        return []
    map_url = urllib.parse.urljoin(script_url, m.group(1))
    try:
        resp = open_url(map_url, ctx, follow=False, max_body=2000)
    except (OSError, urllib.error.URLError):
        return []
    head = resp.body.decode("utf-8", "ignore")
    if resp.status == 200 and '"version"' in head and ('"sources"' in head or '"mappings"' in head):
        return [Finding("CS-WEB-034", "Source map exposed", "MEDIUM", "CWE-540", map_url, 1,
                        "the original source code can be downloaded",
                        "Do not deploy .map files (or serve them only to authenticated developers).")]
    return []
