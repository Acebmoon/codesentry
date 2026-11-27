# site_scan.py
# Passive website check: transport, headers, cookies, CORS, page content, exposed files and
# the page's own JavaScript. Only plain GET/OPTIONS requests (about 100, a few in parallel).
# Nothing is guessed, fuzzed, logged into or exploited.

import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import warnings as _warnings
from html.parser import HTMLParser
from typing import List, Optional, Tuple

from .deps_check import _ssl_context, check_packages, Dep, DepsError
from .rules_db import SEVERITY_ORDER
from .scan_engine import Finding, _scan_lines
from .site_http import (SiteError, Resp, TIMEOUT, normalize_url, is_local, open_url)
from .site_js import find_libraries, scan_tokens, scan_internal, scan_source_map
from .site_paths import scan_paths, scan_robots

__all__ = ["scan_site", "SiteError", "normalize_url"]

MAX_SCRIPTS = 12
MAX_SCRIPT_SCAN = 600_000
_open = open_url


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: List[Tuple[str, bool]] = []     # (src, has integrity)
        self.active: List[str] = []                   # script/iframe/stylesheet urls
        self.passive: List[str] = []                  # img/media urls
        self.forms: List[dict] = []
        self.generator = ""
        self.comments: List[str] = []

    def handle_comment(self, data):
        self.comments.append(data)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append((a["src"], bool(a.get("integrity"))))
            self.active.append(a["src"])
        elif tag == "iframe" and a.get("src"):
            self.active.append(a["src"])
        elif tag == "link" and a.get("href") and ("stylesheet" in a.get("rel", "").lower()
                                                  or "modulepreload" in a.get("rel", "").lower()):
            self.active.append(a["href"])
            if "modulepreload" in a.get("rel", "").lower():
                self.scripts.append((a["href"], bool(a.get("integrity"))))
        elif tag in ("img", "audio", "video", "source") and a.get("src"):
            self.passive.append(a["src"])
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.generator = a.get("content", "")
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get").lower(),
                               "password": False, "hidden": []})
        elif tag == "input" and self.forms:
            kind = a.get("type", "text").lower()
            if kind == "password":
                self.forms[-1]["password"] = True
            if kind == "hidden":
                self.forms[-1]["hidden"].append(a.get("name", "").lower())


_DEBUG = (   # pattern, name, severity, cwe
    (r"Werkzeug Debugger|The Werkzeug interactive debugger|interactive debugger", "Debug console exposed", "HIGH", "CWE-489"),
    (r"Traceback \(most recent call last\)", "Python stack trace shown", "MEDIUM", "CWE-209"),
    (r"Fatal error:.{0,200}on line \d+|Warning:.{0,200}on line \d+", "PHP error message shown", "MEDIUM", "CWE-209"),
    (r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[|Unclosed quotation mark|pg_query\(\)|SQLite3::", "Database error message shown", "MEDIUM", "CWE-209"),
    (r"at [\w.$]+\([\w$]+\.java:\d+\)|Whitelabel Error Page", "Java stack trace shown", "MEDIUM", "CWE-209"),
    (r"Server Error in '/' Application|Stack Trace:", ".NET error page shown", "MEDIUM", "CWE-209"),
)
_COMMENT_WORDS = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|credentials?|todo|fixme|hack|test account)\b")


def _f(rule: str, name: str, sev: str, cwe: str, url: str, snippet: str, fix: str) -> Finding:
    return Finding(rule, name, sev, cwe, url, 1, snippet[:120], fix)


def _csp_problems(csp: str) -> List[str]:
    directives = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]
    values = directives.get("script-src", directives.get("default-src", []))
    problems = []
    for bad in ("'unsafe-inline'", "'unsafe-eval'"):
        if bad in values and not ("'strict-dynamic'" in values or any(v.startswith("'nonce-") for v in values)):
            problems.append(f"script-src allows {bad}")
    if any(v in ("*", "http:", "data:") for v in values):
        problems.append("script-src allows any or insecure sources")
    return problems


def _scan_headers(url: str, resp: Resp, https: bool) -> List[Finding]:
    h = resp.headers
    out: List[Finding] = []
    csp = h.get("Content-Security-Policy", "")
    hsts = h.get("Strict-Transport-Security", "")
    if https and not hsts:
        out.append(_f("CS-WEB-004", "Missing HSTS header", "LOW", "CWE-319", url, "Strict-Transport-Security not set",
                      "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."))
    elif https:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if m and int(m.group(1)) < 15552000:
            out.append(_f("CS-WEB-023", "HSTS lifetime is too short", "LOW", "CWE-319", url, f"Strict-Transport-Security: {hsts}",
                          "Use max-age of at least 15552000 (180 days), ideally 31536000."))
    if not csp:
        out.append(_f("CS-WEB-005", "Missing Content-Security-Policy", "MEDIUM", "CWE-693", url,
                      "Content-Security-Policy not set", "Define a Content-Security-Policy to limit scripts and framing."))
    else:
        for problem in _csp_problems(csp):
            out.append(_f("CS-WEB-024", "Weak Content-Security-Policy", "MEDIUM", "CWE-693", url, problem,
                          "Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes) and wildcard sources."))
    if not h.get("X-Frame-Options") and "frame-ancestors" not in csp.lower():
        out.append(_f("CS-WEB-006", "Page can be framed (clickjacking)", "MEDIUM", "CWE-1021", url,
                      "no X-Frame-Options or frame-ancestors", "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
    if h.get("X-Content-Type-Options", "").lower() != "nosniff":
        out.append(_f("CS-WEB-007", "Missing X-Content-Type-Options", "LOW", "CWE-693", url,
                      "X-Content-Type-Options: nosniff not set", "Send X-Content-Type-Options: nosniff."))
    if not h.get("Referrer-Policy") and "referrer" not in resp.body[:20000].decode("utf-8", "ignore").lower():
        out.append(_f("CS-WEB-008", "Missing Referrer-Policy", "LOW", "CWE-200", url,
                      "Referrer-Policy not set", "Send Referrer-Policy: strict-origin-when-cross-origin."))
    if not h.get("Permissions-Policy") and not h.get("Feature-Policy"):
        out.append(_f("CS-WEB-025", "Missing Permissions-Policy", "LOW", "CWE-693", url,
                      "Permissions-Policy not set",
                      "Send a Permissions-Policy that turns off the camera, microphone and location you do not use."))
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Backend-Server"):
        value = h.get(name, "")
        if value and (name != "Server" or re.search(r"\d", value)):
            out.append(_f("CS-WEB-009", "Server software and version disclosed", "LOW", "CWE-200", url,
                          f"{name}: {value}", "Hide version details (ServerTokens Prod, expose_php off, remove X-Powered-By)."))
    cookies = h.get_all("Set-Cookie") or []
    for cookie in cookies:
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=", 1)[0]
        flags = {p.split("=", 1)[0].lower(): p for p in parts[1:]}
        if https and "secure" not in flags:
            out.append(_f("CS-WEB-010", "Cookie without Secure flag", "MEDIUM", "CWE-614", url,
                          f"Set-Cookie: {name}", "Add the Secure attribute so the cookie only travels over HTTPS."))
        if "httponly" not in flags:
            out.append(_f("CS-WEB-011", "Cookie without HttpOnly flag", "MEDIUM", "CWE-1004", url,
                          f"Set-Cookie: {name}", "Add HttpOnly so scripts cannot read the cookie."))
        if "samesite" not in flags:
            out.append(_f("CS-WEB-012", "Cookie without SameSite attribute", "LOW", "CWE-1275", url,
                          f"Set-Cookie: {name}", "Add SameSite=Lax (or Strict)."))
    if cookies and not re.search(r"no-store|private", h.get("Cache-Control", ""), re.I):
        out.append(_f("CS-WEB-026", "Page that sets a cookie can be cached", "LOW", "CWE-524", url,
                      f"Cache-Control: {h.get('Cache-Control', '(not set)')}",
                      "Send Cache-Control: no-store (or private) on pages that set session cookies."))
    return out


def _scan_cors(url: str, ctx) -> List[Finding]:
    origin = "https://codesentry-cors-test.invalid"
    try:
        resp = _open(url, ctx, headers={"Origin": origin})
    except (OSError, urllib.error.URLError):
        return []
    allow = resp.headers.get("Access-Control-Allow-Origin", "")
    creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if allow == origin:
        sev = "HIGH" if creds else "MEDIUM"
        return [_f("CS-WEB-013", "CORS reflects any origin" + (" with credentials" if creds else ""), sev,
                   "CWE-942", url, f"Access-Control-Allow-Origin: {allow}",
                   "Allow only a fixed list of trusted origins, never echo the Origin header.")]
    if allow == "*" and creds:
        return [_f("CS-WEB-013", "CORS wildcard with credentials", "HIGH", "CWE-942", url,
                   "Access-Control-Allow-Origin: *", "Do not combine * with credentials; list trusted origins.")]
    if allow == "*":
        return [_f("CS-WEB-013", "CORS allows any origin", "LOW", "CWE-942", url,
                   "Access-Control-Allow-Origin: *", "Fine for public data; otherwise list trusted origins.")]
    return []


def _scan_methods(url: str, ctx) -> List[Finding]:
    try:
        resp = _open(url, ctx, method="OPTIONS")
    except (OSError, urllib.error.URLError):
        return []
    allowed = {m.strip().upper() for m in resp.headers.get("Allow", "").split(",") if m.strip()}
    risky = sorted(allowed & {"PUT", "DELETE", "TRACE", "CONNECT"})
    if risky:
        return [_f("CS-WEB-014", "Risky HTTP methods enabled", "MEDIUM", "CWE-749", url,
                   "Allow: " + ", ".join(sorted(allowed)), "Disable " + ", ".join(risky) + " unless the application needs them.")]
    return []


def _scan_legacy_tls(host: str, port: int, url: str) -> List[Finding]:
    """Does the server still accept TLS 1.0 / 1.1? (Only possible when this Python's OpenSSL can try.)"""
    accepted = []
    for label, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            with _warnings.catch_warnings():
                _warnings.simplefilter("ignore")
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False  # nosec
                ctx.verify_mode = ssl.CERT_NONE  # nosec
                ctx.minimum_version = version
                ctx.maximum_version = version
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    accepted.append(label)
        except (ssl.SSLError, OSError, ValueError, AttributeError):
            continue
    if accepted:
        return [_f("CS-WEB-029", "Obsolete TLS versions accepted", "MEDIUM", "CWE-326", url,
                   ", ".join(accepted) + " accepted", "Allow only TLS 1.2 and 1.3.")]
    return []


def _scan_tls(host: str, port: int, url: str) -> Tuple[List[Finding], bool]:
    """(findings, certificate_ok)."""
    ctx = _ssl_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        reason = (exc.verify_message or str(exc)).strip()
        return [_f("CS-WEB-003", "TLS certificate is not trusted", "HIGH", "CWE-295", url, reason[:100],
                   "Install a valid certificate from a trusted authority (Let's Encrypt is free).")], False
    except (OSError, ssl.SSLError):
        return [], True
    out: List[Finding] = []
    try:
        days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
        if days < 14:
            out.append(_f("CS-WEB-003", "TLS certificate expires soon", "MEDIUM", "CWE-295", url,
                          f"expires in {max(int(days), 0)} days", "Renew the certificate (automate it with certbot)."))
    except (KeyError, ValueError):
        pass
    return out, True


def _scan_html(url: str, page: _Page, body: str, https: bool, local: bool) -> List[Finding]:
    out: List[Finding] = []
    host = urllib.parse.urlsplit(url).hostname
    if re.search(r"(?i)<title>\s*index of /", body):
        out.append(_f("CS-WEB-015", "Directory listing enabled", "MEDIUM", "CWE-548", url,
                      "page title is 'Index of /'", "Disable directory listing (Options -Indexes, autoindex off)."))
    for pattern, name, sev, cwe in _DEBUG:
        m = re.search(pattern, body)
        if m:
            out.append(_f("CS-WEB-016", name, sev, cwe, url, m.group(0).replace("\n", " "),
                          "Turn debug mode off and show a generic error page in production."))
    if https:
        for src in page.active:
            if src.lower().startswith("http://"):
                out.append(_f("CS-WEB-017", "Mixed content: insecure script, frame or style", "MEDIUM", "CWE-311",
                              url, src, "Load every resource over https://."))
        for src in page.passive:
            if src.lower().startswith("http://"):
                out.append(_f("CS-WEB-017", "Mixed content: insecure image or media", "LOW", "CWE-311", url, src,
                              "Load every resource over https://."))
    for src, has_integrity in page.scripts:
        target = urllib.parse.urlsplit(urllib.parse.urljoin(url, src))
        if target.hostname and target.hostname != host and not has_integrity:
            out.append(_f("CS-WEB-018", "External script without Subresource Integrity", "LOW", "CWE-353", url,
                          src, "Add an integrity=\"sha384-...\" and crossorigin attribute, or host the file yourself."))
    for form in page.forms:
        action = urllib.parse.urljoin(url, form["action"])
        if form["password"] and action.lower().startswith("http://") and not local:
            out.append(_f("CS-WEB-019", "Password form sent over HTTP", "HIGH", "CWE-319", url,
                          f"form action {action}", "Serve the form and its action over HTTPS only."))
        if form["password"] and form["method"] == "get":
            out.append(_f("CS-WEB-028", "Password form uses GET (the password ends up in the URL)", "MEDIUM", "CWE-598", url,
                          f"form action {form['action'] or '(same page)'}", "Use method=\"post\" for forms with passwords."))
        if form["method"] == "post" and not any(re.search(r"token|csrf|nonce|xsrf|authenticity", n) for n in form["hidden"]):
            out.append(_f("CS-WEB-020", "POST form without an anti-CSRF token", "LOW", "CWE-352", url,
                          f"form action {form['action'] or '(same page)'}", "Add a per-session CSRF token to state-changing forms."))
    if page.generator and re.search(r"\d", page.generator):
        out.append(_f("CS-WEB-009", "Server software and version disclosed", "LOW", "CWE-200", url,
                      f"generator: {page.generator}", "Remove the generator meta tag."))
    words: List[str] = []
    for comment in page.comments:
        if comment.lstrip().startswith("[if"):
            continue
        for m in _COMMENT_WORDS.finditer(comment):
            if m.group(1).lower() not in words:
                words.append(m.group(1).lower())
    if words:
        out.append(_f("CS-WEB-027", "HTML comments mention sensitive-looking words", "LOW", "CWE-615", url,
                      "a comment mentions: " + ", ".join(words[:5]), "Strip comments from production pages."))
    return out


_SECRET_NOTE = {
    "CS-SEC-005": ("LOW", "Browser API keys are public by design: restrict this one by HTTP referrer and by API in Google Cloud."),
}


def _scan_secrets(label: str, text: str) -> List[Finding]:
    """The code scanner's secret rules, applied to what the site serves (tokens are handled in site_js)."""
    out = []
    for f in _scan_lines(text.splitlines(), ".js", label):
        if not f.rule_id.startswith("CS-SEC") or f.rule_id == "CS-SEC-006":
            continue
        if f.rule_id in _SECRET_NOTE:
            f.severity, f.fix = _SECRET_NOTE[f.rule_id]
        out.append(f)
    return out


def _fetch_scripts(page: _Page, final: str, ctx) -> List[Tuple[str, str]]:
    final_host = urllib.parse.urlsplit(final).hostname
    seen, scripts = set(), []
    for src, _ in page.scripts:
        script_url = urllib.parse.urljoin(final, src)
        if script_url in seen or urllib.parse.urlsplit(script_url).hostname != final_host:
            continue
        seen.add(script_url)
        if len(scripts) >= MAX_SCRIPTS:
            break
        try:
            js = _open(script_url, ctx, max_body=MAX_SCRIPT_SCAN * 2)
        except (OSError, urllib.error.URLError):
            continue
        if js.status == 200:
            scripts.append((script_url, js.body.decode("utf-8", "ignore")))
    return scripts


def scan_site(url: str, min_severity: str = "LOW", warnings: Optional[List[str]] = None,
              deps: bool = False) -> List[Finding]:
    """Passive checks of one website. Raises SiteError if it cannot be reached.
    With deps=True the JavaScript libraries it finds are checked against OSV.dev."""
    url = normalize_url(url)
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    local = is_local(host)
    findings: List[Finding] = []
    ctx = _ssl_context()

    if https:
        tls, cert_ok = _scan_tls(host, port, url)
        findings += tls
        if not cert_ok:
            ctx = ssl.create_default_context()          # keep checking a site with a bad certificate
            ctx.check_hostname = False  # nosec
            ctx.verify_mode = ssl.CERT_NONE  # nosec
            if warnings is not None:
                warnings.append("the certificate is not trusted; the other checks ran without verifying it")
        findings += _scan_legacy_tls(host, port, url)
    try:
        resp = _open(url, ctx)
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise SiteError(f"could not reach {url}: {reason}") from None

    final = resp.url
    final_https = final.lower().startswith("https://")
    if not final_https:
        name = "HTTPS redirects to plain HTTP" if https else "Site is served over plain HTTP"
        findings.append(_f("CS-WEB-001", name, "LOW" if local else "HIGH", "CWE-319",
                           final, "no HTTPS", "Serve the site over HTTPS and redirect all HTTP traffic to it."))
    elif https and not local and port == 443:
        try:
            plain = _open(f"http://{host}/", ctx, follow=False)
            location = plain.headers.get("Location", "")
            if plain.status == 200 or (300 <= plain.status < 400 and not location.lower().startswith("https://")):
                findings.append(_f("CS-WEB-002", "HTTP does not redirect to HTTPS", "MEDIUM", "CWE-319", f"http://{host}/",
                                   f"HTTP status {plain.status}", "Redirect all http:// requests to https://."))
        except (OSError, urllib.error.URLError):
            pass

    text = resp.body.decode("utf-8", "ignore")
    page = _Page()
    try:
        page.feed(text)
    except Exception:      # broken markup must not stop the scan
        pass
    base_local = is_local(urllib.parse.urlsplit(final).hostname or "")

    findings += _scan_headers(final, resp, final_https)
    findings += _scan_html(final, page, text, final_https, local)
    findings += _scan_secrets(final, text)
    findings += scan_tokens(final, text)
    if not base_local:
        findings += scan_internal(final, text)
    findings += _scan_cors(final, ctx)
    findings += _scan_methods(final, ctx)
    findings += scan_robots(final, ctx)
    findings += scan_paths(final, ctx)

    libraries = find_libraries(text)
    for script_url, js in _fetch_scripts(page, final, ctx):
        findings += _scan_secrets(script_url, js[:MAX_SCRIPT_SCAN])
        findings += scan_tokens(script_url, js[:MAX_SCRIPT_SCAN])
        if not base_local:
            findings += scan_internal(script_url, js[:MAX_SCRIPT_SCAN])
        findings += scan_source_map(script_url, js, ctx)
        libraries += [(n, v) for n, v in find_libraries(js) if (n, v) not in libraries]
    for src, _ in page.scripts:                       # libraries loaded from a CDN: name and version are in the URL
        libraries += [(n, v) for n, v in find_libraries(urllib.parse.urljoin(final, src)) if (n, v) not in libraries]

    if deps and libraries:
        try:
            findings += check_packages([Dep(n, v, "npm", f"{n} {v} (JavaScript library of {final})", 1)
                                        for n, v in libraries])
        except DepsError as exc:
            if warnings is not None:
                warnings.append(f"library check failed: {exc}")

    threshold = SEVERITY_ORDER[min_severity]
    unique, seen = [], set()
    for f in findings:
        key = (f.rule_id, f.name, f.file, f.snippet)
        if key not in seen and SEVERITY_ORDER[f.severity] >= threshold:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.rule_id, x.file))
    return unique
