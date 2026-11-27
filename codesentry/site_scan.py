# site_scan.py
# Passive website check: security headers, cookies, TLS, CORS, exposed files, page leaks.
# Only plain GET/OPTIONS requests (about 30 at most). Nothing is guessed, fuzzed or exploited.

import ipaddress
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Dict, List, NamedTuple, Optional, Tuple

from .deps_check import _ssl_context
from .rules_db import SEVERITY_ORDER
from .scan_engine import Finding, _scan_lines

TIMEOUT = 10
MAX_BODY = 1_500_000
MAX_SCRIPTS = 8
MAX_SCRIPT_SCAN = 400_000
USER_AGENT = "CodeSentry-site-check (passive; https://github.com/Acebmoon/codesentry)"


class SiteError(Exception):
    """A readable problem: bad address, site unreachable."""


class _Resp(NamedTuple):
    status: int
    headers: object          # email.message.Message
    body: bytes
    url: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def normalize_url(text: str) -> str:
    text = text.strip().strip('"').strip("'")
    if not text:
        raise SiteError("Type a website address, e.g. https://example.com")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SiteError("Only http:// and https:// addresses are supported.")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _is_local(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def _open(url: str, ctx, follow: bool = True, method: str = "GET",
          headers: Optional[Dict[str, str]] = None) -> _Resp:
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return _Resp(resp.status, resp.headers, resp.read(MAX_BODY), resp.geturl())
    except urllib.error.HTTPError as exc:       # 3xx without follow, 4xx, 5xx still carry data
        try:
            body = exc.read(MAX_BODY)
        except OSError:
            body = b""
        return _Resp(exc.code, exc.headers, body, url)


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: List[Tuple[str, bool]] = []     # (src, has integrity)
        self.active: List[str] = []                   # script/iframe/stylesheet urls
        self.passive: List[str] = []                  # img/media urls
        self.forms: List[dict] = []
        self.generator = ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append((a["src"], bool(a.get("integrity"))))
            self.active.append(a["src"])
        elif tag == "iframe" and a.get("src"):
            self.active.append(a["src"])
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.active.append(a["href"])
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


_SENSITIVE = (   # path, name, severity, check(body bytes)
    ("/.git/HEAD", "Git repository exposed", "HIGH", lambda b: b.startswith(b"ref:")),
    ("/.git/config", "Git configuration exposed", "HIGH", lambda b: b"[core]" in b),
    ("/.env", "Environment file exposed", "HIGH",
     lambda b: b"<html" not in b[:500].lower() and len(re.findall(rb"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", b)) >= 2),
    ("/.htpasswd", "Password file exposed", "HIGH", lambda b: bool(re.search(rb"(?m)^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\})", b))),
    ("/.DS_Store", "macOS metadata file exposed", "LOW", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1")),
    ("/phpinfo.php", "phpinfo() page exposed", "MEDIUM", lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("/server-status", "Apache server-status exposed", "MEDIUM", lambda b: b"Apache Server Status" in b),
    ("/wp-config.php.bak", "WordPress config backup exposed", "HIGH", lambda b: b"DB_PASSWORD" in b),
    ("/config.php.bak", "Config backup exposed", "HIGH", lambda b: b"<?php" in b),
    ("/backup.sql", "Database dump exposed", "HIGH", lambda b: bool(re.search(rb"(?i)create table|insert into", b))),
    ("/dump.sql", "Database dump exposed", "HIGH", lambda b: bool(re.search(rb"(?i)create table|insert into", b))),
    ("/backup.zip", "Backup archive exposed", "HIGH", lambda b: b.startswith(b"PK")),
    ("/docker-compose.yml", "Docker compose file exposed", "MEDIUM", lambda b: b"services:" in b),
)

_DEBUG = (   # pattern, name, severity, cwe
    (r"Werkzeug Debugger|The Werkzeug interactive debugger|interactive debugger", "Debug console exposed", "HIGH", "CWE-489"),
    (r"Traceback \(most recent call last\)", "Python stack trace shown", "MEDIUM", "CWE-209"),
    (r"Fatal error:.{0,200}on line \d+|Warning:.{0,200}on line \d+", "PHP error message shown", "MEDIUM", "CWE-209"),
    (r"You have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[|Unclosed quotation mark|pg_query\(\)|SQLite3::", "Database error message shown", "MEDIUM", "CWE-209"),
    (r"at [\w.$]+\([\w$]+\.java:\d+\)|Whitelabel Error Page", "Java stack trace shown", "MEDIUM", "CWE-209"),
    (r"Server Error in '/' Application|Stack Trace:", ".NET error page shown", "MEDIUM", "CWE-209"),
)


def _f(rule: str, name: str, sev: str, cwe: str, url: str, snippet: str, fix: str) -> Finding:
    return Finding(rule, name, sev, cwe, url, 1, snippet[:120], fix)


def _scan_headers(url: str, resp: _Resp, https: bool, local: bool) -> List[Finding]:
    h = resp.headers
    out: List[Finding] = []
    csp = h.get("Content-Security-Policy", "")
    if https and not h.get("Strict-Transport-Security"):
        out.append(_f("CS-WEB-004", "Missing HSTS header", "LOW", "CWE-319", url, "Strict-Transport-Security not set",
                      "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."))
    if not csp:
        out.append(_f("CS-WEB-005", "Missing Content-Security-Policy", "MEDIUM", "CWE-693", url,
                      "Content-Security-Policy not set", "Define a Content-Security-Policy to limit scripts and framing."))
    if not h.get("X-Frame-Options") and "frame-ancestors" not in csp.lower():
        out.append(_f("CS-WEB-006", "Page can be framed (clickjacking)", "MEDIUM", "CWE-1021", url,
                      "no X-Frame-Options or frame-ancestors", "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
    if h.get("X-Content-Type-Options", "").lower() != "nosniff":
        out.append(_f("CS-WEB-007", "Missing X-Content-Type-Options", "LOW", "CWE-693", url,
                      "X-Content-Type-Options: nosniff not set", "Send X-Content-Type-Options: nosniff."))
    if not h.get("Referrer-Policy") and "referrer" not in resp.body[:20000].decode("utf-8", "ignore").lower():
        out.append(_f("CS-WEB-008", "Missing Referrer-Policy", "LOW", "CWE-200", url,
                      "Referrer-Policy not set", "Send Referrer-Policy: strict-origin-when-cross-origin."))
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        value = h.get(name, "")
        if value and (name != "Server" or re.search(r"\d", value)):
            out.append(_f("CS-WEB-009", "Server software and version disclosed", "LOW", "CWE-200", url,
                          f"{name}: {value}", "Hide version details (ServerTokens Prod, expose_php off, remove X-Powered-By)."))
    for cookie in h.get_all("Set-Cookie") or []:
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
    try:
        days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
    except (KeyError, ValueError):
        return [], True
    if days < 14:
        return [_f("CS-WEB-003", "TLS certificate expires soon", "MEDIUM", "CWE-295", url,
                   f"expires in {max(int(days), 0)} days", "Renew the certificate (automate it with certbot).")], True
    return [], True


def _scan_html(url: str, body: str, https: bool, local: bool) -> List[Finding]:
    out: List[Finding] = []
    page = _Page()
    try:
        page.feed(body)
    except Exception:      # broken markup must not stop the scan
        pass
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
        if form["password"] and action.lower().startswith("http://") and not _is_local(host or ""):
            out.append(_f("CS-WEB-019", "Password form sent over HTTP", "HIGH", "CWE-319", url,
                          f"form action {action}", "Serve the form and its action over HTTPS only."))
        if form["method"] == "post" and not any(re.search(r"token|csrf|nonce|xsrf|authenticity", n) for n in form["hidden"]):
            out.append(_f("CS-WEB-020", "POST form without an anti-CSRF token", "LOW", "CWE-352", url,
                          f"form action {form['action'] or '(same page)'}", "Add a per-session CSRF token to state-changing forms."))
    if page.generator and re.search(r"\d", page.generator):
        out.append(_f("CS-WEB-009", "Server software and version disclosed", "LOW", "CWE-200", url,
                      f"generator: {page.generator}", "Remove the generator meta tag."))
    return out


def _scan_secrets(url: str, body: str, label: str) -> List[Finding]:
    found = _scan_lines(body.splitlines(), ".js", url)
    out = []
    for f in found:
        if f.rule_id.startswith("CS-SEC"):
            f.file = label
            out.append(f)
    return out


def _scan_sensitive(base: str, ctx) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for path, name, sev, check in _SENSITIVE:
        target = urllib.parse.urljoin(base, path)
        try:
            resp = _open(target, ctx, follow=False)
        except (OSError, urllib.error.URLError):
            continue
        if resp.status == 200 and resp.body and check(resp.body) and (name, path) not in seen:
            seen.add((name, path))
            out.append(_f("CS-WEB-021", name, sev, "CWE-538", target, f"{path} returned content",
                          "Remove the file from the web root or block the path in the server configuration."))
    return out


def scan_site(url: str, min_severity: str = "LOW", warnings: Optional[List[str]] = None) -> List[Finding]:
    """Passive checks of one website. Raises SiteError if it cannot be reached."""
    url = normalize_url(url)
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    local = _is_local(host)
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
    try:
        resp = _open(url, ctx)
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise SiteError(f"could not reach {url}: {reason}") from None

    final = resp.url
    final_https = final.lower().startswith("https://")
    if not final_https:
        findings.append(_f("CS-WEB-001", "Site is served over plain HTTP", "LOW" if local else "HIGH", "CWE-319",
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
    findings += _scan_headers(final, resp, final_https, local)
    findings += _scan_html(final, text, final_https, local)
    findings += _scan_secrets(final, text, final)
    findings += _scan_cors(final, ctx)
    findings += _scan_methods(final, ctx)
    findings += _scan_sensitive(final, ctx)

    page = _Page()
    try:
        page.feed(text)
    except Exception:
        pass
    final_host = urllib.parse.urlsplit(final).hostname
    count = 0
    for src, _ in page.scripts:
        script_url = urllib.parse.urljoin(final, src)
        if urllib.parse.urlsplit(script_url).hostname != final_host or count >= MAX_SCRIPTS:
            continue
        count += 1
        try:
            js = _open(script_url, ctx)
        except (OSError, urllib.error.URLError):
            continue
        if js.status == 200:
            findings += _scan_secrets(script_url, js.body[:MAX_SCRIPT_SCAN].decode("utf-8", "ignore"), script_url)

    threshold = SEVERITY_ORDER[min_severity]
    unique, seen = [], set()
    for f in findings:
        key = (f.rule_id, f.name, f.file, f.snippet)
        if key not in seen and SEVERITY_ORDER[f.severity] >= threshold:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.rule_id, x.file))
    return unique
