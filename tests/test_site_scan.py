# tests/test_site_scan.py
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from codesentry import site_scan
from codesentry.cli_main import main
from codesentry.menu_ui import run_menu
from codesentry.site_scan import SiteError, normalize_url, scan_site

_KEY = "AKIA" + "IOSFODNN7EXAMPLE"

_PAGE = f"""<html><head><title>Test</title><meta name="generator" content="WordPress 4.1">
<script src="/app.js"></script><script src="https://cdn.example.net/lib.js"></script></head>
<body><form method="post" action="/login"><input type="password" name="pw"></form>
You have an error in your SQL syntax near 'x'
</body></html>"""


class _Vulnerable(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body, extra=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(200, "", [("Allow", "GET, POST, PUT, DELETE, TRACE")])

    def do_GET(self):
        origin = self.headers.get("Origin")
        if self.path == "/.env":
            self._send(200, "DB_HOST=localhost\nDB_PASS=hunter2\n")
        elif self.path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n")
        elif self.path == "/app.js":
            self._send(200, f'var cfg = {{ key: "{_KEY}" }};')
        elif self.path == "/":
            extra = [("Server", "Apache/2.4.1"), ("X-Powered-By", "PHP/5.6"), ("Set-Cookie", "PHPSESSID=abc; Path=/")]
            if origin:
                extra += [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            self._send(200, _PAGE, extra)
        else:
            self._send(404, "<html>Not Found</html>")


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Vulnerable)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}/"
    httpd.shutdown()


def test_finds_the_usual_problems(server):
    found = scan_site(server)
    names = {f.name for f in found}
    ids = {f.rule_id for f in found}
    assert "Environment file exposed" in names and "Git repository exposed" in names
    assert {"CS-WEB-005", "CS-WEB-006", "CS-WEB-007", "CS-WEB-009", "CS-WEB-011", "CS-WEB-012",
            "CS-WEB-013", "CS-WEB-014", "CS-WEB-016", "CS-WEB-018", "CS-WEB-020"} <= ids
    assert any(f.rule_id.startswith("CS-SEC") and f.file.endswith("/app.js") for f in found)
    assert any(f.rule_id == "CS-WEB-001" and f.severity == "LOW" for f in found)     # local dev site: low
    assert "CS-WEB-004" not in ids                                                    # HSTS is https only
    secret_text = " ".join(f.snippet for f in found)
    assert _KEY not in secret_text                                                    # secrets are masked
    assert any(f.name == "CORS reflects any origin with credentials" and f.severity == "HIGH" for f in found)


def test_min_severity_filters(server):
    assert all(f.severity == "HIGH" for f in scan_site(server, "HIGH"))


def test_soft_404_pages_are_not_reported(server):
    # every missing path answers 200 with an HTML page: signatures must still reject it
    class Soft(_Vulnerable):
        def do_GET(self):
            self._send(200, "<html><body>Welcome</body></html>")
    httpd = HTTPServer(("127.0.0.1", 0), Soft)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        found = scan_site(f"http://127.0.0.1:{httpd.server_port}/")
    finally:
        httpd.shutdown()
    assert not any(f.rule_id == "CS-WEB-021" for f in found)


def test_unreachable_site_is_a_readable_error():
    with pytest.raises(SiteError):
        scan_site("http://127.0.0.1:1/")


def test_normalize_url():
    assert normalize_url("example.com") == "https://example.com/"
    assert normalize_url(' "http://a.b/x?y=1" ') == "http://a.b/x?y=1"
    for bad in ("", "ftp://x.y", "   "):
        with pytest.raises(SiteError):
            normalize_url(bad)


def test_cli_requires_permission_flag(server, capsys):
    assert main(["--site", server]) == 2
    assert "--i-have-permission" in capsys.readouterr().err


def test_cli_site_json(server, capsys):
    code = main(["--site", server, "--i-have-permission", "-f", "json"])
    assert code == 1 and "CS-WEB-021" in capsys.readouterr().out


def _feed(answers):
    it = iter(answers)
    return lambda prompt="": next(it)


def test_menu_asks_for_permission(server):
    lines = []
    run_menu(_feed(["3", server, "n", "", "7"]), lines.append)
    assert any("permission" in l for l in lines) and not any("CS-WEB" in l for l in lines)


def test_menu_scans_site(server):
    lines = []
    run_menu(_feed(["3", server, "y", "n", "b", "7"]), lines.append)
    assert any("Total:" in l for l in lines) and any("CS-WEB" in l for l in lines)


def test_menu_back_from_site_screen():
    run_menu(_feed(["3", "b", "7"]), lambda s: None)


def test_expired_or_untrusted_certificate_is_reported(monkeypatch):
    import ssl

    def boom(*a, **k):
        err = ssl.SSLCertVerificationError(1, "certificate verify failed")
        err.verify_message = "self-signed certificate"
        raise err

    monkeypatch.setattr(site_scan.socket, "create_connection", boom)
    found, ok = site_scan._scan_tls("example.test", 443, "https://example.test/")
    assert not ok and found[0].severity == "HIGH" and "self-signed" in found[0].snippet


# ---------------------------------------------------------------- v0.8.1: deeper checks
import base64
import json as _json


def _jwt(payload):
    enc = lambda d: base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'HS256'})}.{enc(payload)}.{'s' * 20}"


class _Deep(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="text/html"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self._send(200, """<html><head><script src="/assets/app.js"></script>
            <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script></head>
            <body><!-- TODO remove the admin password before launch -->
            <form method="get" action="/login"><input type="password" name="pw"></form></body></html>""")
        elif self.path == "/assets/app.js":
            self._send(200, f'const s="{_jwt({"role": "service_role", "iss": "supabase"})}";'
                            f'const a="{_jwt({"role": "anon", "iss": "supabase"})}";'
                            'fetch("http://192.168.1.20:3000/api");\n//# sourceMappingURL=app.js.map',
                       "application/javascript")
        elif self.path == "/assets/app.js.map":
            self._send(200, '{"version":3,"sources":["src/App.tsx"],"mappings":"AAAA"}', "application/json")
        elif self.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin-panel/\nDisallow: /public/", "text/plain")
        elif self.path == "/actuator/env":
            self._send(200, '{"propertySources":[]}', "application/json")
        elif self.path == "/uploads/":
            self._send(200, "<html><head><title>Index of /uploads</title></head></html>")
        else:
            self._send(200, "<html><body>Welcome</body></html>")      # single-page-app style: 200 for everything


@pytest.fixture()
def deep():
    httpd = HTTPServer(("127.0.0.1", 0), _Deep)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}/"
    httpd.shutdown()


def test_deeper_checks(deep):
    found = scan_site(deep)
    by_id = {}
    for f in found:
        by_id.setdefault(f.rule_id, []).append(f)
    assert any(f.severity == "HIGH" and "service_role" in f.name for f in by_id["CS-WEB-030"])
    assert any("anon key" in f.name and f.severity == "LOW" for f in by_id["CS-WEB-031"])
    assert "CS-WEB-032" not in by_id                              # supabase keys are not reported as generic JWTs
    assert by_id["CS-WEB-034"][0].file.endswith("/assets/app.js.map")
    assert any(f.name == "Spring Boot environment exposed" or "Actuator" in f.name or "environment" in f.name
               for f in by_id["CS-WEB-021"])
    assert "CS-WEB-022" in by_id and "/admin-panel/" in by_id["CS-WEB-022"][0].snippet
    assert "CS-WEB-027" in by_id and "password" in by_id["CS-WEB-027"][0].snippet     # words only, never the comment text
    assert "CS-WEB-028" in by_id                                  # password form using GET
    assert any(f.name == "Directory listing enabled" and f.file.endswith("/uploads/") for f in found)
    assert "CS-WEB-025" in by_id and "CS-WEB-026" not in by_id    # no cookies here
    # the key itself is never printed
    assert all(len(f.snippet) <= 12 for f in by_id["CS-WEB-030"] + by_id["CS-WEB-031"])


def test_single_page_app_answering_200_everywhere_gives_no_exposed_files():
    class Spa(_Deep):
        def do_GET(self):
            self._send(200, "<!doctype html><html><body><div id='root'></div></body></html>")
    httpd = HTTPServer(("127.0.0.1", 0), Spa)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        found = scan_site(f"http://127.0.0.1:{httpd.server_port}/")
    finally:
        httpd.shutdown()
    assert not any(f.rule_id in ("CS-WEB-021", "CS-WEB-022") for f in found)


def test_libraries_are_found_and_checked_only_when_asked(deep, monkeypatch):
    from codesentry import site_scan
    seen = []

    def fake(deps, min_severity="LOW"):
        seen.extend((d.name, d.version) for d in deps)
        return []
    monkeypatch.setattr(site_scan, "check_packages", fake)
    scan_site(deep)
    assert seen == []                                             # nothing is sent unless deps=True
    scan_site(deep, deps=True)
    assert ("jquery", "1.12.4") in seen


def test_find_libraries_patterns():
    from codesentry.site_js import find_libraries
    text = ("/*! jQuery JavaScript Library v3.4.1 */ /* axios v0.21.1 | (c) */ //! version : 2.18.1\n"
            "https://cdn.jsdelivr.net/npm/lodash@4.17.4/lodash.min.js @license React v17.0.2")
    libs = dict(find_libraries(text))
    assert libs["jquery"] == "3.4.1" and libs["axios"] == "0.21.1" and libs["lodash"] == "4.17.4"
    assert libs["react"] == "17.0.2"


def test_weak_csp_and_hsts_and_cookie_cache():
    from codesentry.site_scan import _scan_headers, _csp_problems
    from codesentry.site_http import Resp
    from email.message import Message
    m = Message()
    m["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' *"
    m["Strict-Transport-Security"] = "max-age=300"
    m["Set-Cookie"] = "sid=1; Secure; HttpOnly; SameSite=Lax"
    found = _scan_headers("https://x.test/", Resp(200, m, b"", "https://x.test/"), True)
    ids = {f.rule_id for f in found}
    assert {"CS-WEB-023", "CS-WEB-024", "CS-WEB-026"} <= ids
    assert _csp_problems("script-src 'nonce-abc' 'unsafe-inline'") == []     # nonce makes unsafe-inline ignored


def test_internal_addresses_and_google_key_note():
    from codesentry.site_js import scan_internal
    from codesentry.site_scan import _scan_secrets
    assert scan_internal("u", 'fetch("http://localhost:3000/x")')[0].rule_id == "CS-WEB-033"
    key = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
    found = _scan_secrets("u", f'const k="{key}"')
    assert found and found[0].severity == "LOW" and key not in found[0].snippet


def test_check_packages_is_shared_with_the_manifest_check(monkeypatch):
    from codesentry import deps_check
    monkeypatch.setattr(deps_check, "_post", lambda *a: {"results": [{"vulns": [{"id": "GHSA-x"}]}]})
    monkeypatch.setattr(deps_check, "_get", lambda url: {"id": "GHSA-x", "summary": "bad", "database_specific": {"severity": "HIGH"}})
    found = deps_check.check_packages([deps_check.Dep("jquery", "1.12.4", "npm", "jquery 1.12.4 (site)", 1)])
    assert found and found[0].severity == "HIGH" and "jquery 1.12.4" in found[0].name


@pytest.mark.skipif(__import__("shutil").which("openssl") is None, reason="needs the openssl command")
def test_self_signed_https_site_is_reported_and_still_scanned(tmp_path):
    import ssl
    import subprocess
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "30", "-subj", "/CN=localhost"], check=True, capture_output=True)
    httpd = HTTPServer(("127.0.0.1", 0), _Vulnerable)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    warnings = []
    try:
        found = scan_site(f"https://127.0.0.1:{httpd.server_port}/", warnings=warnings)
    finally:
        httpd.shutdown()
    assert any(f.rule_id == "CS-WEB-003" and f.severity == "HIGH" for f in found)
    assert any(f.name == "Environment file exposed" for f in found)          # the scan went on
    assert warnings and "not trusted" in warnings[0]


def test_number_input_without_limits_is_flagged():
    from codesentry.site_js import scan_form_controls
    assert scan_form_controls("u", 'h("input",{type:"number",value:1})')[0].rule_id == "CS-WEB-035"
    assert scan_form_controls("u", '<input type="number" min="1" max="9">') == []
