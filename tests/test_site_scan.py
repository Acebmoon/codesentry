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
    run_menu(_feed(["3", server, "y", "b", "7"]), lines.append)
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
