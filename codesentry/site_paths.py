# site_paths.py
# Well-known paths that should never be public. Each one is only reported when the content
# matches what the file really looks like, so a custom 404 page or a single-page app that
# answers 200 for everything does not produce false alarms.

import re
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Tuple

from .scan_engine import Finding
from .site_http import open_url

WORKERS = 6


def _has(*needles: bytes) -> Callable[[bytes], bool]:
    return lambda b: all(n in b for n in needles)


def _any(*needles: bytes) -> Callable[[bytes], bool]:
    return lambda b: any(n in b for n in needles)


def _re(pattern: str) -> Callable[[bytes], bool]:
    rx = re.compile(pattern.encode())
    return lambda b: bool(rx.search(b))


def _not_html(check: Callable[[bytes], bool]) -> Callable[[bytes], bool]:
    return lambda b: b"<html" not in b[:600].lower() and b"<!doctype" not in b[:100].lower() and check(b)


_ENV = _not_html(_re(r"(?m)^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S")) 
_SQL = _re(r"(?i)create table|insert into|drop table")
_LOG = _not_html(_re(r"(?m)^\[?\d{2,4}[-/ :]|\[error\]|PHP (?:Warning|Fatal|Notice)|Stack trace|Traceback|ERROR"))
_PHPINFO = _any(b"phpinfo()", b"PHP Version")
_LISTING = _re(r"(?i)<title>\s*index of /")

# path, name, severity, cwe, check, fix
_REMOVE = "Remove it from the web root or block the path in the server configuration."
_CATALOG: List[Tuple[str, str, str, str, Callable[[bytes], bool], str]] = [
    # version control and editors
    ("/.git/HEAD", "Git repository exposed", "HIGH", "CWE-538", lambda b: b.startswith(b"ref:"), _REMOVE),
    ("/.git/config", "Git configuration exposed", "HIGH", "CWE-538", _has(b"[core]"), _REMOVE),
    ("/.svn/entries", "Subversion metadata exposed", "MEDIUM", "CWE-538", _has(b"\ndir\n"), _REMOVE),
    ("/.hg/hgrc", "Mercurial configuration exposed", "MEDIUM", "CWE-538", _has(b"[paths]"), _REMOVE),
    ("/.idea/workspace.xml", "IDE project file exposed", "LOW", "CWE-538", _has(b"<project"), _REMOVE),
    ("/.DS_Store", "macOS metadata file exposed", "LOW", "CWE-538", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"), _REMOVE),
    # secrets and configuration
    ("/.env", "Environment file exposed", "HIGH", "CWE-538", _ENV, _REMOVE),
    ("/.env.local", "Environment file exposed", "HIGH", "CWE-538", _ENV, _REMOVE),
    ("/.env.production", "Environment file exposed", "HIGH", "CWE-538", _ENV, _REMOVE),
    ("/.env.backup", "Environment file exposed", "HIGH", "CWE-538", _ENV, _REMOVE),
    ("/.htpasswd", "Password file exposed", "HIGH", "CWE-538", _re(r"(?m)^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\})"), _REMOVE),
    ("/.htaccess", "Apache .htaccess exposed", "MEDIUM", "CWE-538", _re(r"RewriteEngine|AuthType|<IfModule"), _REMOVE),
    ("/.npmrc", "npm credentials exposed", "HIGH", "CWE-538", _any(b"_authToken", b"//registry"), _REMOVE),
    ("/.aws/credentials", "AWS credentials exposed", "HIGH", "CWE-538", _has(b"aws_access_key_id"), _REMOVE),
    ("/.ssh/id_rsa", "Private SSH key exposed", "HIGH", "CWE-538", _has(b"PRIVATE KEY"), _REMOVE),
    ("/id_rsa", "Private SSH key exposed", "HIGH", "CWE-538", _has(b"PRIVATE KEY"), _REMOVE),
    ("/.bash_history", "Shell history exposed", "HIGH", "CWE-538",
     _not_html(_re(r"(?m)^(?:cd|ls|sudo|git|ssh|cat|vim|nano|mysql|curl|wget)\b")), _REMOVE),
    ("/sftp-config.json", "SFTP credentials exposed", "HIGH", "CWE-538", _has(b'"host"', b'"user'), _REMOVE),
    ("/web.config", "IIS web.config exposed", "MEDIUM", "CWE-538", _has(b"<configuration"), _REMOVE),
    ("/appsettings.json", "ASP.NET settings exposed", "HIGH", "CWE-538", _has(b"ConnectionStrings"), _REMOVE),
    ("/application.properties", "Spring properties exposed", "HIGH", "CWE-538",
     _re(r"(?m)^(?:spring|server)\.[\w.]+\s*="), _REMOVE),
    ("/wp-config.php.bak", "WordPress config backup exposed", "HIGH", "CWE-538", _has(b"DB_PASSWORD"), _REMOVE),
    ("/wp-config.php~", "WordPress config backup exposed", "HIGH", "CWE-538", _has(b"DB_PASSWORD"), _REMOVE),
    ("/config.php.bak", "Config backup exposed", "HIGH", "CWE-538", _has(b"<?php"), _REMOVE),
    ("/config.php~", "Config backup exposed", "HIGH", "CWE-538", _has(b"<?php"), _REMOVE),
    ("/docker-compose.yml", "Docker compose file exposed", "MEDIUM", "CWE-538", _has(b"services:"), _REMOVE),
    ("/Dockerfile", "Dockerfile exposed", "MEDIUM", "CWE-538", lambda b: b.lstrip().startswith(b"FROM "), _REMOVE),
    ("/.gitlab-ci.yml", "CI configuration exposed", "LOW", "CWE-538", _any(b"stages:", b"script:"), _REMOVE),
    ("/.travis.yml", "CI configuration exposed", "LOW", "CWE-538", _has(b"language:"), _REMOVE),
    ("/composer.json", "Composer manifest exposed", "LOW", "CWE-538", _has(b'"require"'), _REMOVE),
    ("/package.json", "npm manifest exposed", "LOW", "CWE-538", _any(b'"dependencies"', b'"devDependencies"'), _REMOVE),
    # dumps, backups and logs
    ("/backup.sql", "Database dump exposed", "HIGH", "CWE-538", _SQL, _REMOVE),
    ("/dump.sql", "Database dump exposed", "HIGH", "CWE-538", _SQL, _REMOVE),
    ("/db.sql", "Database dump exposed", "HIGH", "CWE-538", _SQL, _REMOVE),
    ("/database.sql", "Database dump exposed", "HIGH", "CWE-538", _SQL, _REMOVE),
    ("/users.sql", "Database dump exposed", "HIGH", "CWE-538", _SQL, _REMOVE),
    ("/backup.zip", "Backup archive exposed", "HIGH", "CWE-538", lambda b: b.startswith(b"PK"), _REMOVE),
    ("/site.zip", "Backup archive exposed", "HIGH", "CWE-538", lambda b: b.startswith(b"PK"), _REMOVE),
    ("/www.zip", "Backup archive exposed", "HIGH", "CWE-538", lambda b: b.startswith(b"PK"), _REMOVE),
    ("/backup.tar.gz", "Backup archive exposed", "HIGH", "CWE-538", lambda b: b.startswith(b"\x1f\x8b"), _REMOVE),
    ("/error_log", "Error log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/error.log", "Error log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/debug.log", "Debug log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/php_errors.log", "Error log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/npm-debug.log", "Debug log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/logs/error.log", "Error log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/storage/logs/laravel.log", "Laravel log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/wp-content/debug.log", "WordPress debug log exposed", "MEDIUM", "CWE-532", _LOG, _REMOVE),
    ("/access.log", "Access log exposed", "MEDIUM", "CWE-532", _re(r'"(?:GET|POST|HEAD) /'), _REMOVE),
    # server and framework internals
    ("/phpinfo.php", "phpinfo() page exposed", "MEDIUM", "CWE-200", _PHPINFO, _REMOVE),
    ("/info.php", "phpinfo() page exposed", "MEDIUM", "CWE-200", _PHPINFO, _REMOVE),
    ("/server-status", "Apache server-status exposed", "MEDIUM", "CWE-200", _has(b"Apache Server Status"), _REMOVE),
    ("/server-info", "Apache server-info exposed", "MEDIUM", "CWE-200", _has(b"Apache Server Information"), _REMOVE),
    ("/elmah.axd", "ELMAH error log exposed", "HIGH", "CWE-532", _has(b"Error Log for"), _REMOVE),
    ("/trace.axd", "ASP.NET trace exposed", "HIGH", "CWE-200", _has(b"Application Trace"), _REMOVE),
    ("/actuator", "Spring Boot Actuator exposed", "MEDIUM", "CWE-200", _has(b'"_links"', b"actuator"), "Restrict actuator endpoints to internal networks."),
    ("/actuator/env", "Spring Boot environment exposed", "HIGH", "CWE-200", _has(b"propertySources"), "Disable or protect /actuator/env."),
    ("/actuator/mappings", "Spring Boot mappings exposed", "MEDIUM", "CWE-200", _has(b"dispatcherServlet"), "Restrict actuator endpoints."),
    ("/env", "Spring Boot environment exposed", "HIGH", "CWE-200", _has(b"systemProperties"), "Disable or protect /env."),
    ("/metrics", "Prometheus metrics exposed", "MEDIUM", "CWE-200", _has(b"# HELP"), "Serve metrics on an internal port only."),
    ("/debug/pprof/", "Go pprof profiler exposed", "HIGH", "CWE-489", _has(b"Types of profiles available"), "Never expose pprof publicly."),
    ("/_profiler/", "Symfony profiler exposed", "HIGH", "CWE-489", _has(b"Symfony Profiler"), "Disable the profiler in production."),
    ("/telescope", "Laravel Telescope exposed", "MEDIUM", "CWE-489", _has(b"Laravel Telescope"), "Restrict Telescope or disable it in production."),
    ("/console", "Interactive debug console exposed", "HIGH", "CWE-489", _has(b"Interactive Console"), "Turn debug mode off in production."),
    ("/h2-console", "H2 database console exposed", "HIGH", "CWE-489", _has(b"H2 Console"), "Disable the H2 console in production."),
    ("/manager/html", "Tomcat manager exposed", "MEDIUM", "CWE-284", _has(b"Tomcat Web Application Manager"), "Restrict the manager to internal networks."),
    ("/graphiql", "GraphiQL explorer exposed", "MEDIUM", "CWE-200", _has(b"GraphiQL"), "Disable GraphiQL in production."),
    # API documentation
    ("/swagger.json", "API documentation exposed", "LOW", "CWE-200", _has(b'"swagger"', b'"paths"'), "Hide API docs in production or require authentication."),
    ("/openapi.json", "API documentation exposed", "LOW", "CWE-200", _has(b'"openapi"', b'"paths"'), "Hide API docs in production or require authentication."),
    ("/v2/api-docs", "API documentation exposed", "LOW", "CWE-200", _has(b'"swagger"', b'"paths"'), "Hide API docs in production or require authentication."),
    ("/v3/api-docs", "API documentation exposed", "LOW", "CWE-200", _has(b'"openapi"', b'"paths"'), "Hide API docs in production or require authentication."),
    ("/swagger-ui.html", "Swagger UI exposed", "LOW", "CWE-200", _has(b"Swagger UI"), "Hide API docs in production or require authentication."),
    ("/docs", "Swagger UI exposed", "LOW", "CWE-200", _has(b"Swagger UI"), "Hide API docs in production or require authentication."),
    ("/redoc", "ReDoc API documentation exposed", "LOW", "CWE-200", _has(b"ReDoc"), "Hide API docs in production or require authentication."),
    # admin panels and CMS
    ("/phpmyadmin/", "phpMyAdmin exposed", "MEDIUM", "CWE-284", _has(b"phpMyAdmin"), "Restrict it by IP or remove it."),
    ("/adminer.php", "Adminer exposed", "MEDIUM", "CWE-284", _has(b"Adminer"), "Remove it from production."),
    ("/wp-login.php", "WordPress login page reachable", "LOW", "CWE-200", _any(b"wp-submit", b"user_login"), "Restrict wp-login.php (IP, 2FA, rate limit)."),
    ("/wp-json/wp/v2/users", "WordPress user list public", "MEDIUM", "CWE-200", _has(b'"slug"'), "Disable the users REST endpoint for anonymous visitors."),
    ("/xmlrpc.php", "WordPress XML-RPC enabled", "LOW", "CWE-749", _has(b"XML-RPC server accepts POST requests only"), "Disable xmlrpc.php if you do not use it."),
    ("/readme.html", "WordPress readme exposed", "LOW", "CWE-200", _has(b"WordPress", b"Version"), "Delete readme.html."),
    ("/administrator/", "Joomla administrator login reachable", "LOW", "CWE-200", _has(b"Joomla"), "Restrict the administrator area."),
    ("/crossdomain.xml", "Flash cross-domain policy allows any domain", "MEDIUM", "CWE-942", _has(b'domain="*"'), "List only trusted domains."),
]

# folders where a listing is never wanted
_FOLDERS = ("/uploads/", "/upload/", "/backup/", "/backups/", "/files/", "/logs/", "/tmp/", "/old/", "/private/")


def _probe(args) -> List[Finding]:
    base, ctx, path, name, sev, cwe, check, fix = args
    target = urllib.parse.urljoin(base, path)
    try:
        resp = open_url(target, ctx, follow=False, max_body=200_000)
    except (OSError, urllib.error.URLError):
        return []
    if resp.status == 200 and resp.body and check(resp.body):
        return [Finding("CS-WEB-021", name, sev, cwe, target, 1, f"{path} returned matching content", fix)]
    return []


def scan_paths(base: str, ctx) -> List[Finding]:
    jobs = [(base, ctx, p, n, s, c, ck, fx) for p, n, s, c, ck, fx in _CATALOG]
    jobs += [(base, ctx, f, "Directory listing enabled", "MEDIUM", "CWE-548", _LISTING,
              "Disable directory listing (Options -Indexes, autoindex off).") for f in _FOLDERS]
    out: List[Finding] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for found in pool.map(_probe, jobs):
            out += found
    return out


_ROBOTS_WORDS = re.compile(r"(?i)admin|backup|private|secret|internal|staging|config|\.git|dump|database|\bdb\b|upload|\btmp\b|\bold\b")


def scan_robots(base: str, ctx) -> List[Finding]:
    target = urllib.parse.urljoin(base, "/robots.txt")
    try:
        resp = open_url(target, ctx, follow=False, max_body=100_000)
    except (OSError, urllib.error.URLError):
        return []
    text = resp.body.decode("utf-8", "ignore")
    if resp.status != 200 or "<html" in text[:500].lower():
        return []
    paths = []
    for line in text.splitlines():
        m = re.match(r"(?i)\s*disallow\s*:\s*(\S+)", line)
        if m and _ROBOTS_WORDS.search(m.group(1)):
            paths.append(m.group(1))
    if not paths:
        return []
    return [Finding("CS-WEB-022", "robots.txt points to sensitive-looking paths", "LOW", "CWE-200", target, 1,
                    ", ".join(paths[:5]),
                    "robots.txt is public: do not use it to hide paths, protect them with authentication instead.")]
