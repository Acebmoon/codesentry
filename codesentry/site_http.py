# site_http.py
# Plain HTTP helpers shared by the website check: one request, no cookies, optional no-redirect.

import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, NamedTuple, Optional

TIMEOUT = 10
MAX_BODY = 1_500_000
USER_AGENT = "CodeSentry-site-check (passive; https://github.com/Acebmoon/codesentry)"


class SiteError(Exception):
    """A readable problem: bad address, site unreachable."""


class Resp(NamedTuple):
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


def is_local(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def open_url(url: str, ctx, follow: bool = True, method: str = "GET",
             headers: Optional[Dict[str, str]] = None, max_body: int = MAX_BODY) -> Resp:
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return Resp(resp.status, resp.headers, resp.read(max_body), resp.geturl())
    except urllib.error.HTTPError as exc:       # 3xx without follow, 4xx, 5xx still carry data
        try:
            body = exc.read(max_body)
        except OSError:
            body = b""
        return Resp(exc.code, exc.headers, body, url)
