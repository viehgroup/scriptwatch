"""Fetch a page, find the scripts it loads, and fetch those.

Only GET requests, like a browser loading the page. Nothing is executed:
scripts a page adds at runtime are found by following .js URLs written in
the scripts it loads (one level by default), which covers tag managers and
loaders like the Optimizely snippet, but not everything a browser would run.
"""

import gzip
import hashlib
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional

from . import __version__

UA = (f"Mozilla/5.0 (compatible; scriptwatch/{__version__}; +https://github.com/viehgroup/scriptwatch)")
USER_AGENTS = {
    "iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
              "Version/18.5 Mobile/15E148 Safari/604.1",
    "android": "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/141.0.0.0 Mobile Safari/537.36",
    "desktop": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/141.0.0.0 Safari/537.36",
}
MAX_BYTES = 8 * 1024 * 1024


class FetchError(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: Dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        ctype = self.headers.get("content-type", "")
        m = re.search(r"charset=([\w-]+)", ctype)
        try:
            return self.body.decode(m.group(1) if m else "utf-8", "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")


def fetch(url: str, timeout: float = 20, insecure: bool = False, user_agent: str = UA) -> Response:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "*/*",
                                               "Accept-Encoding": "gzip, deflate"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(MAX_BYTES + 1)
            headers = {k.lower(): v for k, v in r.headers.items()}
            status, final = r.status, r.geturl()
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code}") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise FetchError(str(getattr(e, "reason", e))) from e
    if len(body) > MAX_BYTES:
        raise FetchError(f"larger than {MAX_BYTES // 2**20} MB")
    enc = headers.get("content-encoding", "")
    try:
        if "gzip" in enc:
            body = gzip.decompress(body)
        elif "deflate" in enc:
            body = zlib.decompress(body)
    except (OSError, zlib.error) as e:
        raise FetchError(f"bad compressed response: {e}") from e
    return Response(final, status, headers, body)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ HTML

@dataclass
class ScriptTag:
    src: Optional[str]          # absolute URL, None for inline
    inline: str = ""
    integrity: str = ""
    kind: str = "script"        # script, preload, modulepreload


@dataclass
class Page:
    url: str
    scripts: List[ScriptTag] = field(default_factory=list)
    csp: str = ""
    csp_source: str = ""


class _Parser(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.scripts: List[ScriptTag] = []
        self.meta_csp = ""
        self._in_script: Optional[ScriptTag] = None
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs_list):
        a = {k.lower(): (v or "") for k, v in attrs_list}
        if tag == "base" and a.get("href"):
            self.base = urllib.parse.urljoin(self.base, a["href"])
        elif tag == "script":
            stype = a.get("type", "").lower()
            if stype and stype not in ("text/javascript", "application/javascript", "module", "text/ecmascript"):
                return  # JSON-LD, templates and other data blocks aren't code
            src = a.get("src")
            st = ScriptTag(urllib.parse.urljoin(self.base, src) if src else None, integrity=a.get("integrity", ""))
            if src:
                self.scripts.append(st)
            else:
                self._in_script, self._buf = st, []
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if a.get("href") and (rel == "modulepreload" or (rel == "preload" and a.get("as", "").lower() == "script")):
                self.scripts.append(ScriptTag(urllib.parse.urljoin(self.base, a["href"]), integrity=a.get("integrity", ""),
                                              kind=rel))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            self.meta_csp = a.get("content", "")

    def handle_data(self, data):
        if self._in_script is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script is not None:
            self._in_script.inline = "".join(self._buf)
            if self._in_script.inline.strip():
                self.scripts.append(self._in_script)
            self._in_script = None


def parse_page(resp: Response) -> Page:
    p = _Parser(resp.url)
    p.feed(resp.text)
    p.close()
    page = Page(resp.url, p.scripts)
    if resp.headers.get("content-security-policy"):
        page.csp, page.csp_source = resp.headers["content-security-policy"], "header"
    elif p.meta_csp:
        page.csp, page.csp_source = p.meta_csp, "meta tag"
    return page


# ------------------------------------------------------------------ hosts

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ne", "or", "go"}


def site_of(host: str) -> str:
    """Rough registrable domain: www.bbc.co.uk -> bbc.co.uk, cdn.optimizely.com -> optimizely.com."""
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def third_party(script_url: str, page_url: str) -> bool:
    return site_of(host_of(script_url)) != site_of(host_of(page_url))
