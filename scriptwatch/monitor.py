"""Scan pages, compare with the last known-good baseline, and report what changed."""

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from . import signals as S
from . import web

RULES = {
    "SW001": "Card skimmer behaviour",
    "SW002": "Crypto wallet swapping",
    "SW003": "Hidden code that loads or sends more",
    "SW004": "Screen capture sent out",
    "SW005": "Talks to a raw IP address",
    "SW006": "Extra code only for iPhones and iPads",
    "SW007": "Watches form typing",
    "SW008": "Reads cookies and sends data",
    "SW009": "Hides from developer tools",
    "SW010": "Large encoded blob",
    "SW011": "New third-party script",
    "SW012": "Script changed",
    "SW013": "Script talks to new domains",
    "SW014": "Script loaded over plain HTTP",
    "SW015": "No Content-Security-Policy for scripts",
    "SW016": "Pinned library without integrity check",
    "SW017": "Script couldn't be fetched",
}
ORDER = {"high": 2, "medium": 1, "low": 0}
PINNED_CDN = re.compile(r"(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|"
                        r"ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com)/.*\d+\.\d+")


@dataclass
class Finding:
    rule: str
    severity: str
    page: str
    script: str
    message: str
    evidence: str = ""


@dataclass
class ScriptRecord:
    url: str
    sha256: str = ""
    size: int = 0
    loaded_by: str = ""          # page or parent script
    third_party: bool = True
    fingerprints: Set[Tuple[str, str]] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    error: str = ""

    def to_json(self, first_seen: str) -> dict:
        return {"sha256": self.sha256, "size": self.size, "loaded_by": self.loaded_by,
                "third_party": self.third_party, "first_seen": first_seen,
                "fingerprints": sorted(list(f) for f in self.fingerprints), "domains": sorted(self.domains)}


@dataclass
class PageResult:
    url: str
    scripts: Dict[str, ScriptRecord] = field(default_factory=dict)
    inline_fp: Set[Tuple[str, str]] = field(default_factory=set)
    csp: str = ""
    findings: List[Finding] = field(default_factory=list)
    error: str = ""
    removed: List[str] = field(default_factory=list)


# ------------------------------------------------------------------ baseline

def load_baseline(path: Optional[str]) -> dict:
    if not path or not os.path.exists(path):
        return {"version": 1, "pages": {}}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("version") != 1:
        raise ValueError(f"{path}: unsupported baseline version")
    return data


def save_baseline(path: str, results: List[PageResult], old: dict):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pages = dict(old.get("pages", {}))
    for r in results:
        if r.error:
            continue
        prev = pages.get(r.url, {}).get("scripts", {})
        pages[r.url] = {
            "checked": now,
            "csp": r.csp,
            "inline_fingerprints": sorted(list(f) for f in r.inline_fp),
            "scripts": {u: s.to_json(prev.get(u, {}).get("first_seen", now)) for u, s in sorted(r.scripts.items())
                        if not s.error},
        }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "tool": "scriptwatch", "pages": pages}, fh, indent=1, sort_keys=True)
        fh.write("\n")


# ------------------------------------------------------------------ scanning

class Scanner:
    def __init__(self, fetcher=web.fetch, depth: int = 1, max_scripts: int = 60):
        self.fetch = fetcher
        self.depth = depth
        self.max_scripts = max_scripts

    def scan(self, url: str, baseline: dict) -> PageResult:
        res = PageResult(url)
        try:
            resp = self.fetch(url)
        except web.FetchError as e:
            res.error = f"couldn't load the page: {e}"
            return res
        page = web.parse_page(resp)
        res.csp = page.csp
        base = baseline.get("pages", {}).get(url, {})
        known = base.get("scripts", {})
        known_hosts = {web.host_of(u) for u in known}

        # inline scripts: judged together, compared with the baseline's inline behaviour
        inline_hits: List[S.Hit] = []
        for st in page.scripts:
            if st.src is None:
                inline_hits += S.scan(st.inline)
        res.inline_fp = S.fingerprints(inline_hits)
        old_inline = {tuple(x) for x in base.get("inline_fingerprints", [])}
        if base:
            added = S.new_hits(old_inline, inline_hits)
            for c in S.judge(inline_hits, web.host_of(url), added=added):
                res.findings.append(Finding(c.rule, c.severity, url, "inline <script>", c.message, c.evidence))
        else:
            for c in S.judge(inline_hits, web.host_of(url)):
                res.findings.append(Finding(c.rule, c.severity, url, "inline <script>", c.message, c.evidence))

        queue = [(st.src, url, st, 0) for st in page.scripts if st.src]
        seen: Set[str] = set()
        while queue and len(res.scripts) < self.max_scripts:
            src, parent, tag, level = queue.pop(0)
            if src in seen:
                continue
            seen.add(src)
            rec = ScriptRecord(src, loaded_by=parent, third_party=web.third_party(src, url))
            res.scripts[src] = rec
            if src.startswith("http://"):
                res.findings.append(Finding("SW014", "high", url, src, "script is loaded over plain HTTP, so anyone on "
                                            "the network path can change it"))
            if not src.startswith(("http://", "https://")):
                continue
            try:
                body = self.fetch(src).body
            except web.FetchError as e:
                rec.error = str(e)
                res.findings.append(Finding("SW017", "low", url, src, f"couldn't fetch the script ({e})"))
                continue
            js = body.decode("utf-8", "replace")
            hits = S.scan(js)
            rec.sha256, rec.size = web.sha256(body), len(body)
            rec.fingerprints, rec.domains = S.fingerprints(hits), S.domains(js)
            self._judge(res, rec, hits, known.get(src), known_hosts, bool(base), tag)
            if level < self.depth:
                for child in S.script_urls(js):
                    if child not in seen:
                        queue.append((child, src, None, level + 1))

        if base:
            res.removed = sorted(set(known) - set(res.scripts))
        third = [s for s in res.scripts.values() if s.third_party]
        if third and not re.search(r"(?:^|;)\s*(?:script-src|default-src)\b", res.csp or ""):
            res.findings.append(Finding("SW015", "low", url, "", f"the page loads {len(third)} third-party script(s) "
                                        "but has no Content-Security-Policy limiting where scripts may come from"))
        return res

    def _judge(self, res: PageResult, rec: ScriptRecord, hits: List[S.Hit], before: Optional[dict],
               known_hosts: Set[str], has_baseline: bool, tag):
        host = web.host_of(rec.url)
        label = rec.url + (f" (loaded by {rec.loaded_by})" if rec.loaded_by != res.url else "")
        if tag is not None and rec.third_party and not tag.integrity and PINNED_CDN.search(rec.url):
            res.findings.append(Finding("SW016", "low", res.url, rec.url,
                                        "a version-pinned library from a public CDN without an integrity attribute; "
                                        "add one so a tampered copy is refused"))
        if not has_baseline:
            for c in S.judge(hits, host):
                res.findings.append(Finding(c.rule, c.severity, res.url, label, c.message, c.evidence))
            return
        if before is None:
            sev = "medium" if rec.third_party and host not in known_hosts else "low"
            res.findings.append(Finding("SW011", sev, res.url, label,
                                        "a script that wasn't there at the last check"
                                        + (" from a host this page never used before" if sev == "medium" else "")))
            for c in S.judge(hits, host):
                res.findings.append(Finding(c.rule, c.severity, res.url, label, c.message, c.evidence))
            return
        if before.get("sha256") == rec.sha256:
            return
        old_fp = {tuple(x) for x in before.get("fingerprints", [])}
        added = S.new_hits(old_fp, hits)
        concerns = S.judge(hits, host, added=added)
        for c in concerns:
            res.findings.append(Finding(c.rule, c.severity, res.url, label, c.message, c.evidence))
        new_domains = sorted(d for d in rec.domains - set(before.get("domains", []))
                             if web.site_of(d) != web.site_of(host))
        if new_domains:
            res.findings.append(Finding("SW013", "high" if concerns else "medium", res.url, label,
                                        f"the script changed and now names {len(new_domains)} new domain(s)",
                                        ", ".join(new_domains[:6])))
        if not concerns and not new_domains:
            res.findings.append(Finding("SW012", "low", res.url, label,
                                        f"content changed ({before.get('size', 0):,} -> {rec.size:,} bytes) "
                                        "without new risky behaviour"))
