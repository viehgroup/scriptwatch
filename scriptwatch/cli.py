import argparse
import os
import sys
import urllib.parse
from typing import List

from . import __version__, report
from . import signals as S
from . import web
from .monitor import ORDER, RULES, Finding, PageResult, Scanner, load_baseline, save_baseline

COMMANDS = {"scan", "file", "diff", "rules"}


def build_parser():
    p = argparse.ArgumentParser(prog="scriptwatch",
                                description="Catch hacked third-party scripts on your website: lists every script "
                                            "a page loads and flags new scripts, changes and skimmer-like behaviour.",
                                epilog="Shortcut: `scriptwatch URL...` is the same as `scriptwatch scan URL...`.")
    p.add_argument("--version", action="version", version=f"scriptwatch {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json", "sarif", "github", "markdown"], default="text")
    common.add_argument("-o", "--output")
    common.add_argument("--summary", metavar="FILE", help="also append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    common.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high")
    common.add_argument("--all", action="store_true", help="also show low-severity notes")
    common.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", parents=[common], help="check pages of a site you run")
    s.add_argument("urls", nargs="+")
    s.add_argument("--baseline", default=".scriptwatch/baseline.json",
                   help="known-good state to compare with (default: .scriptwatch/baseline.json)")
    s.add_argument("--update", action="store_true", help="save today's scripts as the new baseline")
    s.add_argument("--depth", type=int, default=1, help="follow script URLs inside scripts this many levels (default 1)")
    s.add_argument("--insecure", action="store_true", help="don't verify TLS certificates (staging sites)")
    s.add_argument("--user-agent", metavar="UA",
                   help="fetch as this browser; 'iphone', 'android' and 'desktop' are shortcuts. Attackers often "
                        "serve malicious code only to some visitors")
    f = sub.add_parser("file", parents=[common], help="check a JavaScript file")
    f.add_argument("path")
    d = sub.add_parser("diff", parents=[common], help="compare two versions of a script")
    d.add_argument("old")
    d.add_argument("new")
    sub.add_parser("rules", help="list all rules")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "scan")
    try:
        return _main(argv)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130


def normalize(url: str) -> str:
    """example.com, https://example.com and https://example.com/ are one page in the baseline."""
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "rules":
        for rid, title in RULES.items():
            print(f"{rid}  {title}")
        return 0
    results: List[PageResult] = []
    baseline_used = True
    if args.cmd == "scan":
        try:
            baseline = load_baseline(args.baseline)
        except (OSError, ValueError) as e:
            print(f"scriptwatch: {e}", file=sys.stderr)
            return 2
        baseline_used = bool(baseline.get("pages"))
        ua = web.USER_AGENTS.get((args.user_agent or "").lower(), args.user_agent) or web.UA
        fetcher = web.fetch if (not args.insecure and ua == web.UA) else \
            (lambda u: web.fetch(u, insecure=args.insecure, user_agent=ua))
        scanner = Scanner(fetcher, depth=max(0, args.depth))
        for url in args.urls:
            results.append(scanner.scan(normalize(url), baseline))
        if args.update:
            ok = [r for r in results if not r.error]
            if ok:
                save_baseline(args.baseline, results, baseline)
                skipped = len(results) - len(ok)
                print(f"scriptwatch: baseline saved to {args.baseline} for {len(ok)} page(s)"
                      + (f"; {skipped} page(s) couldn't be loaded and kept their previous baseline" if skipped else ""),
                      file=sys.stderr)
            else:
                print("scriptwatch: no page could be loaded, so the baseline was not changed", file=sys.stderr)
    elif args.cmd == "file":
        r = PageResult(args.path)
        for c in S.judge(S.scan(_read(args.path)), ""):
            r.findings.append(Finding(c.rule, c.severity, args.path, "", c.message, c.evidence))
        results.append(r)
    else:
        old, new = _read(args.old), _read(args.new)
        r = PageResult(f"{args.old} -> {args.new}")
        new_hits = S.scan(new)
        added = S.new_hits(S.fingerprints(S.scan(old)), new_hits)
        for c in S.judge(new_hits, "", added=added):
            r.findings.append(Finding(c.rule, c.severity, r.url, "", c.message, c.evidence))
        nd = sorted(S.domains(new) - S.domains(old))
        if nd:
            r.findings.append(Finding("SW013", "medium", r.url, "", f"names {len(nd)} new domain(s)", ", ".join(nd[:6])))
        results.append(r)

    if args.format == "json":
        out = report.as_json(results)
    elif args.format == "sarif":
        out = report.sarif(results)
    elif args.format == "github":
        out = report.github(results)
    elif args.format == "markdown":
        out = report.markdown(results)
    else:
        color = not args.output and sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        out = report.text(results, color, args.all, baseline_used if args.cmd == "scan" else True,
                          saved=args.cmd == "scan" and args.update)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    elif out:
        print(out)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(report.markdown(results) + "\n")
    if args.fail_on == "never":
        return 0
    if results and all(r.error for r in results):
        return 2  # nothing could be checked
    return 1 if report.worst(results) >= ORDER[args.fail_on] else 0
