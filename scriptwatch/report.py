import json
import shutil
import textwrap
from typing import List

from . import __version__
from .monitor import ORDER, RULES, PageResult

_C = {"high": "31", "medium": "33", "low": "36", "dim": "2", "bold": "1", "ok": "32"}
_ICON = {"high": "🔴", "medium": "🟠", "low": "🔵"}


def _p(on: bool):
    return lambda s, k: f"\033[{_C[k]}m{s}\033[0m" if on else s


def _shown(r: PageResult, show_all: bool):
    return sorted([f for f in r.findings if show_all or f.severity != "low"], key=lambda f: -ORDER[f.severity])


def text(results: List[PageResult], color: bool, show_all: bool = False, baseline_used: bool = True,
         saved: bool = False) -> str:
    p = _p(color)
    width = min(100, shutil.get_terminal_size((80, 24)).columns)
    out = []
    for r in results:
        worst = max((f.severity for f in r.findings), key=lambda s: ORDER[s], default=None)
        if r.error:
            head = p("?  COULDN'T CHECK", "medium")
        elif worst == "high":
            head = p("⚠️  DANGER", "high")
        elif worst == "medium":
            head = p("⚠️  REVIEW", "medium")
        else:
            head = p("✅ OK", "ok")
        third = sum(1 for s in r.scripts.values() if s.third_party)
        out.append(f"{head}  {p(r.url, 'bold')}")
        if r.error:
            out.append("    " + r.error)
            out.append("")
            continue
        out.append(p(f"    {len(r.scripts)} external script(s), {third} from other companies", "dim"))
        for f in _shown(r, show_all):
            out.append(f"  {p(f'{f.severity:<6}', f.severity)} {f.rule}  {RULES[f.rule]}")
            if f.script:
                for line in textwrap.wrap(f.script, width - 6, break_long_words=True):
                    out.append("      " + p(line, "dim"))
            for line in textwrap.wrap(f.message[0].upper() + f.message[1:], width - 6):
                out.append("      " + line)
            if f.evidence:
                for line in textwrap.wrap("Evidence: " + f.evidence, width - 6, break_long_words=True):
                    out.append("      " + p(line, "dim"))
        hidden = len(r.findings) - len(_shown(r, show_all))
        if hidden:
            out.append("    " + p(f"({hidden} low-severity note(s); --all shows them)", "dim"))
        if r.removed:
            out.append("    " + p(f"{len(r.removed)} script(s) from the baseline are no longer loaded", "dim"))
        out.append("")
    if not baseline_used and saved and any(not r.error for r in results):
        out.extend(textwrap.wrap("Baseline saved. From now on, any script that's added, changes or gains risky "
                                 "behaviour will be flagged.", width))
    elif not baseline_used:
        out.extend(textwrap.wrap("No baseline yet, so only strong patterns were checked. Save one with --update; "
                                 "later runs then flag any script that changes or gains risky behaviour.", width))
    return "\n".join(out).rstrip()


def markdown(results: List[PageResult]) -> str:
    lines = ["## scriptwatch"]
    flagged = [r for r in results if r.error or any(f.severity != "low" for f in r.findings)]
    if not flagged:
        lines.append(f"✅ {len(results)} page(s) checked. No suspicious script changes.")
    for r in flagged:
        lines.append(f"\n### {r.url}")
        if r.error:
            lines.append(f"Couldn't check: {r.error}")
            continue
        lines.append("| | Finding | Script | Details |\n|---|---|---|---|")
        for f in _shown(r, False):
            details = (f.message + (f" ({f.evidence})" if f.evidence else "")).replace("|", "\\|")
            lines.append(f"| {_ICON[f.severity]} | {f.rule} {RULES[f.rule]} | `{f.script[:80]}` | {details} |")
    lines.append(f"\n<sub>scriptwatch {__version__}</sub>")
    return "\n".join(lines) + "\n"


def as_json(results: List[PageResult]) -> str:
    return json.dumps({"version": __version__, "pages": [{
        "url": r.url, "error": r.error, "csp": r.csp, "removed": r.removed,
        "scripts": [{"url": s.url, "sha256": s.sha256, "size": s.size, "third_party": s.third_party,
                     "loaded_by": s.loaded_by, "error": s.error} for s in r.scripts.values()],
        "findings": [f.__dict__ for f in r.findings]} for r in results]}, indent=2)


def sarif(results: List[PageResult]) -> str:
    level = {"high": "error", "medium": "warning", "low": "note"}
    used = sorted({f.rule for r in results for f in r.findings})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "scriptwatch", "version": __version__,
                            "informationUri": "https://github.com/viehgroup/scriptwatch",
                            "rules": [{"id": u, "name": RULES[u].replace(" ", ""),
                                       "shortDescription": {"text": RULES[u]}} for u in used]}},
        "results": [{"ruleId": f.rule, "level": level[f.severity],
                     "message": {"text": f"{f.page}: {f.script} {f.message} {f.evidence}".strip()},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.page}}}]}
                    for r in results for f in r.findings]}]}, indent=2)


def github(results: List[PageResult]) -> str:
    kind = {"high": "error", "medium": "warning", "low": "notice"}

    def esc(s):
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    return "\n".join(
        f"::{kind[f.severity]} title={esc(f.rule + ' ' + RULES[f.rule]).replace(':', '%3A').replace(',', '%2C')}::"
        + esc(f"{f.page}: {f.script} {f.message}" + (f" ({f.evidence})" if f.evidence else ""))
        for r in results for f in r.findings)


def worst(results: List[PageResult]) -> int:
    sevs = [ORDER[f.severity] for r in results for f in r.findings]
    return max(sevs) if sevs else -1
