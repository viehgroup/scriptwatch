"""What a piece of browser JavaScript can do, as comparable fingerprints.

Third-party scripts legitimately read cookies, watch clicks and send data:
that's what analytics and A/B testing are. So a single capability means
little. What matters is
  * dangerous combinations (card fields + sending data somewhere), and
  * behaviour a script didn't have yesterday, which is how the Optimizely
    compromise of November 2026 would have shown up.
"""

import re
from dataclasses import dataclass
from typing import List, Set, Tuple

PATTERNS = {
    # where data goes
    "send": r"\bnavigator\.sendBeacon\s*\(|\bnew\s+XMLHttpRequest\b|\bfetch\s*\(|\bnew\s+WebSocket\s*\(|"
            r"new\s+Image\s*\(\s*\)\s*\.src\s*=|\.src\s*=\s*['\"`]https?://[^'\"`]+\?[^'\"`]*['\"`]\s*\+",
    "websocket_raw_ip": r"wss?://(?:\d{1,3}\.){3}\d{1,3}",
    "raw_ip_url": r"https?://(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/",
    # what gets taken
    "card_fields": r"\b(?:cc[-_]?(?:num|number|cvv|cvc|exp)|card[-_ ]?(?:number|num|holder|cvc|cvv)|cardnumber|"
                   r"security[-_ ]?code|cvv2?|cvc2?|expir(?:y|ation)[-_ ]?(?:date|month|year))\b",
    "card_regex": r"\^?\(?\?:4\[0-9\]\{12\}|\b4\[0-9\]\{12\}|\[2-5\]\[1-5\]|luhn",
    "form_harvest": r"querySelectorAll\(\s*['\"`](?:input|form|input,\s*select|input\[type)|new\s+FormData\s*\(|"
                    r"\.elements\b[^;]{0,40}\.value",
    "keylog": r"addEventListener\(\s*['\"`](?:keydown|keyup|keypress|input)['\"`]",
    "cookie_read": r"\bdocument\.cookie\b(?!\s*=)",
    "storage_read": r"\blocalStorage\.getItem\s*\(|\bsessionStorage\.getItem\s*\(",
    "clipboard": r"navigator\.clipboard\.(?:writeText|readText)|addEventListener\(\s*['\"`](?:copy|paste)['\"`]|"
                 r"execCommand\(\s*['\"`]copy",
    "wallet_address": r"\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|"
                      r"T[1-9A-HJ-NP-Za-km-z]{33})\b",
    "wallet_regex": r"\[13\]\[a-km-zA-HJ-NP-Z1-9\]|0x\[a-fA-F0-9\]\{40\}|bc1\[|\bethereum\b.{0,40}\breplace\b",
    "screen_capture": r"\bhtml2canvas\b|getDisplayMedia\s*\(|\bdom-to-image\b|\.toDataURL\(\s*['\"`]image/",
    # how it hides or spreads
    "eval_decode": r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(|"
                   r"(?:new\s+)?Function\s*\(\s*atob\s*\(|setTimeout\s*\(\s*atob\s*\(",
    "obfuscator": r"\b_0x[0-9a-f]{4,6}\b(?:\s*\(|\[)",
    "charcode_chain": r"String\.fromCharCode\((?:\s*\d+\s*,){20,}",
    "devtools_check": r"\bdebugger\b\s*;?\s*\}\s*,\s*\d+|outerWidth\s*-\s*innerWidth\s*>\s*\d{2,}|devtools(?:Open|Detector)",
    "script_inject": r"createElement\(\s*['\"`]script['\"`]\s*\)|document\.write\(\s*['\"`]<script",
    "ios_targeting": r"/\(?(?:iPhone\|iPad|iPad\|iPhone|iPhone\|iPod)",
}
COMPILED = {k: re.compile(v, re.I if k in ("card_fields",) else 0) for k, v in PATTERNS.items()}

# Payment providers are supposed to touch card fields; that's not a skimmer
PAYMENT_HOSTS = re.compile(r"(?:^|\.)(?:stripe\.com|stripe\.network|braintreegateway\.com|braintree-api\.com|"
                           r"paypal\.com|paypalobjects\.com|adyen\.com|checkout\.com|squareup\.com|"
                           r"square\.site|klarna\.com|klarnaservices\.com|authorize\.net|worldpay\.com|"
                           r"mollie\.com|razorpay\.com|cybersource\.com|globalpay\.com)$")

URL_LITERAL = re.compile(r"['\"`](https?:)?//([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(/[^'\"`\s]*)?['\"`]", re.I)
BIG_BLOB = re.compile(r"['\"`][A-Za-z0-9+/]{3000,}={0,2}['\"`]")


@dataclass(frozen=True)
class Hit:
    name: str
    text: str


# Card field names listed next to passwords and SSNs are usually a "never record these" list
# in session-replay and analytics SDKs: code that skips card fields looks like code that targets them.
MASK_CONTEXT = re.compile(r"pass(?:word)?\b|\bpwd\b|\bssn\b|socsec|socialsec|social[-_ ]?security|routing", re.I)


def scan(js: str, limit: int = 8) -> List[Hit]:
    out = []
    masked_only = True
    card_seen = False
    for key, pad in (("card_fields", 150), ("card_regex", 300)):
        for m in COMPILED[key].finditer(js):
            card_seen = True
            if not MASK_CONTEXT.search(js[max(0, m.start() - pad): m.end() + pad]):
                masked_only = False
                break
        if not masked_only:
            break
    if card_seen and masked_only:
        out.append(Hit("card_masking", "card fields listed with passwords/SSNs (privacy masking)"))
    for name, rx in COMPILED.items():
        seen = set()
        for m in rx.finditer(js):
            t = re.sub(r"\s+", " ", m.group(0))[:80]
            if t in seen:
                continue
            seen.add(t)
            out.append(Hit(name, t))
            if len(seen) >= limit:
                break
    m = BIG_BLOB.search(js)
    if m:
        out.append(Hit("encoded_blob", f"{len(m.group(0)) // 1000}k:{m.group(0)[1:33]}"))
    return out


def names(hits: List[Hit]) -> Set[str]:
    return {h.name for h in hits}


def fingerprints(hits: List[Hit]) -> Set[Tuple[str, str]]:
    return {(h.name, h.text) for h in hits}


def new_hits(old: Set[Tuple[str, str]], hits: List[Hit]) -> List[Hit]:
    return [h for h in hits if (h.name, h.text) not in old]


def domains(js: str) -> Set[str]:
    """Hosts named in string literals: where a script can load from or send to."""
    out = set()
    for m in URL_LITERAL.finditer(js):
        host = m.group(2).lower().rstrip(".")
        if not re.search(r"\.(?:js|css|png|svg|jpe?g|gif|json|html?|woff2?)$", host):
            out.add(host)
    return out


def script_urls(js: str) -> List[str]:
    """Absolute .js URLs a script mentions, the next hop for tag managers and loaders."""
    out = []
    for m in URL_LITERAL.finditer(js):
        path = m.group(3) or ""
        if path.endswith(".js") or ".js?" in path:
            out.append(("https:" if not m.group(1) else m.group(1)) + "//" + m.group(2) + path)
    return list(dict.fromkeys(out))[:20]


# ------------------------------------------------------------------ judgement

@dataclass
class Concern:
    rule: str
    severity: str
    message: str
    evidence: str


def judge(hits: List[Hit], host: str, added: object = False) -> List[Concern]:
    """Dangerous combinations in a script.

    `added` is False for a first look, or the hits that are new since the
    baseline. In that case a combination counts when it exists in the script as
    a whole and at least one of its defining parts is new, so an attacker who
    reuses a script's existing network code is still caught.
    """
    change = added is not False
    new = {h.name for h in added} if change and added is not True else (names(hits) if added is True else set())
    n = names(hits)
    when = "newly " if change else ""

    def trig(*parts: str) -> bool:
        return (not change) or bool(new & set(parts))

    def ev(*ns: str) -> str:
        pool = [h for h in (added if change and added is not True else hits) if h.name in ns] or \
               [h for h in hits if h.name in ns]
        return ", ".join(list(dict.fromkeys(h.text for h in pool))[:3])

    payment = bool(PAYMENT_HOSTS.search(host or ""))
    out: List[Concern] = []
    sends = bool(n & {"send", "websocket_raw_ip", "raw_ip_url"})
    if not payment and (n & {"card_fields", "card_regex"}) and sends and (n & {"form_harvest", "keylog"}) \
            and trig("card_fields", "card_regex", "form_harvest", "keylog"):
        masking = "card_masking" in n
        out.append(Concern("SW001", "medium" if (masking and not change) else "high",
                           f"{when}reads payment-card fields and sends data out: the shape of a card skimmer"
                           + (" (the field names also appear in a privacy-masking list, which session recorders use)"
                              if masking and not change else ""),
                           ev("card_fields", "card_regex", "form_harvest", "keylog", "send")))
    if "wallet_address" in n and (n & {"clipboard", "wallet_regex"}) and trig("wallet_address", "wallet_regex", "clipboard"):
        out.append(Concern("SW002", "high", f"{when}contains crypto wallet addresses and rewrites or copies addresses",
                           ev("wallet_address", "wallet_regex", "clipboard")))
    if (n & {"eval_decode", "obfuscator", "charcode_chain"}) and (sends or "script_inject" in n) \
            and trig("eval_decode", "obfuscator", "charcode_chain"):
        out.append(Concern("SW003", "high" if change else "medium",
                           f"{when}decodes and runs hidden code that can load or send more",
                           ev("eval_decode", "obfuscator", "charcode_chain")))
    if "screen_capture" in n and sends and trig("screen_capture"):
        out.append(Concern("SW004", "high" if change else "medium", f"{when}captures what's on screen and can send it",
                           ev("screen_capture", "send")))
    if (n & {"websocket_raw_ip", "raw_ip_url"}) and trig("websocket_raw_ip", "raw_ip_url"):
        out.append(Concern("SW005", "high" if change else "medium", f"{when}talks to a raw IP address",
                           ev("websocket_raw_ip", "raw_ip_url")))
    if change and "ios_targeting" in n and "script_inject" in n and trig("ios_targeting", "script_inject"):
        out.append(Concern("SW006", "high", "newly loads extra code only for iPhones and iPads, as the Optimizely payload did",
                           ev("ios_targeting", "script_inject")))
    if change:
        if (n & {"keylog", "form_harvest"}) and sends and not payment and not out and trig("keylog", "form_harvest"):
            out.append(Concern("SW007", "medium", "newly watches what people type into forms and can send data",
                               ev("keylog", "form_harvest", "send")))
        if "cookie_read" in n and sends and not out and trig("cookie_read"):
            out.append(Concern("SW008", "medium", "newly reads cookies and can send data", ev("cookie_read", "send")))
        if "devtools_check" in n and trig("devtools_check"):
            out.append(Concern("SW009", "medium", "newly checks whether developer tools are open, a way malware hides",
                               ev("devtools_check")))
        if "encoded_blob" in n and trig("encoded_blob"):
            out.append(Concern("SW010", "medium", "newly carries a large encoded blob", ev("encoded_blob")))
    return out
