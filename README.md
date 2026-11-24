# scriptwatch

**Catch hacked third-party scripts on your website.** Lists every script your pages
load, remembers what each one does, and warns you the moment one is new, changes,
or starts behaving like a card skimmer.

```
$ scriptwatch https://127.0.0.1:8901/ --insecure

⚠️  DANGER  https://127.0.0.1:8901/
    4 external script(s), 3 from other companies
  high   SW001  Card skimmer behaviour
      https://localhost:8902/experiments.js
      Newly reads payment-card fields and sends data out: the
      shape of a card skimmer
      Evidence: cardnumber, querySelectorAll("input,
      addEventListener("keyup"
  high   SW002  Crypto wallet swapping
      https://localhost:8902/experiments.js
      Newly contains crypto wallet addresses and rewrites or
      copies addresses
      Evidence: addEventListener("copy",
      bc1qexampleexampleexampleexample0wallet3x
  high   SW006  Extra code only for iPhones and iPads
      https://localhost:8902/experiments.js
      Newly loads extra code only for iPhones and iPads, as the
      Optimizely payload did
      Evidence: createElement("script"), /(iPhone|iPad
  high   SW013  Script talks to new domains
      https://localhost:8902/experiments.js
      The script changed and now names 2 new domain(s)
      Evidence: img-cdn.example, stats-cdn.example
    (2 low-severity note(s); --all shows them)
```

<sub>Real output from a test shop loading the real Optimizely and PostHog scripts, after
an inert attack was added to the vendor's copy of the Optimizely script.</sub>

## Why

In November 2026, malicious JavaScript was served through **Optimizely**, an A/B
testing service, to visitors of 178 organisations including Zoom, the BBC, CNN,
Salesforce, GitLab, IKEA, HSBC and Equifax ([Report URI's write-up](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/)).
The payload skimmed payment cards, swapped crypto wallet addresses, took session
data and loaded exploit kits for iPhones and iPads. None of those companies changed a
line of their own code; a script they had trusted for years changed underneath them.

Almost every site loads code from other companies: analytics, tag managers, chat,
A/B testing, ads. Your own security reviews never see it. scriptwatch does.

## How it works

1. **Inventory.** Fetches each page and every script it loads, including scripts a
   tag manager or loader pulls in (one level deep by default).
2. **Baseline.** Records each script's fingerprint and what it can do: send data, read
   cookies, watch form fields, touch the clipboard, decode hidden code, and more.
3. **Compare.** On the next run, flags new scripts, changed scripts, and above all
   scripts that **gained** a dangerous combination of behaviours. Behaviour a script
   always had isn't news; a script that just started reading card fields is.

Analytics and A/B testing scripts legitimately read cookies and send data, so on a first
scan only strong patterns are reported. Payment providers (Stripe, PayPal, Adyen and
others) are allowed to touch card fields.

## Quick start

```
pip install git+https://github.com/viehgroup/scriptwatch

scriptwatch https://your-site.example/ --update
scriptwatch https://your-site.example/
scriptwatch https://your-site.example/ --user-agent iphone
```

The first command saves a baseline to `.scriptwatch/baseline.json`; later runs compare
against it. `--user-agent iphone` fetches the page the way an iPhone would, since attackers
often serve malicious code only to some visitors. `scriptwatch file vendor.js` checks a
single script and `scriptwatch diff old.js new.js` compares two versions.

No dependencies. Only GET requests, like a browser loading the page; nothing is executed.
Use it on sites you run.

## GitHub Action

Run it on a schedule and get an alert when a script changes:

```yaml
on:
  schedule:
    - cron: "17 * * * *"      # every hour
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scriptwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: viehgroup/scriptwatch@main
        with:
          urls: |
            https://shop.example/
            https://shop.example/checkout
```

Commit `.scriptwatch/baseline.json` first (run with `--update` locally, or with
`update: "true"` and a commit step). A failed run means something changed; once you've
confirmed a change is legitimate, update the baseline again. Pin the action to a
commit SHA in production workflows.

## What it flags

| ID | Finding |
|---|---|
| SW001 | Reads payment-card fields and sends data out (card skimmer) |
| SW002 | Crypto wallet addresses plus clipboard or address rewriting |
| SW003 | Decodes and runs hidden code that can load or send more |
| SW004 | Captures the screen and can send it |
| SW005 | Talks to a raw IP address |
| SW006 | Newly loads extra code only for iPhones and iPads |
| SW007 | Newly watches form typing and can send data |
| SW008 | Newly reads cookies and can send data |
| SW009 | Newly checks for developer tools |
| SW010 | Newly carries a large encoded blob |
| SW011 | A script that wasn't there before (medium from a new host) |
| SW012 | A script changed without new risky behaviour (low) |
| SW013 | A changed script names new domains |
| SW014 | Script loaded over plain HTTP |
| SW015 | Third-party scripts but no Content-Security-Policy for scripts |
| SW016 | Version-pinned CDN library without an integrity attribute |
| SW017 | A script couldn't be fetched |

Options: `--format text|json|sarif|github|markdown`, `--fail-on high|medium|low|never`,
`--all` (include low notes), `--depth`, `--insecure`, `--user-agent`, `--summary FILE`.

## How it was tested

- **Real scripts, for false alarms.** 42 minified production scripts from 19 libraries
  (React, Vue, jQuery, Bootstrap, Chart.js, PostHog, Sentry, Segment, Mixpanel, Amplitude,
  Optimizely's SDK and more): no high findings on a first scan. Mixpanel's session
  recorder is reported as medium, because its privacy filter names card fields in order
  to skip them.
- **Real updates.** 19 version-to-version updates of those libraries, including jQuery 3.6
  to 4.1, raise nothing.
- **Recreated attack.** A real vendor script with an inert payload modelled on the
  Optimizely report added: card skimming, wallet swapping and the iPhone-only loader are
  each flagged high, with the new attacker domains listed. A skimmer that reuses the
  vendor's own existing network code is still caught.
- **End to end** over HTTPS with separate shop and vendor hosts, and in CI, where the
  action must fail after the vendor script is changed.
- 21 unit tests on Python 3.9, 3.11 and 3.13.

## Limits

- It reads scripts; it doesn't run them. Code assembled at runtime, or loaded more than
  `--depth` levels down, can be missed.
- Attackers can serve malicious code only to some visitors (by country, device or time).
  Check with `--user-agent`, and run often.
- Pages behind a login aren't checked.
- Patterns can be evaded by a determined attacker. The strongest signal is still the
  simplest: **a script changed**. Every change is recorded, even when nothing looks risky.
- A Content-Security-Policy and Subresource Integrity prevent much of this; scriptwatch
  tells you when they're missing.

## Related

From the same team: [nginxwatch](https://github.com/viehgroup/nginxwatch),
[ghostwatch](https://github.com/viehgroup/ghostwatch),
[bumpwatch](https://github.com/viehgroup/bumpwatch),
[extwatch](https://github.com/viehgroup/extwatch),
[agentscan](https://github.com/viehgroup/agentscan) and
[slopwatch](https://github.com/viehgroup/slopwatch).

## License

MIT. Built and maintained by the **VIEH Security Team**.
