# SQL Injection & XSS Lab — Manual vs LLM vs Agent

A hands-on web-application security assessment of an **authorized, intentionally
vulnerable** lab target, testing for **SQL injection** and **Cross-Site Scripting
(XSS / JavaScript injection)** three different ways — **manually**, **LLM-assisted**,
and with a **guardrailed agent** — and comparing what each method found.

> **Target:** `http://testaspnet.vulnweb.com/` — Acunetix's public, deliberately
> vulnerable ASP.NET test site, provided expressly for testing security tools and
> training. **Do not point this tooling at anything else.** See
> [`docs/00-rules-of-engagement.md`](docs/00-rules-of-engagement.md).

Built for a coursework assignment (OWASP ZAP + sqlmap), but structured like a real
engagement: rules of engagement, methodology, enforced scope, reproducible evidence,
and a findings report.

---

## TL;DR — what was found

| # | Finding | Location | Severity | Confirmed by |
|---|---------|----------|----------|--------------|
| 1 | **SQL injection** (CWE-89) | `Comments.aspx?id` | Critical | manual + **sqlmap** (MSSQL 2014, boolean-blind) |
| 2 | **SQL injection** (CWE-89) | `ReadNews.aspx?id` | Critical | manual (quote-collapse) |
| 3 | **Stored XSS** (CWE-79) | `Comments.aspx` → `tbComment` | High | canary stored **unencoded** (`<script>` executes) |
| – | Reflected XSS via `?id` | query string | *Mitigated* | blocked by ASP.NET Request Validation |

Full write-up: [`results/findings.md`](results/findings.md) and
[`docs/06-comparison.md`](docs/06-comparison.md).

---

## The three methods

1. **Manual** ([`docs/03-phase1-manual.md`](docs/03-phase1-manual.md)) — `curl`, a real
   browser, and small differential probes. Proved SQLi by showing a single quote
   collapses the page to 0 bytes, and stored XSS by storing an unencoded canary.
2. **LLM-assisted** ([`docs/04-phase2-llm.md`](docs/04-phase2-llm.md)) — an LLM reads the
   crawl output, ranks the likely issues, proposes payloads, and the hypotheses are then
   **verified in the lab** (including one it got wrong — reflected XSS — which the live
   test correctly refuted).
3. **Agent** ([`docs/05-phase3-agent.md`](docs/05-phase3-agent.md)) — `agent_runner.py`
   runs the whole pipeline unattended under **programmatic guardrails**: a single-host
   allowlist and a sqlmap risk/level clamp pinned to **2–3 (never 5)**, with destructive
   flags denied.

---

## Programmatic guardrails (the safety core)

All scope and intensity rules live in [`config/scope.yaml`](config/scope.yaml) and are
enforced by [`scripts/guardrails.py`](scripts/guardrails.py) before any tool runs:

- **Host allowlist** — only `testaspnet.vulnweb.com`; every other URL is refused.
- **sqlmap risk/level clamp** — forced into `{2,3}`; `--risk 5` is clamped to `3`.
- **Forbidden-flag denylist** — `--os-shell`, `--sql-shell`, `--file-write`,
  `--dump-all`, `--all`, … can never be passed.

Prove it:

```bash
python scripts/guardrails.py --selftest     # 17 checks, all PASS
```

---

## Quick start

```bash
# 1. Python deps for this repo's scripts
pip install -r requirements.txt

# 2. (SQLi tool) sqlmap — pure Python
pip install --target .tools/sqlmap-pkg sqlmap        # or: git clone https://github.com/sqlmapproject/sqlmap .tools/sqlmap

# 3. Discover entry points (scoped crawl)
python scripts/crawl_entrypoints.py

# 4. Phase 1 — manual probes
python scripts/sqli_manual_probe.py --url "http://testaspnet.vulnweb.com/Comments.aspx?id=1" --param id
python scripts/xss_stored_probe.py

# 5. Phase 3 — the guardrailed agent (audit first, then run)
python scripts/agent_runner.py --dry-run    # prints every action + hardened sqlmap argv
python scripts/agent_runner.py              # full run

# 6. OWASP ZAP — scoped active scan (needs Docker running)
powershell -ExecutionPolicy Bypass -File scripts/run_zap.ps1     # Windows
bash scripts/run_zap.sh                                          # Linux/macOS
```

---

## Repository map

```
.
├── README.md                     ← you are here
├── config/scope.yaml             ← single source of truth: host allowlist + sqlmap caps
├── scripts/
│   ├── guardrails.py             ← enforces scope + risk/level clamp + flag denylist (run --selftest)
│   ├── crawl_entrypoints.py      ← scoped entry-point crawler
│   ├── sqli_manual_probe.py      ← error/boolean/time differential SQLi probe
│   ├── xss_manual_probe.py       ← reflected-XSS reflection probe
│   ├── xss_stored_probe.py       ← stored-XSS probe (comment form)
│   ├── agent_runner.py           ← Phase-3 guardrailed orchestrator
│   └── run_zap.ps1 / run_zap.sh  ← OWASP ZAP headless runner (Docker)
├── zap/automation-plan.yaml      ← ZAP Automation Framework plan (scoped, SQLi/XSS rules)
├── docs/                         ← 00 rules-of-engagement … 07 remediation
├── evidence/                     ← real, sanitized tool output (crawl, sqlmap, xss, zap, agent)
└── results/findings.{md,json}    ← consolidated findings
```

---

## Ethics & authorization

This repository targets **one** host that is published specifically for security
testing. Testing used non-executing canaries and bounded, metadata-only enumeration;
no mass data was exfiltrated and no harmful attack code was planted. Using any of this
against systems you do not own or are not explicitly authorized to test is illegal.
See [`docs/00-rules-of-engagement.md`](docs/00-rules-of-engagement.md).

## License

[MIT](LICENSE).
