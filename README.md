# SQL Injection & XSS Lab — Manual vs LLM vs Agent (OWASP ZAP + sqlmap)

A complete, hands-on web-application security assessment of an **authorized,
intentionally vulnerable** lab target, testing for **SQL injection** and **XSS /
JavaScript injection** three independent ways — **manually**, **LLM-assisted**, and with
a **guardrailed agent** — backed by **OWASP ZAP** and **sqlmap**, and ending in a
side-by-side comparison of what each method found.

> **Target (authorized):** `http://testaspnet.vulnweb.com/` — Acunetix's public,
> deliberately vulnerable ASP.NET test site, published expressly for testing security
> tools and training. **Do not point this tooling at anything else.**
> See [`docs/00-rules-of-engagement.md`](docs/00-rules-of-engagement.md).

---

## 1. The assignment, and where each part is answered

This repository is the full answer to the lab brief. Every requirement maps to a
concrete artifact:

| Assignment requirement | How it was done | Where |
|---|---|---|
| Use **OWASP ZAP** to scan for SQLi & XSS | Headless ZAP (Docker) + Automation Framework plan, scoped to the host, SQLi/XSS rule policy | [`zap/automation-plan.yaml`](zap/automation-plan.yaml), [`scripts/run_zap.*`](scripts), [`docs/08-owasp-zap.md`](docs/08-owasp-zap.md), [`evidence/zap/`](evidence/zap) |
| **Find the app's entry points** (fields, parameters…) | Scoped crawler → inventory of URL params + forms | [`scripts/crawl_entrypoints.py`](scripts/crawl_entrypoints.py), [`docs/02-entry-points.md`](docs/02-entry-points.md) |
| **Run sqlmap manually** to test for SQLi | sqlmap at risk/level 2 → confirmed boolean-blind + stacked-queries + time-based, MSSQL 2014 | [`docs/03-phase1-manual.md`](docs/03-phase1-manual.md) §3.3, [`evidence/sqlmap/sqlmap_comments_id.log`](evidence/sqlmap/sqlmap_comments_id.log) |
| **Test for XSS / JavaScript injection manually** | Reflection + stored-comment canary probes; browser PoC | [`docs/03-phase1-manual.md`](docs/03-phase1-manual.md) §3.2, [`evidence/xss/`](evidence/xss) |
| **Phase 2** — LLM helps crawl & discover, then tests in the lab | LLM ranks entry points, proposes payloads, hypotheses verified live (incl. one it got wrong) | [`docs/04-phase2-llm.md`](docs/04-phase2-llm.md) |
| **Phase 3** — agent runs the approved tools | `agent_runner.py` runs crawl → probes → sqlmap unattended | [`docs/05-phase3-agent.md`](docs/05-phase3-agent.md), [`evidence/agent/run.json`](evidence/agent/run.json) |
| **Guardrails: sqlmap risk/level 2–3, not 5; stay in the lab** | Enforced in code: host allowlist + risk/level clamp + forbidden-flag denylist | [`config/scope.yaml`](config/scope.yaml), [`scripts/guardrails.py`](scripts/guardrails.py) |
| **Compare manual / LLM / agent results** | Full cross-method coverage + findings matrix and discussion | [`docs/06-comparison.md`](docs/06-comparison.md) |

---

## 2. Results — what was found

Against `testaspnet.vulnweb.com`, four exploitable vulnerabilities (plus hardening gaps)
were confirmed. Full write-up: [`results/findings.md`](results/findings.md) · machine-readable
[`results/findings.json`](results/findings.json).

| ID | Finding | Location | Severity | Confirmed by |
|----|---------|----------|----------|--------------|
| **SQLI-01** | SQL injection (CWE-89) | `Comments.aspx?id` | Critical | manual + **sqlmap** (MSSQL 2014: boolean/stacked/time-based) + ZAP |
| **SQLI-02** | SQL injection (CWE-89) | `ReadNews.aspx?id` | Critical | manual + ZAP (time-based) |
| **SQLI-03** | SQL injection / auth bypass (CWE-89) | `login.aspx` `tbUsername` | Critical | **ZAP only** (`' OR '1'='1' --`) |
| **XSS-01** | Stored XSS (CWE-79) | `Comments.aspx` `tbComment` | High | manual (unencoded `<script>`) + ZAP |
| **XSS-02** | Reflected XSS via `javascript:` URI (CWE-79) | `ReadNews.aspx?NewsAd` | High | **ZAP only** |
| MISC | No CSP / anti-CSRF / anti-clickjacking headers, info leaks | site-wide | Low–Med | ZAP |
| INFO-01 | `<`-tag reflected XSS in query string | query string | *Mitigated* | blocked by ASP.NET Request Validation |

**Backend:** Microsoft SQL Server 2014 (identified by sqlmap).
**Fixes:** parameterised queries, contextual output-encoding, input whitelisting, CSP +
secure headers — see [`docs/07-remediation.md`](docs/07-remediation.md).

---

## 3. The three methods (+ ZAP) and the headline comparison

- **Manual** ([`docs/03`](docs/03-phase1-manual.md)) — `curl`, a browser, and small
  differential probes. Proved SQLi by showing a single quote collapses the page to
  **0 bytes**, and stored XSS by storing an unencoded canary.
- **LLM-assisted** ([`docs/04`](docs/04-phase2-llm.md)) — an LLM reads the crawl output,
  ranks the likely issues, proposes payloads, and the hypotheses are **verified in the
  lab** (including one it got wrong — reflected XSS — which the live test refuted).
- **Agent** ([`docs/05`](docs/05-phase3-agent.md)) — `agent_runner.py` runs the whole
  pipeline unattended under the guardrails below.
- **OWASP ZAP** ([`docs/08`](docs/08-owasp-zap.md)) — spider + AJAX spider + passive +
  active scan (SQLi/XSS rule policy), headless in Docker.

**The key lesson of the comparison** ([`docs/06`](docs/06-comparison.md)): all methods
agreed on the core SQLi and stored XSS, but **ZAP found two real issues the manual, LLM,
and agent passes all missed** —

1. **Reflected XSS on `NewsAd`** via a `javascript:` URI. The focused methods reasoned
   their way to `<`-tag payloads, which ASP.NET Request Validation blocks, and concluded
   "mitigated." ZAP's wider payload set used a `javascript:` URI (no `<`) and found a live
   vulnerability. *(We corrected our conclusion accordingly — honesty over tidiness.)*
2. **SQLi in the `login.aspx` form**, which the human/LLM/agent kept to detection-only per
   scope while ZAP actively confirmed it.

> **Takeaway:** the LLM is best at *prioritising*; the agent is best at *disciplined,
> repeatable* execution; ZAP is best at *breadth* (at the cost of noise to triage); the
> human stays in the loop to verify and decide. They are complementary, not competing.

---

## 4. Programmatic guardrails — the safety core (Phase 3)

The assignment requires that the automated tooling keep sqlmap at **risk/level 2–3, never
5**, and **stay inside the lab**. That is enforced in **code**, not in a prompt, so it
cannot be argued away. All scope/intensity rules live in
[`config/scope.yaml`](config/scope.yaml) and are enforced by
[`scripts/guardrails.py`](scripts/guardrails.py) before any tool runs:

- **Host allowlist** — only `testaspnet.vulnweb.com`; every other URL (and look-alikes
  like `…vulnweb.com.evil.com`) is refused.
- **sqlmap risk/level clamp** — forced into `{2,3}`; a request for `--risk 5` is clamped
  to `3` and can never reach 5.
- **Forbidden-flag denylist** — `--os-shell`, `--sql-shell`, `--file-write`,
  `--dump-all`, `--all`, … can never be passed.
- **Bounded, polite** — `--batch`, capped threads, metadata-only enumeration, identifying
  User-Agent.

Prove it holds:

```bash
python scripts/guardrails.py --selftest      # 17 checks, all PASS (incl. "risk 5 clamped", "--os-shell rejected")
```

---

## 5. Reproduce it

```bash
# 1. Python deps for this repo's scripts
pip install -r requirements.txt

# 2. sqlmap (pure Python) — either:
pip install --target .tools/sqlmap-pkg sqlmap
#   or: git clone https://github.com/sqlmapproject/sqlmap .tools/sqlmap

# 3. Discover entry points (scoped crawl)
python scripts/crawl_entrypoints.py

# 4. Phase 1 — manual probes
python scripts/sqli_manual_probe.py --url "http://testaspnet.vulnweb.com/Comments.aspx?id=1" --param id
python scripts/xss_stored_probe.py

# 5. Phase 3 — the guardrailed agent (audit first, then run)
python scripts/agent_runner.py --dry-run     # prints every action + the hardened sqlmap argv
python scripts/agent_runner.py               # full run

# 6. OWASP ZAP — scoped scan (needs Docker running)
powershell -ExecutionPolicy Bypass -File scripts/run_zap.ps1     # Windows
bash scripts/run_zap.sh                                          # Linux/macOS
```

---

## 6. Repository map

```
.
├── README.md                     ← this file (full project answer)
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
├── docs/
│   ├── 00-rules-of-engagement.md ├── 01-methodology.md     ├── 02-entry-points.md
│   ├── 03-phase1-manual.md       ├── 04-phase2-llm.md       ├── 05-phase3-agent.md
│   ├── 06-comparison.md          ├── 07-remediation.md      └── 08-owasp-zap.md
├── evidence/                     ← real, sanitized output (crawl, sqlmap, xss, agent, zap)
└── results/findings.{md,json}    ← consolidated findings
```

---

## 7. Ethics & authorization

This repository targets **one** host that is published specifically for security testing.
Testing used non-executing canaries and bounded, metadata-only enumeration; no mass data
was exfiltrated and no harmful attack code was planted. Submitter IPs captured incidentally
were redacted from evidence. Using any of this against systems you do not own or are not
explicitly authorized to test is illegal. See
[`docs/00-rules-of-engagement.md`](docs/00-rules-of-engagement.md).

## License

[MIT](LICENSE).
