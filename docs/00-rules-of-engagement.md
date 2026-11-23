# 00 — Rules of Engagement

> **Read this first.** Everything in this repository is scoped by the rules below.
> The tooling enforces them in code (`config/scope.yaml` + `scripts/guardrails.py`),
> but the human running it is still responsible for staying inside them.

## 1. Authorization & target

| Item | Value |
|------|-------|
| **Target application** | `http://testaspnet.vulnweb.com/` |
| **Primary entry point (assigned)** | `http://testaspnet.vulnweb.com/Comments.aspx?id=1` |
| **Nature of target** | Acunetix **public, intentionally-vulnerable** test application |
| **Authorization basis** | Acunetix publishes the `*.vulnweb.com` sites expressly for testing web vulnerability scanners and for security training. This is also the application assigned by the course. |
| **Engagement type** | Educational coursework lab (SQL injection + JavaScript/XSS injection) |

Acunetix's own notice on these hosts: *"This is an example PHP/ASP application ...
It is intended to help you test Acunetix. ... you may use it to test tools."* The
`vulnweb.com` family (testphp, testasp, testaspnet, testhtml5) is the canonical
"legal to scan" practice range used across the industry.

**Do not** point any script or tool in this repo at a host you are not explicitly
authorized to test. The guardrails below are designed to make that hard, not to
transfer responsibility away from the operator.

## 2. Scope

**In scope**
- Single host: `testaspnet.vulnweb.com`
- Vulnerability classes: **SQL injection** and **Cross-Site Scripting / JavaScript injection** only
- Techniques: detection + **bounded** proof-of-impact (confirm the flaw; enumerate
  database metadata only far enough to prove exploitability)

**Out of scope / explicitly forbidden**
- Any other host or domain (enforced by host allowlist)
- OS-level exploitation, shells, file read/write, registry access, privilege escalation
- Mass data exfiltration / full table dumps
- Denial of service, brute forcing, or high-intensity scanning (sqlmap risk/level capped at 2–3)
- Pivoting, persistence, or any post-exploitation activity

## 3. Programmatic guardrails (how the rules are enforced)

All network-touching scripts load `config/scope.yaml` through
`scripts/guardrails.py` **before** acting. The guardrails:

1. **Host allowlist** — only `testaspnet.vulnweb.com` is reachable. Any other URL
   raises `ScopeViolation` and the tool refuses to run. Look-alike hosts
   (`testaspnet.vulnweb.com.evil.com`) are rejected too.
2. **sqlmap risk/level clamp** — `--risk` and `--level` are forced into the **2–3**
   window (default 2). A request for `--risk 5` is silently clamped to 3; it can
   never reach the assignment-forbidden level 5.
3. **Forbidden-flag denylist** — destructive / post-exploitation sqlmap flags
   (`--os-shell`, `--sql-shell`, `--file-write`, `--dump-all`, `--all`, …) are
   rejected. They cannot be smuggled into a scan.
4. **Politeness** — non-interactive (`--batch`), capped threads, bounded time
   thresholds, fixed User-Agent that identifies the scan.

Prove the rails hold at any time:

```bash
python scripts/guardrails.py --selftest
```

## 4. Safety & etiquette rules followed

- A fixed, honest `User-Agent` identifies every request as an authorized coursework scan.
- XSS testing uses **non-executing canary markers** (`<zzxss…zz>`), not live
  `<script>` payloads, so no working attack code is planted on the shared host.
- Stored-XSS testing posts exactly **one** canary comment per run, not a flood.
- sqlmap enumeration stops at database metadata (`--banner`, `--current-db`,
  `--dbs`, list tables) — enough to prove impact, no bulk data retrieval.
- No credentials, tokens, or retrieved data are committed to the repository.

## 5. Legal / ethical note

This methodology, tooling, and these guardrails are provided for **authorized
testing and education only**. Running them against systems you do not own or do
not have written permission to test is illegal in most jurisdictions. The target
used here is chosen specifically because it is a sanctioned practice range.
