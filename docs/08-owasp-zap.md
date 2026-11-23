# 08 — OWASP ZAP (Phase 1, automated scanner)

OWASP ZAP was run **headless in Docker** against the scoped host using the Automation
Framework plan [`zap/automation-plan.yaml`](../zap/automation-plan.yaml): classic spider
→ AJAX spider → passive scan → **active scan restricted to the SQLi and XSS rule
families**, then HTML + JSON reports.

- Runner: [`scripts/run_zap.ps1`](../scripts/run_zap.ps1) / [`scripts/run_zap.sh`](../scripts/run_zap.sh)
- Image: `ghcr.io/zaproxy/zaproxy:stable`
- Reports: [`evidence/zap/zap-report.html`](../evidence/zap/zap-report.html) · [`evidence/zap/zap-report.json`](../evidence/zap/zap-report.json)
- Scope: pinned to `http://testaspnet.vulnweb.com` by the context include-regex — ZAP cannot leave the host.

## 8.1 Alerts

| Risk | Alert | CWE | Instances |
|------|-------|-----|-----------|
| **High** | SQL Injection | 89 | 3 |
| **High** | SQL Injection – MsSQL (Time Based) | 89 | 6 |
| **High** | Cross Site Scripting (Persistent) | 79 | 1 |
| **High** | Cross Site Scripting (Reflected) | 79 | 5 |
| Medium | Absence of Anti-CSRF Tokens | 352 | 5 |
| Medium | Content Security Policy (CSP) Header Not Set | 693 | 5 |
| Medium | Missing Anti-clickjacking Header | 1021 | 4 |
| Low | Cookie without SameSite Attribute | 1275 | 2 |
| Low | Server/X-Powered-By/X-AspNet-Version info leaks | 497/933 | 15 |
| Low | X-Content-Type-Options missing | 693 | 5 |
| Info | User-Controllable HTML Element Attribute (Potential XSS) | 20 | 36 |

## 8.2 What ZAP confirmed (agreement with manual / sqlmap)

- **SQL Injection on `id`** — `GET Comments.aspx?id=5-2` (arithmetic inference) and
  **MsSQL time-based** `id=0 WAITFOR DELAY '0:0:15' --` on `Comments.aspx` and
  `ReadNews.aspx`. This matches the manual quote-collapse result and sqlmap's
  boolean/stacked/time-based confirmation, **independently**.
- **Stored (Persistent) XSS** — `POST Comments.aspx` param `tbComment` with
  `</div><script>alert(1);</script><div>`. Matches the stored-XSS proof in
  [`03-phase1-manual.md`](03-phase1-manual.md).

## 8.3 What ZAP found that manual / LLM / agent did **not** — two important additions

1. **Reflected XSS via a `javascript:` URI in `ReadNews.aspx?NewsAd`.**
   `GET ReadNews.aspx?id=0&NewsAd=javascript:alert(1);` — the `NewsAd` value is placed
   into a link, and a `javascript:` URI payload executes on click.
   **Why manual/LLM missed it:** our manual XSS probes injected `<`-based tag canaries,
   which ASP.NET **Request Validation blocks** — so we concluded the query-string vector
   was mitigated. A `javascript:` URI contains **no `<`**, so Request Validation lets it
   through. ZAP's broader payload set caught the vector our narrower one walked past.
   → This corrects the earlier "reflected XSS fully mitigated" reading: the `<`-tag
   query-string vector *is* blocked, but a `javascript:`-URI vector on `NewsAd` is **not**.
2. **SQL Injection in the login form (`login.aspx`, `tbUsername`).**
   `POST login.aspx` with `tbUsername = ZAP' OR '1'='1' --`. We had flagged login as a
   *candidate* but kept to detection-only per scope; ZAP actively confirmed it.

## 8.4 Breadth beyond the assigned classes

ZAP also reported configuration/hardening gaps the focused SQLi/XSS testing did not
chase: **no CSP**, **no anti-CSRF tokens**, **no anti-clickjacking header**, cookies
without `SameSite`, and version/info leaks (`Server`, `X-Powered-By`,
`X-AspNet-Version`). These are real defence-in-depth gaps and reinforce the remediation
in [`07-remediation.md`](07-remediation.md) (CSP + secure headers + cookie flags).

## 8.5 Takeaway for the comparison

ZAP is the **breadth** instrument: it enumerated the most entry points, confirmed both
assigned vulnerability classes independently, and — crucially — found a reflected-XSS
vector and a login SQLi that the manual/LLM/agent passes missed. Its cost is **noise**
(36 "potential" info items, config findings) that a human must triage. See the full
cross-method discussion in [`06-comparison.md`](06-comparison.md).
