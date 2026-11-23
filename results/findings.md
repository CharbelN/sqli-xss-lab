# Findings — testaspnet.vulnweb.com (SQLi / XSS lab)

**Assessment date:** 2026-11-23 · **Operator:** CharbelN · **Scope:** `testaspnet.vulnweb.com` only
**Methods:** manual · LLM-assisted · guardrailed agent · OWASP ZAP · sqlmap

| ID | Title | Severity | CWE | Status |
|----|-------|----------|-----|--------|
| **SQLI-01** | SQL injection in `Comments.aspx` `id` parameter | Critical | CWE-89 | Confirmed |
| **SQLI-02** | SQL injection in `ReadNews.aspx` `id` parameter | Critical | CWE-89 | Confirmed |
| **SQLI-03** | SQL injection in `login.aspx` `tbUsername` (auth bypass) | Critical | CWE-89 | Confirmed (ZAP) |
| **XSS-01** | Stored XSS in `Comments.aspx` comment field (`tbComment`) | High | CWE-79 | Confirmed |
| **XSS-02** | Reflected XSS via `javascript:` URI in `ReadNews.aspx?NewsAd` | High | CWE-79 | Confirmed (ZAP) |
| **MISC** | Missing CSP / anti-CSRF / anti-clickjacking headers, info leaks | Low–Med | 352/693/1021/497 | Confirmed (ZAP) |
| **INFO-01** | Reflected XSS via `<`-tag in query string | Info | CWE-79 | Mitigated for this vector (ASP.NET Request Validation) |

---

## SQLI-01 — SQL injection in `Comments.aspx?id` (Critical, CWE-89)

- **Entry point:** `GET http://testaspnet.vulnweb.com/Comments.aspx?id=1`, parameter `id`.
- **Manual evidence:** appending a single quote collapses the response from **13 390 B
  → 0 B** (query breaks on a bare quote). `evidence/sqlmap/manual_probe_comments_id.json`.
- **sqlmap confirmation (risk/level 2, 202 requests):** parameter `id` is injectable
  via **three** techniques — **boolean-based blind** (`id=1 AND 1954=1954`),
  **stacked queries** (`id=1;WAITFOR DELAY '0:0:5'--`), and **time-based blind**
  (`id=1 WAITFOR DELAY '0:0:5'`); back-end DBMS **Microsoft SQL Server 2014**.
  Log: `evidence/sqlmap/sqlmap_comments_id.log`.
- **Impact:** read access to the application database; depending on DB privileges,
  potential for broader compromise. (Enumeration kept to metadata — see log.)
- **Remediation:** parameterised queries + integer validation of `id`. See
  [`../docs/07-remediation.md`](../docs/07-remediation.md).

## SQLI-02 — SQL injection in `ReadNews.aspx?id` (Critical, CWE-89)

- **Entry point:** `GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=1`, parameter `id`.
- **Evidence:** same quote-collapse differential as SQLI-01
  (`evidence/sqlmap/manual_probe_readnews_id.json`). Same backend query pattern.
- **Remediation:** as SQLI-01.

## SQLI-03 — SQL injection in `login.aspx` `tbUsername` (Critical, CWE-89)

- **Entry point:** `POST http://testaspnet.vulnweb.com/login.aspx`, field `tbUsername`.
- **Evidence (OWASP ZAP):** payload `ZAP' OR '1'='1' --` flagged as SQL Injection — a
  classic authentication-bypass pattern. `evidence/zap/zap-report.html`.
- **Note:** flagged as a candidate during manual/LLM/agent work but kept to
  *detection-only* per scope (no account takeover attempted). ZAP actively confirmed it.
- **Remediation:** parameterised auth query + account lockout; never build the login
  `WHERE` clause from string concatenation.

## XSS-02 — Reflected XSS via `javascript:` URI in `ReadNews.aspx?NewsAd` (High, CWE-79)

- **Entry point:** `GET http://testaspnet.vulnweb.com/ReadNews.aspx?id=0&NewsAd=javascript:alert(1);`, parameter `NewsAd`.
- **Evidence (OWASP ZAP):** `NewsAd` is reflected into a link target; a `javascript:`
  URI executes. `evidence/zap/zap-report.html`.
- **Why manual/LLM missed it:** our probes used `<`-tag canaries, which ASP.NET Request
  Validation blocks. A `javascript:` URI has no `<`, so it slips past that filter. This
  is the key cross-method lesson — see `../docs/08-owasp-zap.md` §8.3.
- **Remediation:** validate/whitelist `NewsAd` against known-good paths; reject
  `javascript:`/`data:` URI schemes; output-encode for the attribute context.

## XSS-01 — Stored XSS in `Comments.aspx` comment field (High, CWE-79)

- **Entry point:** `POST http://testaspnet.vulnweb.com/Comments.aspx`, field `tbComment`.
- **Evidence:** a submitted comment is stored and re-rendered **without
  output-encoding**. A canary `<zzxss…zz>` appears raw inside
  `<DIV class="CommentText">…</DIV>`; server-side escalation shows
  `<img src=x onerror=alert(1)>` and `<script>x=1</script>` are all stored verbatim.
  `evidence/xss/stored_probe.json`, PoC render `evidence/xss/poc_render.html`.
- **Impact:** arbitrary JavaScript executes in the browser of every visitor who views
  the thread — session theft, defacement, redirection, keylogging.
- **Remediation:** contextual HTML output-encoding (`HttpUtility.HtmlEncode`) + CSP +
  `HttpOnly` cookies. See [`../docs/07-remediation.md`](../docs/07-remediation.md).

## INFO-01 — Reflected XSS via `<`-tag in query string (Info — mitigated *for this vector*)

- Injecting a `<`-based tag into `ReadNews.aspx?id` / `?NewsAd` triggers ASP.NET
  **Request Validation** ("A potentially dangerous Request.QueryString value was
  detected"), and the value is returned HTML-encoded. Not exploitable **via a `<`-tag
  payload**. `evidence/xss/probe_readnews_id.json`.
- **Important caveat:** Request Validation only blocks markup-like input. It does **not**
  stop the `javascript:`-URI reflected XSS on `NewsAd` (**XSS-02**) or the stored POST
  vector (**XSS-01**). It is a backstop, not a substitute for output-encoding and input
  whitelisting.

---

### Method attribution (who found what)

| Finding | Manual | LLM | Agent | ZAP |
|---------|:------:|:---:|:-----:|:---:|
| SQLI-01 (`Comments.aspx?id`) | ✅ | ✅ | ✅ | ✅ |
| SQLI-02 (`ReadNews.aspx?id`) | ✅ | ✅ | ✅ | ✅ |
| SQLI-03 (`login.aspx` auth) | candidate only | candidate only | candidate only | ✅ **only ZAP confirmed** |
| XSS-01 (stored `tbComment`) | ✅ | ✅ | ✅ | ✅ |
| XSS-02 (`javascript:` URI `NewsAd`) | ❌ missed | ❌ missed | ❌ missed | ✅ **only ZAP found** |
| INFO-01 (`<`-tag query XSS blocked) | ✅ | ✅ | ✅ | ✅ |

Two findings (SQLI-03, XSS-02) were discovered **only by ZAP** — the clearest evidence
of why an automated scanner complements manual/LLM/agent testing. See
[`../docs/08-owasp-zap.md`](../docs/08-owasp-zap.md) and
[`../docs/06-comparison.md`](../docs/06-comparison.md).

Full comparison and discussion: [`../docs/06-comparison.md`](../docs/06-comparison.md).
