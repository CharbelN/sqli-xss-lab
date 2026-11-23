# Findings — testaspnet.vulnweb.com (SQLi / XSS lab)

**Assessment date:** 2026-11-23 · **Operator:** CharbelN · **Scope:** `testaspnet.vulnweb.com` only
**Methods:** manual · LLM-assisted · guardrailed agent · OWASP ZAP · sqlmap

| ID | Title | Severity | CWE | Status |
|----|-------|----------|-----|--------|
| **SQLI-01** | SQL injection in `Comments.aspx` `id` parameter | Critical | CWE-89 | Confirmed |
| **SQLI-02** | SQL injection in `ReadNews.aspx` `id` parameter | Critical | CWE-89 | Confirmed |
| **XSS-01** | Stored XSS in `Comments.aspx` comment field (`tbComment`) | High | CWE-79 | Confirmed |
| **INFO-01** | Reflected XSS via query string | Info | CWE-79 | Mitigated (ASP.NET Request Validation) |

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

## INFO-01 — Reflected XSS via query string (Info — mitigated)

- Injecting `<` into `ReadNews.aspx?id` / `?NewsAd` triggers ASP.NET **Request
  Validation** ("A potentially dangerous Request.QueryString value was detected"),
  and the value is returned HTML-encoded. Not exploitable via this vector.
  `evidence/xss/probe_readnews_id.json`.
- **Note:** Request Validation is a backstop; it does **not** cover the stored POST
  vector (XSS-01). Output-encoding is still required.

---

### Method attribution (who found what)

| Finding | Manual | LLM | Agent | ZAP |
|---------|:------:|:---:|:-----:|:---:|
| SQLI-01 | ✅ | ✅ | ✅ | see `evidence/zap/` |
| SQLI-02 | ✅ | ✅ | ✅ | see `evidence/zap/` |
| XSS-01  | ✅ | ✅ | ✅ | see `evidence/zap/` |
| INFO-01 | ✅ | ✅ | ✅ | see `evidence/zap/` |

Full comparison and discussion: [`../docs/06-comparison.md`](../docs/06-comparison.md).
