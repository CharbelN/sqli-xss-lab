# 07 — Remediation

The two confirmed vulnerabilities share one root cause: **untrusted input is mixed
into a command/markup context without separation.** Fixing them is well-understood.

## 7.1 SQL Injection (`Comments.aspx?id`, `ReadNews.aspx?id`) — CWE-89

**Root cause:** the `id` value is concatenated into a SQL string, e.g.

```csharp
// VULNERABLE
string sql = "SELECT * FROM comments WHERE id = '" + Request.QueryString["id"] + "'";
SqlCommand cmd = new SqlCommand(sql, conn);
```

**Fix — parameterised queries (primary control):**

```csharp
// SAFE
string sql = "SELECT * FROM comments WHERE id = @id";
using (var cmd = new SqlCommand(sql, conn))
{
    cmd.Parameters.Add("@id", SqlDbType.Int).Value = int.Parse(Request.QueryString["id"]);
    // ...
}
```

The database now treats `@id` strictly as **data**, never as SQL syntax, so a trailing
quote cannot break out of the statement.

**Defence in depth**
- **Input validation / type binding.** `id` is an integer — reject anything that is not
  (`int.TryParse`). This alone would have stopped the quote payload.
- **Least privilege.** The web app's SQL login should be a low-privilege account with
  no `db_owner`/`sa` rights, so even a successful injection cannot read system tables or
  run `xp_cmdshell`. (sqlmap's `--is-dba` check reports on exactly this exposure.)
- **Use an ORM / stored procedures** with parameterisation throughout, not just here.
- **Generic error pages** so SQL errors never reach the client.

## 7.2 Stored XSS (`Comments.aspx` → `tbComment`) — CWE-79

**Root cause:** the comment body is written into the HTML response without
output-encoding:

```csharp
// VULNERABLE
litComments.Text += "<DIV class=\"CommentText\">" + comment.Body + "</DIV>";
```

**Fix — contextual output encoding (primary control):** encode on the way *out*, for
the HTML context in which the data lands.

```csharp
// SAFE — System.Web / AntiXSS
litComments.Text += "<div class=\"CommentText\">"
                  + System.Web.HttpUtility.HtmlEncode(comment.Body)
                  + "</div>";
```

Now `<script>` becomes `&lt;script&gt;` and renders as inert text.

**Defence in depth**
- **Input validation** on submission (length limits, reject control characters) — but
  encoding on output is the control that actually stops XSS.
- **Content-Security-Policy.** A policy such as
  `Content-Security-Policy: default-src 'self'; script-src 'self'` makes an injected
  inline `<script>` fail to execute even if encoding is missed.
- **HttpOnly cookies.** Mark the session cookie `HttpOnly` so injected JS cannot read
  it via `document.cookie`, blunting session-hijacking.
- **Keep framework protections on.** ASP.NET Request Validation already blocks the
  *query-string* vector here; the same scrutiny must cover POST bodies, and must not be
  the only layer (it is a backstop, not a substitute for encoding).

## 7.3 Priority

| Finding | Severity | Fix effort | Priority |
|---------|----------|-----------|----------|
| SQLi on `id` (SQL Server, confirmed) | **Critical** (DB read, possible host impact) | Low (parameterise) | **1** |
| Stored XSS on `tbComment` | **High** (runs in every visitor's browser) | Low (output-encode) | **2** |
| Reflected XSS on `?id` | Mitigated (Request Validation) | — | monitor |

Both primary fixes are small, standard, and should ship together with a regression
test that submits the exact payloads in `config/scope.yaml` and asserts they are
rejected / encoded.
