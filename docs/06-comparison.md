# 06 — Comparison: Manual vs LLM vs Agent

The assignment's final task: *"Compare your manual, LLM, and agent results. Record
which entry points and possible issues each method found."* This is that record.

## 6.1 Coverage matrix — entry points discovered

| Entry point | Manual | LLM-assisted | Agent | ZAP |
|-------------|:------:|:-----------:|:-----:|:---:|
| `Comments.aspx?id` (GET) | ✅ (assigned target) | ✅ | ✅ (crawl) | ✅ |
| `ReadNews.aspx?id` (GET) | ⚠️ by browsing | ✅ nominated | ✅ (crawl) | ✅ |
| `ReadNews.aspx?NewsAd` (GET) | ❌ easy to miss | ✅ path-like | ✅ (crawl) | ✅ |
| `Comments.aspx` `tbComment` (POST) | ✅ | ✅ stored sink | ✅ | ✅ |
| `login.aspx` `tbUsername`/`tbPassword` | ✅ | ✅ candidate | ✅ (detection-only) | ✅ |
| `Signup.aspx` fields | ❌ | ✅ | ✅ | ✅ |

**Takeaway:** the **agent's crawler** and **ZAP's spiders** give the most *complete and
repeatable* enumeration (they do not get bored or forget a page). The **LLM** is best at
**ranking** that list — saying *which* to test first and why. The **human** is reliable
on the obvious targets but most likely to miss a quiet one like `NewsAd`.

## 6.2 Findings matrix — issues confirmed

| Issue (entry point) | Manual | LLM | Agent | ZAP | Ground truth |
|---------------------|:------:|:---:|:-----:|:---:|:-------------|
| **SQLi** — `Comments.aspx?id` | ✅ quote-collapse | ✅ predicted | ✅ probe+sqlmap | ✅ | **Vulnerable** (CWE-89) |
| **SQLi** — `ReadNews.aspx?id` | ✅ quote-collapse | ✅ | ✅ | ✅ time-based | **Vulnerable** (CWE-89) |
| **SQLi** — `login.aspx` `tbUsername` | ⚠️ candidate | ⚠️ candidate | ⚠️ candidate | ✅ **confirmed** | **Vulnerable** (CWE-89) |
| **Stored XSS** — `tbComment` | ✅ unencoded | ✅ predicted | ✅ probe | ✅ persistent | **Vulnerable** (CWE-79) |
| **Reflected XSS** — `NewsAd` `javascript:` URI | ❌ **missed** | ❌ **missed** | ❌ **missed** | ✅ **found** | **Vulnerable** (CWE-79) |
| **Reflected XSS** — `?id` `<`-tag | ✅ found the *block* | ✅ predicted block | ✅ encoded | ✅ | **Blocked** (Request Validation) |
| Missing CSP / CSRF / headers | ❌ out of focus | ❌ | ❌ | ✅ **found** | **Present** (hardening gaps) |

Two rows are the instructive ones:

- **`NewsAd` reflected XSS — found only by ZAP.** Manual/LLM/agent probed with `<`-based
  tag canaries, which ASP.NET Request Validation blocks, and concluded "reflected XSS
  mitigated." ZAP tried a `javascript:` URI (no `<`), which slips past Request Validation,
  and found a real reflected XSS. **A narrower payload set walked straight past a live
  vulnerability** — the single best argument for running an automated scanner alongside
  targeted testing. (We corrected our conclusion accordingly; see `08-owasp-zap.md`.)
- **`login.aspx` SQLi — confirmed only by ZAP**, because the human/LLM/agent kept to
  *detection-only* on the auth form per scope while ZAP actively tested it.

No method produced a *false positive* that survived verification — every reported issue
was tested, not merely asserted — but **coverage differed**, and ZAP's breadth caught two
real issues the focused methods missed.

## 6.3 Qualitative comparison

| Dimension | Manual | LLM-assisted | Agent | OWASP ZAP |
|-----------|--------|--------------|-------|-----------|
| **Entry-point completeness** | Medium | Medium-High | High (crawl) | **High** (spider+AJAX) |
| **Payload breadth** | Narrow (what you think of) | Medium | Medium | **Wide** (rule library) |
| **Prioritisation / payload choice** | Depends on tester | **High** | Mechanical | Mechanical |
| **Speed on a fixed scope** | Slow | Fast to decide | Fast + unattended | **Fast + unattended** |
| **False-positive / noise** | Low (if careful) | Medium if unverified | Low (verifies) | **Higher** (needs triage) |
| **Depth of confirmation** | Shallow by hand | Shallow (delegates) | **Deep** (sqlmap) | Medium (active rules) |
| **Safety / scope discipline** | Operator's judgement | Operator's judgement | **Enforced in code** | Context scope config |
| **Repeatability** | Low | Low | **High** | **High** |
| **Needs a human?** | Yes | Yes (to verify) | Review the run log | **Yes (to triage noise)** |

## 6.4 Conclusions

1. **They are complementary, not competing.** The strongest workflow is the one used
   here: *agent/ZAP crawl* for complete coverage → *ZAP's rule library* for payload
   breadth → *LLM ranks* and reasons → *sqlmap confirms depth* → *human triages and
   verifies*. Each covers the others' blind spot.
2. **Breadth beats cleverness for finding the unexpected.** The reflected XSS on `NewsAd`
   was invisible to the manual, LLM, and agent passes because they all reasoned their way
   to `<`-tag payloads and hit Request Validation. ZAP's dumb-but-wide `javascript:` URI
   payload found it. Automated scanners earn their keep precisely on the vectors you did
   not think to try.
3. **The LLM's weakness is trust.** It reasoned confidently that "reflected XSS is
   mitigated" — correct for the vector it imagined, wrong about the application. Its
   output must be executed and cross-checked, never believed. As an analyst-over-tool-
   output it is excellent; as an oracle it produces confident blind spots.
4. **The agent's strength is discipline, and that strength is only real because of the
   guardrails.** An unconstrained agent pointing sqlmap at the internet is a liability;
   the same agent constrained by `scope.yaml` + `guardrails.py` is safe to run
   unattended. The guardrails are what make "let the agent do it" a defensible choice.
5. **ZAP's cost is noise.** Alongside the real findings it reported 36 "potential" items
   and a stack of config observations — valuable, but someone has to triage them. Breadth
   and signal-to-noise trade off against each other; that is why the human stays in the loop.
