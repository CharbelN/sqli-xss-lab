# 06 — Comparison: Manual vs LLM vs Agent

The assignment's final task: *"Compare your manual, LLM, and agent results. Record
which entry points and possible issues each method found."* This is that record.

## 6.1 Coverage matrix — entry points discovered

| Entry point | Manual | LLM-assisted | Agent |
|-------------|:------:|:-----------:|:-----:|
| `Comments.aspx?id` (GET) | ✅ (knew the assigned target) | ✅ | ✅ (from crawl) |
| `ReadNews.aspx?id` (GET) | ⚠️ found by browsing | ✅ nominated quickly | ✅ (from crawl) |
| `ReadNews.aspx?NewsAd` (GET) | ❌ easy to miss | ✅ flagged as path-like | ✅ (from crawl) |
| `Comments.aspx` `tbComment` (POST) | ✅ | ✅ (predicted stored sink) | ✅ |
| `login.aspx` `tbUsername`/`tbPassword` | ✅ | ✅ (auth SQLi candidate) | ✅ (crawled, detection-only) |
| `Signup.aspx` fields | ❌ | ✅ | ✅ |

**Takeaway:** the **agent's crawler** gives the most *complete and repeatable*
enumeration (it does not get bored or forget a page). The **LLM** is best at **ranking**
that list — saying *which* of the six to test first and why. The **human** is reliable
on the obvious targets but most likely to miss a quiet one like `NewsAd`.

## 6.2 Findings matrix — issues confirmed

| Issue (entry point) | Manual | LLM-assisted | Agent | Ground truth |
|---------------------|:------:|:-----------:|:-----:|:-------------|
| **SQLi** — `Comments.aspx?id` | ✅ quote-collapse | ✅ predicted + verified | ✅ probe + sqlmap | **Vulnerable** (CWE-89) |
| **SQLi** — `ReadNews.aspx?id` | ✅ quote-collapse | ✅ | ✅ | **Vulnerable** (CWE-89) |
| **Stored XSS** — `tbComment` | ✅ canary unencoded | ✅ predicted the sink | ✅ stored probe | **Vulnerable** (CWE-79) |
| **Reflected XSS** — `?id` query | ✅ found the *block* | ✅ predicted the block | ✅ (encoded) | **Not exploitable** (Request Validation) |

No method produced a *false positive* that survived verification — because in every
phase the hypothesis was **tested in the lab**, not merely asserted. The reflected-XSS
row is the instructive one: a method that only *predicts* would have logged "reflected
XSS likely"; all three methods instead **checked** and correctly recorded a negative.

## 6.3 Qualitative comparison

| Dimension | Manual | LLM-assisted | Agent |
|-----------|--------|--------------|-------|
| **Entry-point completeness** | Medium | Medium-High | **High** (exhaustive crawl) |
| **Prioritisation / payload choice** | Depends on tester | **High** (went straight to the right tests) | Mechanical (tests everything in scope) |
| **Speed on a fixed scope** | Slow | Fast to decide | **Fast + unattended** |
| **False-positive risk** | Low (if careful) | **Medium if unverified** | Low (verifies with sqlmap) |
| **Depth of confirmation** | Shallow by hand (timing noisy) | Shallow (delegates) | **Deep** (sqlmap techniques) |
| **Safety / scope discipline** | Operator's judgement | Operator's judgement | **Enforced in code** |
| **Repeatability** | Low | Low | **High** (deterministic) |
| **Needs a human?** | Yes | Yes (to verify) | Only to review the run log |

## 6.4 Conclusions

1. **They are complementary, not competing.** The strongest workflow is the one used
   here: *agent crawls* for complete coverage → *LLM ranks* and picks payloads →
   *tools confirm* → *human reviews*. Each covers the others' blind spot.
2. **The LLM's weakness is trust.** Its single wrong call (reflected XSS) shows why its
   output must be executed, never believed. Used as an analyst-over-tool-output it is
   excellent; used as an oracle it invents findings.
3. **The agent's strength is discipline, and that strength is only real because of the
   guardrails.** An unconstrained agent pointing sqlmap at the internet is a liability;
   the same agent constrained by `scope.yaml` + `guardrails.py` is safe to run
   unattended. The guardrails are what make "let the agent do it" a defensible choice.
4. **Same bug, three lenses.** All three methods converged on the same two real
   vulnerabilities (SQLi on `id`, stored XSS on `tbComment`) and the same real negative
   (reflected XSS blocked) — which is the best possible outcome: agreement, reached
   independently, and verified against the application.
