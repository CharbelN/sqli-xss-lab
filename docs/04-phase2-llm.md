# 04 — Phase 2: LLM-Assisted Discovery & Testing

Phase 2 uses a large language model (Claude) the way a working tester actually
uses one today: as a fast analyst that reads tool output, nominates the likely
vulnerabilities, proposes payloads with reasoning, and then **drives the probes in
the lab** — while the human keeps judgement and the guardrails keep scope.

This file documents what the LLM was asked, what it concluded, and how its
conclusions were verified against reality (not taken on trust).

## 2.1 How the LLM was used

1. **Crawl & map.** The LLM was given `evidence/crawl/entrypoints.json` (the scoped
   crawler's output) and asked to identify the user-controlled inputs most likely to
   be injectable and why.
2. **Hypothesize.** For each candidate it proposed a vulnerability class and a minimal
   payload, with reasoning tied to the parameter's apparent role.
3. **Test in-lab.** Those hypotheses were executed with the repo's probes and `curl`,
   and the model interpreted the responses.
4. **Correct course.** When a hypothesis was wrong (reflected XSS), the model updated
   its model of the app rather than forcing the result.

## 2.2 LLM reasoning (as applied) and lab outcome

| Entry point | LLM hypothesis & reasoning | Lab outcome |
|-------------|----------------------------|-------------|
| `Comments.aspx?id` | *"`id` is a numeric row selector → almost certainly concatenated into a `WHERE id=` clause → SQLi. Test a bare single quote first."* | ✅ Confirmed — quote collapses the page to 0 bytes. |
| `ReadNews.aspx?id` | *"Same pattern as Comments; likely the same backend query shape → SQLi."* | ✅ Confirmed — same quote-collapse behaviour. |
| `ReadNews.aspx?id` (XSS) | *"If `id` is echoed, reflected XSS may be possible — inject `<svg/onload>`."* | ❌ Refuted — **ASP.NET Request Validation** blocks `<` in the query string. The LLM revised: *"query-string XSS is framework-mitigated; pivot to a stored sink."* |
| `Comments.aspx` `tbComment` | *"A free-text comment that is redisplayed is the canonical stored-XSS sink; Request Validation on POST bodies is often disabled. Submit a canary, then escalate to `<script>`."* | ✅ Confirmed — canary, `<img onerror>`, and `<script>` all stored unencoded. |
| `login.aspx` (`tbUsername`/`tbPassword`) | *"Auth forms are classic SQLi (`' OR '1'='1`), but test carefully and do not attempt account takeover — detection only."* | Noted as a candidate; kept to detection per scope (not exploited). |

The value the LLM added was **prioritisation and payload selection** — it went
straight to the single-quote test and to the stored-comment sink, and it correctly
predicted the Request-Validation wall before a single request was wasted on it.

## 2.3 Where the LLM needed the human / the guardrails

- **It cannot be trusted blind.** Every hypothesis above was *executed and checked*;
  the reflected-XSS prediction was wrong and only the live test caught it. An LLM that
  had simply *reported* "reflected XSS likely" would have produced a false positive.
- **Scope is not the LLM's job.** The model proposes; `scripts/guardrails.py` disposes.
  The host allowlist and the sqlmap risk/level clamp are what actually keep an
  over-eager suggestion (e.g. "just run sqlmap with `--risk 3 --level 5 --dump`") from
  turning into an out-of-policy action — see [05-phase3-agent.md](05-phase3-agent.md).
- **Noisy signals need real tooling.** The LLM correctly *deferred* time-based SQLi
  confirmation to sqlmap rather than guessing from a couple of jittery timings.

## 2.4 Representative prompts used

> *"Here is the crawler's entry-point inventory for an authorized lab host. Which
> parameters are the strongest SQL-injection candidates, and what is the single most
> informative first request for each? Keep everything to this one host."*

> *"The comment field stores my input. Give me a graduated set of XSS probes from a
> harmless reflection canary up to a proof that script would execute, without planting
> credential-stealing or redirecting code on a shared site."*

> *"Reflected XSS on `?id` returned an ASP.NET 'potentially dangerous value' page.
> What does that tell us about the app, and where should testing go next?"*

The point of recording these is reproducibility: a reader can re-run the same
reasoning and should reach the same, lab-verified, conclusions.
