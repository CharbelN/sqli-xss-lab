# 01 — Methodology

This lab assesses one ASP.NET application for **SQL injection** and **XSS /
JavaScript injection** using three independent methods and then compares them:

1. **Manual** — a human testing by hand (curl / browser) and with small, purpose-built probes.
2. **LLM-assisted** — a large language model crawls, reasons about likely issues, and drives the probes in the lab.
3. **Agent** — an orchestrator runs the approved tools automatically under programmatic guardrails.

The point of running all three is not redundancy — it is to show **where each
method is strong and where it is blind**, which is the deliverable in
[`06-comparison.md`](06-comparison.md).

## Standards mapping

Testing follows the structure of the **OWASP Web Security Testing Guide (WSTG)**:

| Activity | WSTG ID | What we do |
|----------|---------|------------|
| Information gathering / mapping | WSTG-INFO-* | Crawl the app, inventory entry points (`scripts/crawl_entrypoints.py`) |
| Testing for SQL Injection | **WSTG-INPV-05** | Error/boolean/time differential probes + sqlmap confirmation |
| Testing for Reflected XSS | **WSTG-INPV-01** | Canary reflection probe on URL parameters |
| Testing for Stored XSS | **WSTG-INPV-02** | Canary comment submission + rendered-output inspection |

Findings are classified with standard identifiers:

- **SQL Injection** → CWE-89, OWASP Top 10 2021 **A03: Injection**
- **Cross-Site Scripting** → CWE-79, OWASP Top 10 2021 **A03: Injection**

## Phase 1 — Manual

1. **Map entry points.** Crawl the site (scoped) and list every URL parameter and
   form field a user can influence. Output: `evidence/crawl/entrypoints.json`.
2. **SQL injection.** For each interesting parameter run the differential probe
   (`scripts/sqli_manual_probe.py`): baseline vs. single-quote, boolean true/false,
   and time-delay payloads. Then confirm with **sqlmap** at risk/level 2.
3. **XSS.** Probe URL parameters for unencoded reflection
   (`scripts/xss_manual_probe.py`) and the comment form for stored XSS
   (`scripts/xss_stored_probe.py`), using harmless canaries.

## Phase 2 — LLM-assisted

The LLM (Claude) is given the crawl output and the application's responses and is
asked to (a) nominate the most promising injection points and (b) propose payloads,
with reasoning. It then **executes those tests in the lab** via the same scripts.
The prompts used and the model's reasoning/results are recorded in
[`04-phase2-llm.md`](04-phase2-llm.md). This mirrors how a modern tester actually
uses an LLM: as a fast analyst over tool output, not as an oracle to be trusted blindly.

## Phase 3 — Agent

`scripts/agent_runner.py` is the "chosen agent." It executes the whole pipeline —
crawl → triage probe → guardrailed sqlmap → stored-XSS probe — with **no human in
the loop**, and therefore with the guardrails doing the safety work. The
assignment's specific requirement (*"Add programmatic guardrails so sqlmap uses a
risk and intensity level of 2 or 3, not 5. Keep all testing within the assigned lab
application."*) is implemented in `scripts/guardrails.py` and proven by its
self-test. See [`05-phase3-agent.md`](05-phase3-agent.md).

## Tooling summary

| Tool | Role | Guardrail |
|------|------|-----------|
| `crawl_entrypoints.py` | entry-point discovery | host allowlist |
| `sqli_manual_probe.py` | fast SQLi triage (error/boolean/time) | host allowlist |
| `xss_manual_probe.py` | reflected-XSS reflection check | host allowlist |
| `xss_stored_probe.py` | stored-XSS via comment form | host allowlist, single canary |
| **sqlmap** | authoritative SQLi confirmation + bounded enum | risk/level 2–3, flag denylist |
| **OWASP ZAP** | full passive + active scan (SQLi/XSS rules) | scoped context, SQLi/XSS rules only |
| `agent_runner.py` | Phase-3 orchestrator | all of the above |
