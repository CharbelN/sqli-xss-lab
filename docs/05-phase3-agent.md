# 05 — Phase 3: Agent with Programmatic Guardrails

Phase 3 hands the whole pipeline to an **agent** — `scripts/agent_runner.py` — that
runs the approved tools with **no human in the loop**. The safety therefore cannot
come from a careful operator; it has to be enforced in code. That is the assignment's
core requirement:

> *"Add programmatic guardrails so sqlmap uses a risk and intensity level of 2 or 3,
> not 5. Keep all testing within the assigned lab application."*

Both halves of that sentence are implemented in `scripts/guardrails.py` and proven by
its self-test and by the agent's own run log.

## 3.1 What the agent does

```
load scope + guardrails
   └─ read evidence/crawl/entrypoints.json
       └─ for each in-scope URL parameter:
            ├─ manual differential SQLi probe      (fast triage)
            └─ sqlmap via the HARDENED argv only   (confirmation + bounded enum)
       └─ stored-XSS probe against the comment form
   └─ write evidence/agent/run.json
```

The agent never constructs a sqlmap command by hand. It calls
`Policy.build_sqlmap_argv(...)`, which is the *only* path to running sqlmap and which
is physically incapable of producing an out-of-policy command.

## 3.2 The guardrails, concretely

From the agent's real run log ([`evidence/agent/run.json`](../evidence/agent/run.json)):

```
[agent] scope = ['testaspnet.vulnweb.com']
[agent] guardrails: risk 2-3, level 2-3, 16 forbidden flags
[agent] 3 URL-parameter entry points to assess
```

Every sqlmap command the agent emits looks exactly like this (note the clamped
`--level 2 --risk 2`, the capped threads, and that enumeration stops at metadata):

```
python -m sqlmap -u "http://testaspnet.vulnweb.com/Comments.aspx?id=2" \
    --level 2 --risk 2 --batch --threads 2 --flush-session \
    --time-sec 5 --output-dir evidence/sqlmap \
    -p id --banner --current-db --current-user --is-dba --dbs
```

### How each requirement is enforced

| Requirement | Mechanism (`guardrails.py`) | Proof |
|-------------|------------------------------|-------|
| **Risk/level 2–3, never 5** | `clamp_risk()` / `clamp_level()` force the value into `[2,3]`; `--risk 5` → `3` | self-test: *"risk 5 clamped to ≤3"* |
| **Stay on the lab host** | `assert_in_scope()` host allowlist; everything else raises `ScopeViolation` | self-test: *"evil host rejected"*, *"subdomain-lookalike rejected"* |
| **No destructive actions** | 16-entry `forbidden_flags` denylist (`--os-shell`, `--sql-shell`, `--file-write`, `--dump-all`, `--all`, …) | self-test: *"forbidden flag --os-shell rejected"* |
| **Proof, not exfiltration** | agent only ever appends metadata enumeration (`--banner`, `--current-db`, `--dbs`) | run log / `build_sqlmap_argv` call site |
| **Be polite** | `--batch`, `--threads 2`, `--time-sec`, fixed identifying User-Agent | emitted argv |

Prove it yourself:

```bash
python scripts/guardrails.py --selftest
# 17 checks, all PASS — including that --risk 5 is clamped and --os-shell is refused.
```

## 3.3 Why "guardrails in code" beats "guardrails in the prompt"

An LLM agent can be *told* "use risk 2" and still, through confusion or a crafted
input, emit `--risk 5 --dump-all`. In this design that string never survives contact
with `build_sqlmap_argv()`: the level/risk are re-clamped and the forbidden flags are
rejected regardless of what the caller asked for. The policy is **auditable** (one
YAML file + one module) and **testable** (the self-test), which is exactly what you
want before letting automation point a SQL-injection tool at anything.

## 3.4 Running it

```bash
python scripts/agent_runner.py --dry-run     # show every action + hardened argv, run nothing destructive
python scripts/agent_runner.py               # full run (requires sqlmap available)
python scripts/agent_runner.py --no-sqlmap   # probes only
```

The dry run is the recommended way to *audit* the agent before a live run: it prints
the exact commands and writes them to `evidence/agent/run.json` without touching the
database.
