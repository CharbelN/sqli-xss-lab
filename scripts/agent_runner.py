#!/usr/bin/env python3
"""
agent_runner.py — the Phase-3 "agent": a deterministic orchestrator that runs
the approved tools end-to-end under the programmatic guardrails.

The assignment's Phase 3 asks for *an agent that runs the approved tools* with
*programmatic guardrails so sqlmap uses risk/level 2 or 3, not 5* and keeps all
testing inside the lab. This runner is that agent's executor: whether a human,
an LLM, or a cron job triggers it, the actions it can take are fixed by
config/scope.yaml and enforced by scripts/guardrails.py. The "intelligence"
(which entry points look interesting) comes from the crawl output; the
"safety" is non-negotiable and lives in code, not in a prompt.

Pipeline
--------
  1. Load scope + guardrails.
  2. Read the crawler's entry-point inventory (or crawl if missing).
  3. For every in-scope URL parameter:
       a. run the manual differential SQLi probe (fast triage), then
       b. run sqlmap via the hardened argv (risk/level clamped to 2–3,
          forbidden flags impossible, bounded enumeration only).
  4. Run the stored-XSS probe against the comment form.
  5. Write a machine-readable run log to evidence/agent/run.json.

Every sqlmap invocation is printed before it runs so the operator can audit
exactly what the agent did. Nothing destructive is reachable.

Usage:
    python scripts/agent_runner.py                 # full guardrailed run
    python scripts/agent_runner.py --dry-run       # show planned actions only
    python scripts/agent_runner.py --no-sqlmap     # skip sqlmap (probes only)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrails import Policy, ScopeViolation  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CRAWL_OUT = os.path.join(ROOT, "evidence", "crawl", "entrypoints.json")
AGENT_DIR = os.path.join(ROOT, "evidence", "agent")
SQLMAP_DIR = os.path.join(ROOT, "evidence", "sqlmap")


def log(msg: str) -> None:
    print(f"[agent] {msg}", flush=True)


def ensure_crawl(policy: Policy) -> dict:
    if not os.path.exists(CRAWL_OUT):
        log("no crawl inventory found; running crawler first")
        subprocess.run([sys.executable, os.path.join(HERE, "crawl_entrypoints.py")], check=True)
    with open(CRAWL_OUT, "r", encoding="utf-8") as fh:
        return json.load(fh)


def sqlmap_available() -> bool:
    bundles = [
        os.path.join(ROOT, ".tools", "sqlmap", "sqlmap.py"),
        os.path.join(ROOT, ".tools", "sqlmap-pkg", "sqlmap", "sqlmap.py"),
    ]
    if os.environ.get("SQLMAP_PY") and os.path.exists(os.environ["SQLMAP_PY"]):
        return True
    if any(os.path.exists(b) for b in bundles):
        return True
    if shutil.which("sqlmap"):
        return True
    try:
        r = subprocess.run(
            [sys.executable, "-m", "sqlmap", "--version"],
            capture_output=True, timeout=60,
        )
        return r.returncode == 0
    except Exception:
        return False


def run_sqlmap(policy: Policy, url: str, param: str, dry_run: bool) -> dict:
    """Build a hardened argv and (optionally) execute sqlmap against one param."""
    # Bounded enumeration only — proof of impact, not data exfiltration.
    enum = ["-p", param, "--banner", "--current-db", "--current-user", "--is-dba", "--dbs"]
    try:
        argv = policy.build_sqlmap_argv(
            url,
            level=policy.sqlmap["level"]["default"],
            risk=policy.sqlmap["risk"]["default"],
            extra_args=enum,
            output_dir=SQLMAP_DIR,
        )
    except ScopeViolation as exc:
        return {"url": url, "param": param, "skipped": f"scope violation: {exc}"}

    printable = " ".join(argv)
    log(f"sqlmap argv: {printable}")
    record = {"url": url, "param": param, "argv": argv, "command": printable}

    if dry_run:
        record["dry_run"] = True
        return record

    logfile = os.path.join(SQLMAP_DIR, f"sqlmap_{param}_{_slug(url)}.log")
    os.makedirs(SQLMAP_DIR, exist_ok=True)
    # Feed newlines on stdin: sqlmap shows a one-off "Press Enter to continue"
    # notice on bleeding-edge Python versions; --batch handles every other prompt.
    with open(logfile, "w", encoding="utf-8") as fh:
        proc = subprocess.run(
            argv, stdout=fh, stderr=subprocess.STDOUT,
            input=b"\n" * 50, timeout=1800,
        )
    record["returncode"] = proc.returncode
    record["log"] = os.path.relpath(logfile, ROOT)
    # quick post-parse: did sqlmap declare the parameter injectable?
    try:
        text = open(logfile, "r", encoding="utf-8", errors="replace").read()
        record["injectable"] = ("is vulnerable" in text) or ("sqlmap identified the following injection point" in text)
    except OSError:
        record["injectable"] = None
    return record


def run_probe(script: str, args: list[str]) -> dict:
    cmd = [sys.executable, os.path.join(HERE, script)] + args
    log("probe: " + " ".join(cmd[1:]))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return {"script": script, "args": args, "returncode": proc.returncode,
            "stdout": proc.stdout.strip()}


def _slug(url: str) -> str:
    """A short, readable identifier from a URL's last path segment."""
    from urllib.parse import urlparse
    base = (urlparse(url).path.rsplit("/", 1)[-1] or "root")
    return "".join(c if c.isalnum() else "_" for c in base).strip("_") or "root"


def main() -> int:
    ap = argparse.ArgumentParser(description="Phase-3 guardrailed agent runner.")
    ap.add_argument("--dry-run", action="store_true", help="print planned actions, run nothing destructive")
    ap.add_argument("--no-sqlmap", action="store_true", help="run probes only, skip sqlmap")
    args = ap.parse_args()

    policy = Policy.load()
    os.makedirs(AGENT_DIR, exist_ok=True)

    run = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": sorted(policy.allowed_hosts),
        "guardrails": {
            "risk": policy.sqlmap["risk"],
            "level": policy.sqlmap["level"],
            "forbidden_flags": sorted(policy.forbidden_flags()),
        },
        "sqli": [],
        "sqlmap": [],
        "xss": [],
    }

    log(f"scope = {sorted(policy.allowed_hosts)}")
    log(f"guardrails: risk {policy.sqlmap['risk']['min']}-{policy.sqlmap['risk']['max']}, "
        f"level {policy.sqlmap['level']['min']}-{policy.sqlmap['level']['max']}, "
        f"{len(policy.forbidden_flags())} forbidden flags")

    inventory = ensure_crawl(policy)
    params = inventory.get("url_parameter_entrypoints", [])
    log(f"{len(params)} URL-parameter entry points to assess")

    have_sqlmap = (not args.no_sqlmap) and sqlmap_available()
    if not args.no_sqlmap and not have_sqlmap:
        log("WARNING: sqlmap not found on PATH or as module; running probes only")

    for ep in params:
        url = ep["example_url"]
        param = ep["parameter"]
        if not policy.is_in_scope(url):
            log(f"SKIP out-of-scope {url}")
            continue
        log(f"--- entry point: {ep['method']} {ep['path']}?{param} ---")

        # (a) fast manual triage
        probe = run_probe("sqli_manual_probe.py",
                          ["--url", url, "--param", param,
                           "--out", os.path.join(SQLMAP_DIR, f"manual_probe_{param}_{_slug(url)}.json")])
        run["sqli"].append(probe)

        # (b) authoritative sqlmap under guardrails
        if have_sqlmap:
            run["sqlmap"].append(run_sqlmap(policy, url, param, args.dry_run))
        elif args.dry_run:
            run["sqlmap"].append(run_sqlmap(policy, url, param, True))

    # stored XSS on the comment form
    xss = run_probe("xss_stored_probe.py", [])
    run["xss"].append(xss)

    out = os.path.join(AGENT_DIR, "run.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(run, fh, indent=2)
    log(f"run log -> {os.path.relpath(out, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
