#!/usr/bin/env python3
"""
xss_stored_probe.py — stored/persistent XSS detector for the comment form
(`tbComment`) on Comments.aspx.

ASP.NET Request Validation on this app blocks angle brackets in the *query
string* (reflected vector), but the comment POST body is stored and rendered
back without output-encoding. This script proves that safely:

  1. GET the comment page and harvest the ASP.NET hidden fields
     (__VIEWSTATE / __VIEWSTATEGENERATOR / __EVENTVALIDATION) — required or the
     POST is rejected.
  2. POST a single, harmless, uniquely-identifiable canary tag `<zzxss...zz>`
     as the comment. We use a NON-EXECUTING marker, never a live
     `<script>alert()</script>`, so we never plant working attack code on a
     shared host — proving the tag is stored *unencoded* is sufficient evidence.
  3. Re-render the page and check whether the raw `<canary>` is present
     (exploitable stored XSS) or only its HTML-encoded form (safe).

Scope is enforced by guardrails.Policy.

Usage:
    python scripts/xss_stored_probe.py --url "http://testaspnet.vulnweb.com/Comments.aspx?id=1"
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

# Redact IP-like sequences (3–4 dotted groups) so the submitter's IP, which the
# app stamps next to each comment, never lands in committed evidence.
_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){2,3}")


def _redact(text):
    return _IP_RE.sub("[redacted-ip]", text) if text else text

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrails import Policy  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.normpath(os.path.join(HERE, "..", "evidence", "xss", "stored_probe.json"))


def hidden(soup, name: str) -> str:
    el = soup.find("input", {"name": name})
    return el["value"] if el and el.has_attr("value") else ""


def probe(url: str, policy: Policy) -> dict:
    policy.assert_in_scope(url)
    session = requests.Session()
    session.headers.update({"User-Agent": policy.http.get("user_agent", "sqli-xss-lab")})
    timeout = policy.http.get("timeout_seconds", 20)

    # 1. harvest hidden fields
    r = session.get(url, timeout=timeout)
    soup = BeautifulSoup(r.text, "html.parser")

    token = f"zzxss{uuid.uuid4().hex[:8]}zz"
    canary = f"<{token}>"

    data = {
        "__VIEWSTATE": hidden(soup, "__VIEWSTATE"),
        "__VIEWSTATEGENERATOR": hidden(soup, "__VIEWSTATEGENERATOR"),
        "__EVENTVALIDATION": hidden(soup, "__EVENTVALIDATION"),
        "tbComment": canary,
        "btnSend": "Add Comment",
    }

    # 2. submit one canary comment
    post = session.post(url, data=data, timeout=timeout)

    # 3. re-render and inspect
    get = session.get(url, timeout=timeout)
    corpus = post.text + "\n" + get.text

    raw = f"<{token}>"
    enc = html.escape(raw)
    stored_unencoded = raw in corpus
    stored_encoded = enc in corpus

    snippet = None
    idx = post.text.find(token)
    source = post.text if idx != -1 else get.text
    idx = source.find(token)
    if idx != -1:
        start, end = max(0, idx - 70), min(len(source), idx + 40)
        snippet = _redact(source[start:end])

    if stored_unencoded:
        verdict = "STORED XSS (comment persisted and rendered UNENCODED)"
        confidence = "high"
    elif stored_encoded:
        verdict = "comment stored but output-encoded (not exploitable)"
        confidence = "info"
    else:
        verdict = "canary not found after submission"
        confidence = "info"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "field": "tbComment",
        "method": "POST",
        "canary": canary,
        "post_status": post.status_code,
        "stored_unencoded": stored_unencoded,
        "stored_encoded": stored_encoded,
        "verdict": verdict,
        "confidence": confidence,
        "context_snippet": snippet,
        "note": ("Non-executing canary used deliberately. A real payload such as "
                 "<script>alert(document.cookie)</script> or "
                 "<img src=x onerror=alert(1)> would execute in every visitor's browser."),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Stored-XSS probe for the comment form.")
    ap.add_argument("--url", default="http://testaspnet.vulnweb.com/Comments.aspx?id=1")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    policy = Policy.load()
    report = probe(args.url, policy)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"[xss-stored] target : {report['target']} (field tbComment)")
    print(f"[xss-stored] canary : {report['canary']}")
    print(f"[xss-stored] verdict: {report['verdict']}")
    if report["context_snippet"]:
        print(f"[xss-stored] context: ...{report['context_snippet']}...")
    print(f"[xss-stored] evidence: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
