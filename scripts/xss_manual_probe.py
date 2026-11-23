#!/usr/bin/env python3
"""
xss_manual_probe.py — reflected-XSS detector for a single GET parameter.

Method: inject a unique, harmless canary that contains the HTML-significant
characters an XSS payload would need (`<`, `>`, `"`, `'`). Then inspect the
response and decide whether the canary came back:

  * REFLECTED-UNENCODED  -> the raw `<canary>` appears in the body. The browser
                            would parse it as a tag. This is exploitable XSS.
  * REFLECTED-ENCODED    -> only the HTML-entity form (`&lt;canary&gt;`) appears.
                            The app is encoding output; not exploitable this way.
  * NOT-REFLECTED        -> the canary does not appear at all.

We deliberately use a NON-EXECUTING marker (`<zzxsszz>`) rather than a live
`<script>alert()</script>`. Proving that `<` and `>` survive unencoded is
sufficient and precise evidence of the flaw, and keeps the probe harmless. The
genuinely-executing proof is captured separately with a real browser (see
evidence/xss/) for the write-up.

Usage:
    python scripts/xss_manual_probe.py --url "http://testaspnet.vulnweb.com/ReadNews.aspx?id=1" --param id
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

# Redact IP-like sequences so no submitter/server IP lands in committed evidence.
_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){2,3}")


def _redact(text):
    return _IP_RE.sub("[redacted-ip]", text) if text else text
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrails import Policy  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.normpath(os.path.join(HERE, "..", "evidence", "xss", "manual_probe.json"))


def set_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


def probe(url: str, param: str, policy: Policy) -> dict:
    policy.assert_in_scope(url)
    session = requests.Session()
    session.headers.update({"User-Agent": policy.http.get("user_agent", "sqli-xss-lab")})
    timeout = policy.http.get("timeout_seconds", 20)

    token = f"zzxss{uuid.uuid4().hex[:8]}zz"
    # Canary carries the characters a real payload would rely on.
    canary_raw = f"<{token}>\"'"
    test_url = set_param(url, param, canary_raw)

    r = session.get(test_url, timeout=timeout)
    body = r.text

    raw_tag = f"<{token}>"
    encoded_tag = html.escape(raw_tag)  # &lt;token&gt;

    reflected_unencoded = raw_tag in body
    reflected_encoded = encoded_tag in body
    quote_unencoded = ('"' + token) in body or (token + '"') in body

    if reflected_unencoded:
        verdict = "REFLECTED-UNENCODED (exploitable reflected XSS)"
        confidence = "high"
    elif reflected_encoded:
        verdict = "REFLECTED-ENCODED (output encoded; not exploitable via this vector)"
        confidence = "info"
    else:
        verdict = "NOT-REFLECTED"
        confidence = "info"

    # Capture a short surrounding snippet for the evidence file.
    snippet = None
    idx = body.find(token)
    if idx != -1:
        start, end = max(0, idx - 60), min(len(body), idx + 60)
        snippet = _redact(body[start:end])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "parameter": param,
        "canary": canary_raw,
        "test_url": test_url,
        "status": r.status_code,
        "reflected_unencoded": reflected_unencoded,
        "reflected_encoded": reflected_encoded,
        "quote_unencoded": quote_unencoded,
        "verdict": verdict,
        "confidence": confidence,
        "context_snippet": snippet,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Reflected-XSS reflection probe (single GET param).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    policy = Policy.load()
    report = probe(args.url, args.param, policy)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"[xss] target : {report['target']}")
    print(f"[xss] param  : {report['parameter']}")
    print(f"[xss] verdict: {report['verdict']}")
    if report["context_snippet"]:
        print(f"[xss] context: ...{report['context_snippet']}...")
    print(f"[xss] evidence: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
