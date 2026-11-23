#!/usr/bin/env python3
"""
crawl_entrypoints.py — scoped crawler that inventories where user input enters
the lab application: URL query parameters, HTML form fields, and their methods.

The output (evidence/crawl/entrypoints.json) is the shared input for every later
phase: the manual probes, the LLM analysis, and the Phase-3 agent all decide
*what to test* from this file.

Scope is enforced by guardrails.Policy — the crawler physically cannot follow a
link off the authorized host.

Usage:
    python scripts/crawl_entrypoints.py
    python scripts/crawl_entrypoints.py --max-pages 60 --out evidence/crawl/entrypoints.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrails import Policy, ScopeViolation  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.normpath(os.path.join(HERE, "..", "evidence", "crawl", "entrypoints.json"))


def normalize(url: str) -> str:
    """Drop fragments so we don't crawl the same page twice."""
    p = urlparse(url)
    return p._replace(fragment="").geturl()


def crawl(policy: Policy, max_pages: int, max_depth: int):
    session = requests.Session()
    session.headers.update({"User-Agent": policy.http.get("user_agent", "sqli-xss-lab")})
    timeout = policy.http.get("timeout_seconds", 20)

    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    for seed in policy.seeds:
        if policy.is_in_scope(seed):
            queue.append((normalize(seed), 0))

    pages: list[dict] = []
    query_params: dict[str, dict] = {}   # keyed by "path?param"
    forms: list[dict] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen:
            continue
        seen.add(url)

        try:
            policy.assert_in_scope(url)
        except ScopeViolation:
            continue

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            pages.append({"url": url, "error": str(exc)})
            continue

        page = {
            "url": url,
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "depth": depth,
        }
        pages.append(page)

        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            continue

        # --- record query-string parameters as GET entry points -------------
        parsed = urlparse(url)
        if parsed.query:
            for pname, pvals in parse_qs(parsed.query).items():
                key = f"{parsed.path}?{pname}"
                qp = query_params.setdefault(
                    key,
                    {
                        "type": "url-parameter",
                        "method": "GET",
                        "path": parsed.path,
                        "parameter": pname,
                        "example_url": url,
                        "sample_value": pvals[0] if pvals else "",
                    },
                )
                qp["example_url"] = url

        soup = BeautifulSoup(resp.text, "html.parser")

        # --- record HTML forms as entry points ------------------------------
        for form in soup.find_all("form"):
            action = form.get("action") or url
            action_url = normalize(urljoin(url, action))
            method = (form.get("method") or "GET").upper()
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                fields.append(
                    {
                        "name": name,
                        "tag": inp.name,
                        "type": inp.get("type", "text"),
                    }
                )
            forms.append(
                {
                    "type": "html-form",
                    "found_on": url,
                    "action": action_url,
                    "method": method,
                    "in_scope": policy.is_in_scope(action_url),
                    "fields": fields,
                }
            )

        # --- enqueue in-scope links -----------------------------------------
        if depth < max_depth:
            for a in soup.find_all("a", href=True):
                nxt = normalize(urljoin(url, a["href"]))
                if policy.is_in_scope(nxt) and nxt not in seen:
                    queue.append((nxt, depth + 1))

        time.sleep(0.2)  # be polite

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": sorted(policy.allowed_hosts),
        "stats": {
            "pages_crawled": len(pages),
            "url_parameters": len(query_params),
            "forms": len(forms),
        },
        "pages": pages,
        "url_parameter_entrypoints": list(query_params.values()),
        "form_entrypoints": forms,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Scoped entry-point crawler.")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--max-pages", type=int, default=None)
    ap.add_argument("--max-depth", type=int, default=None)
    args = ap.parse_args()

    policy = Policy.load()
    max_pages = args.max_pages or policy.http.get("max_crawl_pages", 40)
    max_depth = args.max_depth or policy.http.get("max_crawl_depth", 2)

    print(f"[crawl] scope = {sorted(policy.allowed_hosts)}  max_pages={max_pages} depth={max_depth}")
    result = crawl(policy, max_pages, max_depth)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    s = result["stats"]
    print(f"[crawl] pages={s['pages_crawled']}  url-params={s['url_parameters']}  forms={s['forms']}")
    print(f"[crawl] wrote {args.out}")
    # Human-readable summary of entry points
    print("\nURL-parameter entry points:")
    for e in result["url_parameter_entrypoints"]:
        print(f"  {e['method']} {e['path']}?{e['parameter']}=  (e.g. {e['sample_value']!r})")
    print("\nForm entry points:")
    for f in result["form_entrypoints"]:
        names = ", ".join(x["name"] for x in f["fields"]) or "(no named fields)"
        print(f"  {f['method']} {f['action']}  fields: {names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
