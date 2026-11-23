#!/usr/bin/env python3
"""
guardrails.py — programmatic safety rails for the SQLi/XSS lab.

Everything that touches the network in this repo goes through here first.
The job of this module is to make it *structurally impossible* for the
automated tooling (and in particular the Phase-3 agent) to:

  1. contact any host other than the authorized lab target, or
  2. run sqlmap outside the assignment's risk/level 2–3 window, or
  3. hand sqlmap a destructive / post-exploitation flag.

Design note
-----------
Guardrails live in ONE place and are loaded from config/scope.yaml so that the
policy is auditable and the scripts stay dumb. A reviewer can read scope.yaml
and this file and know exactly what the agent is permitted to do — they do not
have to trust the agent's prompt.

Run `python scripts/guardrails.py --selftest` to prove the rails hold.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "[guardrails] PyYAML is required. Install with: pip install -r requirements.txt\n"
    )
    raise

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCOPE = os.path.normpath(os.path.join(HERE, "..", "config", "scope.yaml"))


class ScopeViolation(Exception):
    """Raised when a requested action falls outside the authorized scope."""


@dataclass
class Policy:
    """Parsed, validated view of config/scope.yaml."""

    allowed_hosts: set[str]
    allowed_schemes: set[str]
    deny_paths: list[str]
    seeds: list[str]
    sqlmap: dict
    xss: dict
    http: dict
    raw: dict = field(repr=False, default_factory=dict)

    # ---- loading ----------------------------------------------------------
    @classmethod
    def load(cls, path: str = DEFAULT_SCOPE) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        scope = data.get("scope", {})
        return cls(
            allowed_hosts={h.lower() for h in scope.get("allowed_hosts", [])},
            allowed_schemes={s.lower() for s in scope.get("allowed_schemes", [])},
            deny_paths=[p.lower() for p in scope.get("deny_paths", [])],
            seeds=scope.get("seeds", []),
            sqlmap=data.get("sqlmap", {}),
            xss=data.get("xss", {}),
            http=data.get("http", {}),
            raw=data,
        )

    # ---- URL / host scope -------------------------------------------------
    def assert_in_scope(self, url: str) -> str:
        """Return the URL if it is in scope, else raise ScopeViolation."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ScopeViolation(f"Not an absolute URL: {url!r}")
        if parsed.scheme.lower() not in self.allowed_schemes:
            raise ScopeViolation(
                f"Scheme {parsed.scheme!r} not allowed (allowed: {sorted(self.allowed_schemes)})"
            )
        host = parsed.hostname or ""
        if host.lower() not in self.allowed_hosts:
            raise ScopeViolation(
                f"Host {host!r} is OUT OF SCOPE. Allowed hosts: {sorted(self.allowed_hosts)}"
            )
        path = (parsed.path or "/").lower()
        for deny in self.deny_paths:
            if path.startswith(deny):
                raise ScopeViolation(f"Path {path!r} is explicitly denied by scope.yaml")
        return url

    def is_in_scope(self, url: str) -> bool:
        try:
            self.assert_in_scope(url)
            return True
        except ScopeViolation:
            return False

    # ---- sqlmap argument hardening ---------------------------------------
    def clamp_level(self, requested: int | None) -> int:
        cfg = self.sqlmap.get("level", {})
        lo, hi, dflt = cfg.get("min", 2), cfg.get("max", 3), cfg.get("default", 2)
        if requested is None:
            return dflt
        return max(lo, min(hi, int(requested)))

    def clamp_risk(self, requested: int | None) -> int:
        cfg = self.sqlmap.get("risk", {})
        lo, hi, dflt = cfg.get("min", 2), cfg.get("max", 3), cfg.get("default", 2)
        if requested is None:
            return dflt
        return max(lo, min(hi, int(requested)))

    def forbidden_flags(self) -> set[str]:
        return set(self.sqlmap.get("forbidden_flags", []))

    def reject_forbidden(self, extra_args: list[str]) -> None:
        """Raise if the caller tries to smuggle in a banned flag."""
        banned = self.forbidden_flags()
        for arg in extra_args:
            token = arg.split("=", 1)[0]
            if token in banned:
                raise ScopeViolation(
                    f"Flag {token!r} is forbidden by scope.yaml (destructive / post-exploitation)"
                )

    def build_sqlmap_argv(
        self,
        url: str,
        *,
        level: int | None = None,
        risk: int | None = None,
        extra_args: list[str] | None = None,
        output_dir: str | None = None,
        sqlmap_bin: str | None = None,
    ) -> list[str]:
        """
        Produce a vetted sqlmap command line. The returned argv is guaranteed to:
          * target only an in-scope URL,
          * carry a level/risk clamped into the 2–3 window,
          * contain no forbidden flags,
          * run non-interactively and cap threads.
        """
        self.assert_in_scope(url)
        extra_args = list(extra_args or [])
        self.reject_forbidden(extra_args)

        lvl = self.clamp_level(level)
        rsk = self.clamp_risk(risk)
        threads_max = int(self.sqlmap.get("threads_max", 2))
        ua = self.http.get("user_agent", "sqli-xss-lab")

        # Resolve how to invoke sqlmap, in order of preference:
        #   1. explicit sqlmap_bin argument,
        #   2. $SQLMAP_PY env var pointing at sqlmap.py,
        #   3. a repo-bundled clone at .tools/sqlmap/sqlmap.py,
        #   4. a `sqlmap` console script on PATH,
        #   5. `python -m sqlmap`.
        import shutil
        bundled_candidates = [
            os.path.normpath(os.path.join(HERE, "..", ".tools", "sqlmap", "sqlmap.py")),
            os.path.normpath(os.path.join(HERE, "..", ".tools", "sqlmap-pkg", "sqlmap", "sqlmap.py")),
        ]
        bundled = next((p for p in bundled_candidates if os.path.exists(p)), None)
        if sqlmap_bin:
            argv = [sqlmap_bin]
        elif os.environ.get("SQLMAP_PY"):
            argv = [sys.executable, os.environ["SQLMAP_PY"]]
        elif bundled:
            argv = [sys.executable, bundled]
        elif shutil.which("sqlmap"):
            argv = ["sqlmap"]
        else:
            argv = [sys.executable, "-m", "sqlmap"]

        argv += [
            "-u", url,
            "--level", str(lvl),
            "--risk", str(rsk),
            "--batch",                       # never block on a prompt
            "--threads", str(threads_max),
            "--user-agent", ua,
            "--flush-session",               # reproducible runs
        ]
        if self.sqlmap.get("time_sec"):
            argv += ["--time-sec", str(self.sqlmap["time_sec"])]
        if output_dir:
            argv += ["--output-dir", output_dir]
        argv += extra_args
        return argv


# ---------------------------------------------------------------------------
# Self-test: prove the rails hold. Exit non-zero if any assertion fails.
# ---------------------------------------------------------------------------
def _selftest() -> int:
    p = Policy.load()
    failures: list[str] = []

    def check(name: str, cond: bool):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    print("guardrails self-test")
    print("-" * 60)

    # In-scope URL accepted
    check("in-scope lab URL accepted",
          p.is_in_scope("http://testaspnet.vulnweb.com/Comments.aspx?id=1"))

    # Off-scope hosts rejected
    check("different host rejected", not p.is_in_scope("http://example.com/"))
    check("evil host rejected", not p.is_in_scope("http://attacker.evil/steal"))
    check("subdomain-lookalike rejected",
          not p.is_in_scope("http://testaspnet.vulnweb.com.evil.com/"))

    # risk/level clamping
    check("risk 5 clamped to <=3", p.clamp_risk(5) <= 3)
    check("level 5 clamped to <=3", p.clamp_level(5) <= 3)
    check("risk 1 clamped to >=2", p.clamp_risk(1) >= 2)
    check("default risk is 2", p.clamp_risk(None) == 2)
    check("default level is 2", p.clamp_level(None) == 2)

    # forbidden flags rejected
    for bad in ("--os-shell", "--sql-shell", "--file-write", "--dump-all"):
        try:
            p.build_sqlmap_argv(
                "http://testaspnet.vulnweb.com/Comments.aspx?id=1",
                extra_args=[bad],
            )
            check(f"forbidden flag {bad} rejected", False)
        except ScopeViolation:
            check(f"forbidden flag {bad} rejected", True)

    # off-scope target refused even when building argv
    try:
        p.build_sqlmap_argv("http://example.com/x?id=1")
        check("off-scope sqlmap target refused", False)
    except ScopeViolation:
        check("off-scope sqlmap target refused", True)

    # a well-formed argv really is clamped
    argv = p.build_sqlmap_argv(
        "http://testaspnet.vulnweb.com/Comments.aspx?id=1", level=5, risk=5
    )
    check("built argv caps level at 3", "3" == argv[argv.index("--level") + 1])
    check("built argv caps risk at 3", "3" == argv[argv.index("--risk") + 1])
    check("built argv is non-interactive", "--batch" in argv)

    print("-" * 60)
    if failures:
        print(f"RESULT: {len(failures)} FAILED -> {failures}")
        return 1
    print("RESULT: all guardrail checks passed.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Engagement guardrails (scope + sqlmap hardening).")
    ap.add_argument("--selftest", action="store_true", help="run the guardrail self-test")
    ap.add_argument("--check-url", metavar="URL", help="print whether a URL is in scope")
    ap.add_argument(
        "--show-sqlmap",
        metavar="URL",
        help="print the hardened sqlmap argv that would be used for URL",
    )
    args = ap.parse_args()

    if args.selftest:
        return _selftest()
    if args.check_url:
        p = Policy.load()
        print("IN SCOPE" if p.is_in_scope(args.check_url) else "OUT OF SCOPE")
        return 0
    if args.show_sqlmap:
        p = Policy.load()
        print(" ".join(p.build_sqlmap_argv(args.show_sqlmap)))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
