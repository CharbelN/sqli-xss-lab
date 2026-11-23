#!/usr/bin/env bash
# Run the OWASP ZAP Automation Framework plan headless via Docker, scoped to the
# authorized lab host, writing HTML + JSON reports into evidence/zap/.
#
# Phase 1 (ZAP portion). Requires a running Docker daemon.
# Usage:  bash scripts/run_zap.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZAP_DIR="$REPO_ROOT/zap"
OUT_DIR="$REPO_ROOT/evidence/zap"
IMAGE="ghcr.io/zaproxy/zaproxy:stable"

mkdir -p "$OUT_DIR"

echo "[zap] checking Docker daemon..."
if ! docker info >/dev/null 2>&1; then
  echo "[zap] ERROR: Docker daemon is not running." >&2
  echo "      Start Docker Desktop (or 'systemctl start docker'), wait for it to be ready, then re-run." >&2
  exit 1
fi

echo "[zap] pulling image $IMAGE (first run only)..."
docker pull "$IMAGE"

echo "[zap] running Automation Framework plan (scoped to testaspnet.vulnweb.com)..."
docker run --rm \
  -v "$ZAP_DIR:/zap/wrk:rw" \
  -v "$OUT_DIR:/zap/out:rw" \
  "$IMAGE" zap.sh -cmd -autorun /zap/wrk/automation-plan.yaml || true

echo "[zap] reports written to: $OUT_DIR"
ls -la "$OUT_DIR" || true
