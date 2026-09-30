#!/usr/bin/env sh
# KryxAI one-command launcher.
#
# Creates an isolated virtualenv, installs the engine with the extras the demo
# actually needs, generates the synthetic corpus, and starts the API and the
# dashboard. Safe to re-run: an existing venv is reused unless --recreate is
# passed.
#
#   ./run_kryxai.sh              # start everything
#   ./run_kryxai.sh --recreate   # rebuild the venv from scratch
#   ./run_kryxai.sh --no-frontend  # engine and API only (no Node required)
#
# The [all] extra is deliberate. Installing the base package alone produces a
# working `kryxai` CLI but no uvicorn and no FastAPI, so the API silently fails
# to start. That failure cost us a debugging session once already.

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$REPO_ROOT"

RECREATE=0
WITH_FRONTEND=1
API_PORT="${KRYXAI_API_PORT:-8000}"
WEB_PORT="${KRYXAI_WEB_PORT:-5173}"

for arg in "$@"; do
  case "$arg" in
    --recreate)     RECREATE=1 ;;
    --no-frontend)  WITH_FRONTEND=0 ;;
    --api-port=*)   API_PORT="${arg#*=}" ;;
    --web-port=*)   WEB_PORT="${arg#*=}" ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $arg (try --help)" >&2
      exit 2
      ;;
  esac
done

VENV="$REPO_ROOT/.venv"
PY="$VENV/bin/python"

say() { printf '\n\033[1m[kryxai]\033[0m %s\n' "$1"; }

# --- 1. interpreter ------------------------------------------------------
say "locating a Python 3.11+ interpreter"
if [ ! -x "$PY" ]; then
  if command -v python3 >/dev/null 2>&1; then
    BASE_PY=python3
  elif command -v python >/dev/null 2>&1; then
    BASE_PY=python
  else
    echo "no python3 or python on PATH; install Python 3.11 or newer" >&2
    exit 1
  fi
  "$BASE_PY" - <<'PYCHK' || { echo "Python 3.11+ is required" >&2; exit 1; }
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PYCHK
else
  say "reusing existing venv at .venv"
fi

# --- 2. venv --------------------------------------------------------------
if [ "$RECREATE" = "1" ] || [ ! -x "$PY" ]; then
  say "creating virtualenv"
  [ "$RECREATE" = "1" ] && rm -rf "$VENV"
  "${BASE_PY:-python3}" -m venv "$VENV"
fi

# --- 3. install -----------------------------------------------------------
say "installing kryxai[all] (this is the step that makes the API work)"
"$PY" -m pip install --quiet --upgrade pip
# Editable so a judge can read the source they are demoing.
"$PY" -m pip install --quiet -e ".[all]"

# Verify rather than assume: this is the check whose absence cost us an hour.
say "verifying the API extra is actually importable"
"$PY" - <<'PYVERIFY'
import sys
missing = []
for mod in ("fastapi", "uvicorn"):
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)
if missing:
    sys.exit(
        "these are missing so the API cannot start: "
        + ", ".join(missing)
        + "\nre-run with --recreate, or: pip install -e .[all]"
    )
PYVERIFY

# --- 4. corpus ------------------------------------------------------------
CORPUS_DIR="$REPO_ROOT/demo_captures"
say "generating the synthetic demo corpus"
"$VENV/bin/kryxai" corpus "$CORPUS_DIR"

# --- 5. launch ------------------------------------------------------------
cleanup() {
  [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
  [ -n "${WEB_PID:-}" ] && kill "$WEB_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

say "starting API on 127.0.0.1:$API_PORT"
"$PY" -m uvicorn kryxai.api:app --host 127.0.0.1 --port "$API_PORT" &
API_PID=$!

# Wait for readiness instead of sleeping a fixed amount, so the dashboard is
# never pointed at an API that has not finished booting.
say "waiting for the API to become ready"
READY=0
i=0
while [ "$i" -lt 60 ]; do
  if "$PY" - "$API_PORT" <<'PYWAIT' 2>/dev/null
import sys, urllib.request
try:
    with urllib.request.urlopen(
        f"http://127.0.0.1:{sys.argv[1]}/health", timeout=1
    ) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PYWAIT
  then
    READY=1
    break
  fi
  i=$((i + 1))
  sleep 1
done

if [ "$READY" != "1" ]; then
  echo "API did not become ready on port $API_PORT" >&2
  exit 1
fi

if [ "$WITH_FRONTEND" = "1" ]; then
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm not found; the API is running but the dashboard was skipped." >&2
    echo "API only: http://127.0.0.1:$API_PORT/health" >&2
    wait "$API_PID"
    exit 0
  fi

  if [ ! -d "$REPO_ROOT/frontend/node_modules" ]; then
    say "installing dashboard dependencies"
    (cd frontend && npm install --no-fund --no-audit)
  fi

  say "starting dashboard on 127.0.0.1:$WEB_PORT"
  (
    cd frontend
    VITE_API_TARGET="http://127.0.0.1:$API_PORT" \
      npm run dev -- --port "$WEB_PORT" --host 127.0.0.1
  ) &
  WEB_PID=$!

  cat <<EOF

  Dashboard : http://127.0.0.1:$WEB_PORT
  API       : http://127.0.0.1:$API_PORT/health
  Corpus    : $CORPUS_DIR

  Pick a capture in demo_captures/ and scan it. 13_pop3_healthy.pcap and
  01_healthy_smtp_tls12.pcap are clean baselines; 02_star_ttlssuppressed_
  vodafone_style.pcap shows a suppressed STARTTLS capability.

  Ctrl-C stops both.
EOF
else
  cat <<EOF

  API       : http://127.0.0.1:$API_PORT/health
  Corpus    : $CORPUS_DIR

  Ctrl-C stops it.
EOF
fi

wait
