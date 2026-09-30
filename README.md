# KryxAI

Passive SMTP / IMAP / POP3 mail-security forensics from packet captures.

KryxAI reads a capture that already exists and reports what the traffic shows:
whether a mail server advertised STARTTLS and then quietly stopped offering it,
what TLS version and cipher each session actually negotiated, whether the
certificate chain validates, and which statutory control each observation maps
to. **It never probes, scans, probes or modifies anything.** A clean report is
not proof of a compliant control — it reflects only the traffic in the capture
you supplied.

## Why this exists

Indian mail servers are widely reported to strip the `STARTTLS` capability from
EHLO replies — a pattern associated with Vodafone-style intercepting
middleboxes. The capability is replaced with a token such as `XXXXXXXA` so the
client proceeds in plaintext believing no upgrade was on offer. This is
*K1 capability suppression*, and it is the signature KryxAI was built to detect
and evidence.

## Quick start

One command sets up everything and starts the demo:

```bash
./run_kryxai.sh              # POSIX
run_kryxai.bat               # Windows
```

It creates a virtualenv, installs `.[all]`, generates the synthetic corpus,
waits for the API to actually answer, then starts the dashboard. Useful flags:
`--recreate` (rebuild the venv), `--no-frontend` (engine only, no Node
needed), `--api-port=N`, `--web-port=N`.

Install the `all` extra, not the base package. The base install gives you a
working `kryxai` CLI but no uvicorn or FastAPI, so the API fails to start —
the launcher verifies both imports and tells you if either is missing.

## Install

```bash
python -m pip install -e ".[all]"      # everything
python -m pip install -e .              # core engine only
```

The core engine needs only `cryptography`, `pydantic` and `pydantic-settings`,
and is enough for `kryxai scan` to produce JSON and HTML reports. Extras:

| Extra | Adds | Needed for |
|---|---|---|
| `api` | FastAPI, uvicorn | the HTTP API |
| `reports` | ReportLab, Jinja2 | PDF output |
| `model` | onnxruntime, numpy | optional ONNX fusion |
| `dev` | pytest, httpx2, api + reports | running the test suite |

PDF is deliberately optional: a base install still runs a full scan and writes
JSON and HTML, and the CLI says explicitly that the PDF was skipped rather than
leaving you to infer it from a missing file.

## Where data is written

Writable state goes to a per-user data directory, never into the installed
package:

| Platform | Location |
|---|---|
| Windows | `%LOCALAPPDATA%\KryxAI` |
| Linux / macOS | `$XDG_DATA_HOME/kryxai`, else `~/.local/share/kryxai` |
| Source checkout | the repository root |
| Anywhere | `KRYXAI_HOME` overrides all of the above |

That holds the SQLite evidence database, the `reports/` directory, and the
RSA-3072 report-signing key. Override the individual paths with
`KRYXAI_DATABASE_PATH`, `KRYXAI_REPORTS_DIR` and `KRYXAI_REPORT_KEYS_DIR`.

## Use

```bash
# generate the synthetic demo corpus (17 captures, all clearly labelled fake)
kryxai corpus corpus

# analyse a capture
kryxai scan corpus/02_star_ttlssuppressed_vodafone_style.pcap

# check the evidence chain
kryxai chain

# what this build can and cannot see
kryxai capabilities
```

Library:

```python
from pathlib import Path
from kryxai.config import Settings
from kryxai.engine import run_scan
from kryxai.store import Store
from kryxai.reports import builder

store = Store("evidence.db")
result = run_scan(Path("office.pcap"), Settings(), store=store)
print(result.report["posture"]["grade"], result.report["counts"]["findings"])
builder.write(result.report, Path("reports"), Settings(), langs=["en", "hi"])
```

## HTTP API

```bash
uvicorn kryxai.api:app --port 8000
```

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/health` | liveness, version, chain id, anchor posture |
| `GET`  | `/api/v1/capabilities` | what is and is not observable |
| `POST` | `/api/v1/scan` | analyse a capture already on the server |
| `POST` | `/api/v1/upload` | upload and analyse a capture |
| `GET`  | `/api/v1/report/{scan_id}` | full report JSON (or Hindi HTML) |
| `GET`  | `/api/v1/report/{scan_id}/html?lang=en\|hi` | rendered report |
| `GET`  | `/api/v1/chain` | evidence chain verification and blocks |

Report bodies are held in process memory, so report retrieval does not survive a
restart. The evidence chain is durable in SQLite.

Frontend:

```bash
cd frontend
npm install
npm run dev            # proxies to 127.0.0.1:8000
```

## What it detects

**STARTTLS suppression (the India focus)**
- `K1_capability_suppression` — the capability was advertised, then removed or
  replaced with a placeholder token.
- `K2_cross_flow_inconsistency` — the same server advertises STARTTLS on some
  sessions and not others.
- `K3_refused_upgrade` — the client asked, the server refused.
- `K4_plaintext_after_upgrade` — a negotiated upgrade followed by cleartext
  protocol, which no honest server does.

**Transport** — TLS 1.0–1.3 version, cipher suite, key-exchange group,
signature algorithm, forward secrecy.

**Certificates** — SAN/CN matching, validity judged *at capture time* (not
analysis time), key strength, signature algorithm, chain-signature verification.

**Posture** — a 0–100 score across transport encryption, certificate hygiene,
forward secrecy, tamper resistance and evidence integrity, with a letter grade.
Dimensions that could not be measured are reported as `not_assessed` rather
than scored as zero.

**Compliance** — DPDP Act 2023 and CERT-In Directions 20(3)/2022 mapping in
`kryxai/compliance/sources.json`.

## Limits you must understand

- **TLS 1.3 certificates are not visible.** The server certificate and
  handshake signature are inside encrypted handshake records. KryxAI reports
  this as a visibility limit; it cannot assess a TLS 1.3 chain passively, and a
  TLS 1.3 result is never a pass.
- **A middlebox that rewrites identically in both directions is
  indistinguishable from a server.** Only out-of-band comparison resolves that.
- **Encrypted payload content is never decrypted or retained.**
- **Passive only.** KryxAI cannot tell a hostile middlebox from a misconfigured
  one, and cannot attribute intent.
- **Not legal advice and not a compliance determination.**
- **No authoritative CERT-In IoC feed.** There is no verified machine-readable
  CERT-In API. The bundled feed is an empty, clearly-unverified example;
  operator-supplied files are the supported path and every feed records its own
  provenance.
- **Alerting is opt-in and is the only outbound call KryxAI makes.** Everything
  else is observation of a capture that already exists.

## Alerting

Optional. When a scan produces a finding at or above
`KRYXAI_ALERT_MIN_SEVERITY` (default `high`), the configured channels are
notified. With no channel configured, KryxAI sends nothing — which is the
default install, and the reason a stock deployment makes no network call at all.

```bash
KRYXAI_ALERTS_ENABLED=true
KRYXAI_ALERT_MIN_SEVERITY=high      # critical|high|medium|low|info
KRYXAI_MAX_ALERT_RETRIES=3
KRYXAI_ALERT_TIMEOUT_S=5

KRYXAI_TELEGRAM_BOT_TOKEN=...  KRYXAI_TELEGRAM_CHAT_ID=...
KRYXAI_SMTP_HOST=...           KRYXAI_SMTP_USER=...  KRYXAI_SMTP_PASSWORD=...
KRYXAI_ALERT_EMAIL_TO=...
KRYXAI_NTFY_TOPIC=...
KRYXAI_WEBHOOK_URL=...
```

`/health` and `kryxai capabilities` report which channels are live. Three
guarantees, each tested:

- **Alerting can never fail a scan.** A scan is evidence; losing it because a
  webhook timed out would be the wrong trade.
- **A failed delivery is recorded, not swallowed.** The outcome lands in
  `report.alerts`, and the dashboard's Notification panel renders it directly
  below the finding strips, so a scan whose notification failed says so rather
  than implying a page went out that never did. That panel makes the failure
  state the loud one, and states a 2xx as a hand-off rather than a read
  receipt. Delivery status is deliberately kept off the evidence chain, because
  it varies run to run for identical evidence.
- **No credential is ever logged or echoed.** Delivery records carry the channel
  and a redacted target; secrets are stripped from exception text, since a
  urllib error echoes the URL that failed and a Telegram URL carries the token.

Unconfigured channels are skipped, never fatal. Retries are bounded and
backoff is capped, so a dead channel costs seconds rather than minutes —
worst case `channels × (retries + 1) × KRYXAI_ALERT_TIMEOUT_S` added to a scan.

## Evidence chain

Every scan appends a proof-of-work block to a local SQLite ledger, and signed
reports are written as JSON, English HTML, Hindi HTML and PDF.

- Chain id `KryxAIV1`, report AAD `b"kryxai-report-v1"`.
- Difficulty is stored **per block** and verified against the stored value, so
  weakening the default cannot silently rewrite history.
- A local block is tamper-evident but **not externally attested**, so it is
  labelled `pending`. It is never labelled `anchored`.
- Optional external anchoring (Hyperledger Fabric + IPFS) lives in
  `deploy/nbf-fabric`. Set `KRYXAI_BLOCKCHAIN_EXTERNAL_ANCHOR=true` and
  `KRYXAI_BLOCKCHAIN_ANCHOR_REQUIRED=true` to make anchoring mandatory; in that
  posture a report that cannot be anchored is rejected with 503 and no report
  file is written.

## Bilingual output

JSON and HTML reports are fully bilingual (English / Devanagari). The PDF is
English-only unless a Devanagari-capable font is configured, because a default
Windows install ships none and a PDF cannot render Devanagari without one:

```bash
KRYXAI_DEVANAGARI_FONT_PATH=/path/to/NotoSansDevanagari-Regular.ttf
```

When no font is available the PDF states that Hindi text was omitted rather
than emitting blank glyphs.

## The optional risk model

KryxAI scores every finding with a validated rule engine. That path is the
default and needs no model file.

A 46-feature ONNX model is also supported. When one is present the report
records **both** scores alongside the fused total:

| Field | Meaning |
|---|---|
| `risk.rule_score` | The rule engine's score alone. Always present. |
| `risk.model_score` | The model's score, or `null` if no model is loaded. |
| `risk.total` | The fusion. Identical to `rule_score` when rules-only. |
| `report.model.used` | `false` whenever no model file is configured. |
| `report.model.sessions_scored` | Sessions the model scored, of `sessions_total`. |

So a disagreement between the two is visible rather than resolved silently.

The model scores **one row per session**, built from that session's most serious
finding by the same `fusion.session_feature_row()` that builds its training set.
Every finding in a session carries its session's score. A clean session is
therefore still model-scored even though it produces no findings — which matters,
because those clean sessions are the only examples teaching the model what
"acceptable" looks like. Session-level means in the report use the same unit, so
`sessions_scored < sessions_total` is a real signal rather than an artefact of
counting findings.

```bash
KRYXAI_ONNX_MODEL_PATH=            # force the rules-only path
KRYXAI_ONNX_MODEL_PATH=/path/m.onnx  # use a specific model
```

A model is auto-discovered at `kryxai/scoring/risk_model.onnx`, and is only
accepted if it declares **both** the feature schema version and the exact ordered
feature names matching this build. Either one missing is a refusal, not a
warning: the version is a manual bump that can be forgotten, whereas the names
fail loudly the moment a feature is renamed, reordered or dropped. A model
trained against a different vector is refused, not applied.

**The model is optional because it does not outperform the rules.** It is
trained entirely on synthetic captures and reaches parity with the rule engine
on held-out data. Parity is a statement about that corpus: the training labels
are the same weakness categories the rules detect, so the rules are already
close to a perfect classifier on this data. There is no claim that a learned
model is better here, and no validation against real mail traffic exists.

To retrain, or to see why, see [`training/README.md`](training/README.md) and
open `training/kryxai_train.ipynb` in Colab.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -q      # 338 tests
cd frontend && npm run build && npx oxlint
cd deploy/nbf-fabric/go && go vet ./...
python training/run_notebook_locally.py   # executes the training notebook's cells
```

`tests/test_frontend_contract.py` parses the TypeScript interfaces in
`frontend/src/lib/api.ts` and asserts the API responses match them, so a
renamed field fails the Python suite rather than silently rendering blank in the
browser. In a source checkout those tests are required, not skipped, so the
guard cannot quietly disappear in CI.

`training/run_notebook_locally.py` runs the training notebook's code cells
against this checkout, replacing the clone and `pip install` steps. Run it after
touching `features_for`, the model loader or the notebook: it is what catches a
training/serving skew before it ships.

## Layout

```
kryxai/
  pcap/        capture decoding, TCP reassembly, STARTTLS, TLS, X.509, corpus
  policy/      unified knowledge base, cipher policy, finding emission
  scoring/     risk scoring, posture, anomalies, optional ONNX fusion
  compliance/  DPDP / CERT-In mapping and statutory sources
  feeds/       offline IoC adapter with provenance
  alerts.py    opt-in outbound notification (Telegram, email, ntfy, webhook)
  reports/     signatures and JSON / HTML / PDF rendering
  store.py     SQLite evidence chain, proof of work, anchors
  engine.py    orchestration
  api.py       FastAPI surface
  cli.py       command line interface
deploy/nbf-fabric/   Fabric + IPFS external anchoring
frontend/            React dashboard
training/            synthetic corpus, Colab notebook, model installer
tests/               338 tests
```

## Licence

MIT.
