# Deliverables matrix

Every finding KryxAI emits, mapped to the requirement it satisfies. Codes are
the `code` field in a report; the deliverable tag is what the finding carries
into the report's `deliverable` field and `counts.by_deliverable`.

Codes marked **not emitted** are implemented and reachable but did not appear in
the 17-case synthetic corpus, so they are covered by unit tests rather than by
an end-to-end capture. That distinction matters: it is a statement about the
test corpus, not about the detector.

## Status at a glance

Requirement-by-requirement status against the brief. **Partial** means the
capability exists and is usable but falls short of what was asked, and the
shortfall is stated rather than glossed.

| # | Requirement | Status | Evidence |
|---|---|---|---|
| D1 | Passive PCAP/PCAPNG ingestion, multi-file, no live probing | **met** | `kryxai/pcap/`; 17-capture corpus; `tests/test_corpus.py` |
| D2 | STARTTLS suppression detection (India focus) | **met** | `kryxai/pcap/starttls.py`; K1–K4; cases 02, 09, 10 |
| D3 | SMTP / IMAP / POP3 identification | **met** | `kryxai/pcap/protocol_id.py`; `tests/test_protocol.py` |
| D4 | TLS version assessment | **met** | `policy/kb.py` TLS_VERSION; `not_assessed` when unreadable |
| D5 | Cipher suite assessment | **met** | `policy/ciphers.py`; case 04 |
| D6 | Key-exchange group assessment | **met** | `policy/ciphers.py`; `tests/test_policy.py` |
| D7 | Certificate extraction and chain parsing | **met** | `policy/x509.py`; TLS 1.3 limits stated, never reported as a pass |
| D8 | Certificate validity: dates, SAN/CN, chain depth, CA/self-signed | **met** | cases 06, 07; capture-time evaluation, not wall-clock |
| D9 | Public key algorithm and size analysis | **met** | case 05; 1024-bit RSA flagged |
| D10 | Forward secrecy | **met** | case 04; RSA key exchange → `no_forward_secrecy` |
| D11 | Anomaly detection | **partial** | `scoring/anomaly.py` is capture-local median/MAD statistics, **not ML**. Baseline thresholds are fixed constants, so it detects divergence within one capture, not a learned population. `kryxai_train.ipynb` does not train it. |
| D12 | Risk scoring | **partial** | Two paths, both present. Rules: `scoring/fusion.py`, validated. Model: 46-feature ONNX in `training/`, reaches **parity** with the rules on held-out synthetic data and does not beat them. Served at session granularity via `session_feature_row()`, the same function that builds the training set, with `test_run_scan_scores_the_same_vector_training_saw` asserting agreement to 1e-6 through the real `run_scan` path. Ordering across the shipped corpus is audited by test (clean ≤0.01, weak 0.01–0.71, exposure 0.76–1.00); features outside the training range are clamped and the clamp is reported, not silently applied. See D12 and `training/README.md`. |
| D13 | Posture score | **met** | `fusion.posture()`; letter grade with `not_assessed` dimension counting; each dimension carries a per-dimension rationale and points contribution |
| D14 | DPDP Act 2023 / CERT-In mapping | **met, with caveat** | `compliance/dpdp.py`; statutory text is `UNVERIFIED_IN_THIS_BUILD` and needs legal sign-off, and that status travels with the mapping into the signed report and the dashboard. Section 8 is not claimed to be in the Second Schedule; the ₹250 crore figure is qualified as applying on conviction. |
| D15 | Threat intelligence feed support | **met** | Offline, attributable, provenance-tracked. No verified official machine-readable CERT-In API exists. |
| D16 | Bilingual reporting (English + Hindi) | **met** | JSON, HTML, PDF; 1221 Devanagari code points checked for replacement chars |
| D17 | Report formats | **met** | JSON, HTML, PDF. PDF is an optional extra and is skipped with an explicit hint when absent. |
| D18 | Report signing | **met** | RSA-3072 (PKCS#1 v1.5 / SHA-256) over the report, keyed to the chain |
| D19 | Evidence chain | **met** | PoW chain, `CHAIN_ID = "KryxAIV1"`, AAD `kryxai-report-v1` |
| D20 | External anchoring (Fabric / IPFS) | **met, unexercised** | Chaincode and gateway present and building; **no real network round trip**. Local blocks stay `pending`, never `anchored`. |
| D21 | API and dashboard | **partial** | API: `kryxai/api.py`, contract-tested against the TypeScript types, including the rule/model score split and the report model block. Dashboard: custom SVG with filtering, but limited drill-down, timeline and cross-filtering compared with a charting dashboard. |

### Out of scope

| Item | Reason |
|---|---|
| Kannada UI | Dropped from the reference app rather than machine-translated |
| eBPF live capture | Not in the brief; PCAP file input is the specified path |
| Real-network model validation | No labelled real citizen mail traffic exists in this project |

## D1 — Passive capture ingestion

| Capability | Where | Status |
|---|---|---|
| PCAP and PCAPNG reading, Ethernet / VLAN / SLL / SLL2 / IPv4 / IPv6 / TCP | `kryxai/pcap/io.py` | done |
| TCP reassembly, retransmission and out-of-order handling, gap detection | `kryxai/pcap/tcp.py` | done |
| Sequential connections on one 4-tuple split by each new bare SYN | `kryxai/pcap/tcp.py` | done |
| Capture provenance: SHA-256, packet count, capture window, link type | `kryxai/engine.py::_capture_metadata` | done |
| eBPF capture (optional, not required for MVP) | — | not implemented; PCAP file is the primary path |

## D2 — STARTTLS suppression (the India focus)

| Code | Meaning | Severity |
|---|---|---|
| `starttls_capability_suppressed` | K1 — advertised, then removed or replaced with a placeholder token | critical |
| `cross_flow_inconsistency` | K2 — same peer advertises STARTTLS on some sessions, not others | high |
| `starttls_refused` | K3 — client asked, server refused | high |
| `cleartext_after_upgrade` | K4 — negotiated upgrade followed by cleartext | critical |
| `starttls_not_offered` | capability absent entirely | medium |
| `non_mail_cleartext` | cleartext that is not a mail protocol | info |

Implementation: `kryxai/pcap/starttls.py` (state machine),
`kryxai/policy/kb.py` (signature emission). Obfuscated tokens such as the
Vodafone-style `XXXXXXXA` are detected and surfaced per session.

A token is only reported as substituted on positive evidence: a
repeated-character run (the shape of a redaction) or a one-character difference
from the real token (the shape of a typo or a single-character swap). Matching
the upgrade token's **length** is deliberately not sufficient, because POP3's
upgrade token is the four-character `STLS` and `USER`, `UIDL` and `TOP` are
ordinary capabilities of the same length — treating length as evidence produced
a high-severity `A1_tamper_signature` on clean POP3 traffic. The residual limit
is stated rather than papered over: a middlebox that replaces `STARTTLS` with a
same-length, non-repeating, plausible-looking token is not detected by this rule,
and K2 cross-flow inconsistency is the remaining route to that case.

## D3 — SMTP / IMAP / POP3 identification

Protocol is determined from greeter and command evidence, with the port used
only as a weak prior that must agree — never as the sole signal. `protocol`,
`protocol_confidence` and `protocol_signals` are reported per session so the
reasoning is auditable.

## D4 — TLS version

Codes: `weak_tls_version`, `broken_tls_version`. TLS 1.0/1.1 are rated broken,
1.2 acceptable, 1.3 recommended. `kryxai/policy/ciphers.py`.

## D5 — Cipher suite

Code: `weak_cipher_suite`, `broken_cipher_suite`. `kryxai/policy/ciphers.py`.

## D6 — Key-exchange group

Code: `weak_key_exchange_group`. Static-RSA and small-group key exchanges are
flagged. `kryxai/policy/ciphers.py`.

## D7 — Certificate extraction

Chain extracted from the TLS handshake, DER persisted, one entry per session in
`report.sessions[].tls.certificates`. `kryxai/pcap/x509.py`.

**Limit:** under TLS 1.3 the certificate is inside an encrypted handshake
record, so `certificate_visible` is `false` and the finding
`passive_tls13_certificate_not_visible` is emitted. This is a visibility limit,
never a pass, and the report says so.

## D8 — Certificate validation

| Code | Check |
|---|---|
| `certificate_expired` | validity judged **at capture time**, not analysis time |
| `certificate_not_yet_valid` | as above |
| `certificate_expiring_soon` | as above |
| `hostname_mismatch` | SAN (all names) then CN |
| `incomplete_chain` | missing intermediate |
| `chain_signature_invalid` | verify each link's signature against its issuer |
| `self_signed_leaf` | leaf is its own issuer |
| `unknown_critical_extension` | unrecognised critical extension present |

## D9 — Public key analysis

Code: `weak_public_key` (RSA/DSA/ECDSA key size). `kryxai/pcap/x509.py`.

## D10 — Forward secrecy

Code: `no_forward_secrecy`. TLS 1.3 is always PFS. A dimension that could not be
measured is reported `not_assessed` rather than scored as a failure.

## D11 — Anomaly detection

Codes: `A1_tamper_signature`, `A2_partial_upgrade`,
`A3_plaintext_on_implicit_port`, `A4_certificate_inconsistency`,
`A5_evidence_gap`, `A6_session_size_outlier`. All are
**capture-local baselines**: a peer that is anomalous relative to its own other
sessions in the same capture. `kryxai/scoring/anomaly.py`.

`A3` uses the port as the stake (an implicit-TLS port whose session stayed
cleartext), `A4` requires a contradictory certificate chain across sessions,
`A5` is emitted only when the TCP reassembler lost packets (a real gap, not a
sequence-number jump), and `A6` combines a median/MAD z-score over per-peer
session sizes with a significance bound tied to the baseline count. Every one of
A3–A6 is demonstrated by a dedicated corpus capture
(`14_implicit_port_plaintext` … `17_session_size_outlier`), and
`test_every_anomaly_code_is_demonstrated_somewhere` fails if any code is never
reached end to end.

**This is the weakest part of the delivery against the brief, which asked for
ML-based anomaly detection. What it actually is:** a robust z-score over
per-peer session features, using a median and a median absolute deviation, with
the threshold as a fixed constant. The MAD makes it resistant to the outliers it
is looking for, which is the right choice for a small sample.

What that means in practice:

- It detects divergence **within one capture**, and cannot compare a peer against
  a population of peers seen previously, because nothing is persisted between
  scans.
- The threshold is hand-set, not learned. Changing it is a code change, and
  there is no measurement justifying the current value.
- It is not trained by `training/kryxai_train.ipynb`, which trains the risk
  model only.

The severity assigned to a detected anomaly is a hand-set constant, and is
reported as `weight` rather than `confidence` for exactly that reason: it is an
ordering heuristic, not a calibrated probability. An ML-based detector would need
a labelled population of captures, which this project does not have.

## D12 — Risk scoring

Every finding carries `risk.total`, `risk.priority` (P1–P4) and
`risk.contributions` — the itemised reason for the score. `kryxai/scoring/fusion.py`.

Two scoring paths, and the report keeps both visible so a reader never has to
take the fused number on trust:

| Field | Meaning |
|---|---|
| `risk.rule_score` | The rule engine's score alone. Always present. |
| `risk.model_score` | The ONNX model's score, or `null` when no model is configured. |
| `risk.total` | The fusion of the two. Equals `rule_score` when no model is loaded. |
| `report.model.used` | `false` whenever no model file is configured. |
| `report.model.feature_schema_version` | The vector this build produces, always recorded. |

**The rule engine is the validated path.** It is deterministic, covered by tests,
and needs no model file.

**The model is optional and does not outperform the rules.** A 46-feature ONNX
model is trained by `training/kryxai_train.ipynb` against synthetic captures and
reaches parity with the rules on held-out data. Parity is a statement about that
corpus, not evidence that a learned model is better: the training labels are the
same weakness categories the rules detect, so the rules are already close to a
perfect classifier on this data. `training/README.md` states this at length
rather than presenting parity as an improvement.

A model is auto-discovered at `kryxai/scoring/risk_model.onnx`. It is only
accepted if its declared `kryxai_feature_schema_version` and
`kryxai_feature_names` match this build exactly; otherwise it is refused rather
than applied to a vector it was not trained for. Set
`KRYXAI_ONNX_MODEL_PATH=` (empty) to force the rules-only path.

**Out-of-range serving is clamped, and the clamp is reported.** Every training
capture holds a single session, so 13 of the 46 features are constant in
training and the model learned nothing about them. Feeding a real capture — one
with several sessions to a peer, a dropped packet, or an eleven-session corpus
case — a value it had never seen drove the ReLU stack to a saturated score, and
a session with **no findings at all scored 1.0**. The model card now records the
min/max of every feature seen in training; at serving time values outside that
range are clamped to it, the clamped feature names are recorded in
`report.model.clamped_features`, and `constant_training_features` names what the
model cannot reason about. The card's limitations state this rather than
presenting the score as a generalisation.

Ordering across the shipped corpus is held by test: clean sessions 0.00–0.01,
weak-crypto sessions 0.01–0.71, and sessions whose mail was readable on the wire
0.76–1.00. The exposure band is judged by **traffic**, not by which detector
fired: a plaintext session on an implicit-TLS port is exposure whether or not a
suppression code was involved, which is what the model's own training labels say.

## D13 — Posture score

0–100 across five weighted dimensions, letter grade, with `not_assessed` kept
separate from a zero. Bounded to 0–100; priority bands are severity-led.
`kryxai/scoring/fusion.py`.

Each dimension is **explainable, not just a number**: `dimension_explanation`
carries, for every dimension, the inputs it was measured over, a plain-language
rationale for the value it got, the points it contributed to the total, and
whether it was `not_assessed` and why. The rationale is built in the same
function and from the same inputs as the score, so it cannot drift from the
number it explains; `test_posture_points_reconcile_with_the_overall_score`
asserts the per-dimension points sum to the reported score. A `not_assessed`
dimension explains the visibility limit (e.g. "TLS 1.3 encrypts the certificate")
rather than silently scoring 0. The dashboard renders the rationale under each
dimension bar.

## D14 — DPDP Act 2023 / CERT-In mapping

`kryxai/compliance/dpdp.py` and `compliance/sources.json`. Every mapping carries
`caveats` and `not_a_legal_opinion = True`.

The `compliance` block in the report is part of the signed JSON, so the
statutory-mapping caveat is covered by the same signature as the findings it
refers to. It now carries `verification_status` (`UNVERIFIED_IN_THIS_BUILD` in
this build), the source file's own `verification_note`, the
`authoritative_sources`, and the full `provisions` catalogue. The dashboard
renders this as a prominent banner and a per-provision expandable detail, with
the Second Schedule note shown alongside, so no reader can take a section 8
mapping for a quantified penalty.

Legal posture, stated plainly: observations map to **section 8(4)/(5) for
relevance, not exposure**. Section 8 is not in the Second Schedule and carries
no monetary penalty; the ₹250 crore maximum applies to sections 4, 6(2)–(6), 7
and 9(4)–(5) **on conviction**. The statutory text in `sources.json` is marked
`UNVERIFIED_IN_THIS_BUILD` and must be checked against the Gazette by a lawyer
before any filing.

## D15 — Threat intelligence

Offline IoC adapter (`kryxai/feeds/ioc.py`): IP, domain, SHA-256 and URL
indicators from operator-supplied JSON/CSV. Every feed records provenance and is
marked unverified unless the feed file says otherwise. **There is no verified
machine-readable CERT-In IoC API**; the bundled feed is an empty example.

## D16 — Bilingual reporting

JSON and HTML in English and Devanagari; every finding carries `title` and
`title_hi` plus `translation_complete`. PDF is English unless
`KRYXAI_DEVANAGARI_FONT_PATH` is set, in which case it says so rather than
emitting blank glyphs. `kryxai/reports/builder.py`, `kryxai/i18n.py`.

## D17 — Report formats

Signed JSON, English HTML, Hindi HTML, PDF (ReportLab). `kryxai/reports/builder.py`.

## D18 — Report signing

RSA-3072 (PKCS#1 v1.5, SHA-256) over canonical JSON with AAD
`b"kryxai-report-v1"`. Keys live in
`KRYXAI_REPORT_KEYS_DIR`. A tampered report is detected.

## D19 — Evidence chain

Proof-of-work ledger in SQLite, `CHAIN_ID = "KryxAIV1"`. Difficulty is stored
**per block** and verified against the stored value. Concurrent appends are
serialised. `kryxai/store.py`.

State vocabulary is deliberately narrow: a local block is `pending`. It is
tamper-evident, not externally attested, and is never labelled `anchored`.

## D20 — External anchoring

Hyperledger Fabric + IPFS via an NBF-Lite-compatible REST gateway.
`deploy/nbf-fabric/`. Off by default; when
`KRYXAI_BLOCKCHAIN_ANCHOR_REQUIRED=true` a report that cannot be anchored is
rejected with 503 **and no report file is written**.

Chaincode: `deploy/nbf-fabric/go/kryxai-posture.go` (`go vet` clean, builds).
Anchor records carry `scan_id`, `report_id`, `case_id`, `file_sha256`,
`merkle_root`, `block_hash`, `timestamp`, `ipfs_cid`, `enc_alg`, `key_fp` — only
hashes and a CID, never mail content.

## D21 — API and dashboard

FastAPI (`kryxai/api.py`) and a React dashboard (`frontend/`). The dashboard is
driven by `frontend/src/lib/api.ts`, and `tests/test_frontend_contract.py`
parses those TypeScript interfaces and asserts the live API responses match, so
a renamed field fails the Python suite instead of rendering blank in a browser.
The dashboard shows a risk gauge, a scoring-dimensions radar, per-dimension
posture rationale, a prioritized findings list, a STARTTLS/STLS
downgrade-and-interception evidence panel, a requirement-coverage panel
(derived from the scan's own evidence), a DPDP statutory-mapping panel (with its
unverified-text banner), and a model-scoring-clamp notice when the served model
clamped any input. All labels are bilingual (English/Hindi).

## Known gaps

| Item | Status |
|---|---|
| ML-based anomaly detection (D11) | **Not delivered.** Capture-local median/MAD statistics with a fixed threshold. See D11. |
| Learned risk model (D12) | **Delivered, reaches parity only.** Trained on synthetic data; does not beat the rules. See `training/README.md`. |
| Dashboard interactivity (D21) | **Partial.** Filtering works; drill-down, timeline and cross-filtering are limited. |
| External anchor round-trip | Implemented, not exercised end to end without a Fabric network. Blocks stay `pending`, never `anchored`. |
| `F:\NBF-Lite\NBF-LITE` | Never inspected; the integration target is assumed, not confirmed. |
| Statutory text | `UNVERIFIED_IN_THIS_BUILD`; needs legal sign-off. |
| Hindi PDF rendering | HTML and JSON verified; no Devanagari font on the build host, so the PDF was not visually confirmed. |
| Signed-envelope verification after reload | Not implemented; signature is verified in-process only. |
| Report retrieval after restart | API report bodies are process-local, bounded at 64. The chain is durable; report bodies are not. |
| `policies.json`, `KRYXAI_IOC_FEED_PATH` | Dead config entries: no such file ships and nothing reads them. |

## Browser acceptance

The dashboard was driven end to end in real Chrome over the DevTools Protocol
against the API on `127.0.0.1:8010` and the dashboard on `127.0.0.1:5180`,
scanning `12_mixed_mitigations.pcap` and then `17_session_size_outlier.pcap`
from the UI itself (server-side path field, not a direct API call).

| Check | Result |
|---|---|
| Console errors / warnings | none |
| Uncaught exceptions | none |
| Failed network requests | none |
| HTTP 4xx/5xx responses | none |
| Panels rendered with real content | all 7 (posture, dimensions, findings, limitations, interception, coverage, DPDP) |
| Posture rationale visible on the page | yes |
| DPDP `UNVERIFIED_IN_THIS_BUILD` banner visible | yes |
| DPDP row expands to quoted statutory text | yes |
| Model-clamp notice appears for case 17 and names `cross_session_peer_sessions` | yes |
| Hindi UI: posture + DPDP headings, clamp notice | yes |
| Empty sections, `undefined`/`NaN`/`[object Object]` text leaks, horizontal overflow, zero-width bars | none |

The last row matters more than it looks: a panel that renders nothing, a bar
driven to `NaN` width, or a missing field printing the literal string
`undefined` all produce a screenshot that a reviewer reads as working. Those
were asserted against the live DOM, not judged by eye.

Four assertions failed on the first run and all four were faults in the test
script rather than the product: `innerText` returns CSS-uppercased text (so
`"CHOOSE A CAPTURE"` did not match `"Choose a capture"`), the quoted statutory
text and the Hindi button labels had been guessed rather than read from the
source. Each was corrected against the real strings and re-run. The clamp
feature itself was confirmed working at the API level before the UI assertion
was trusted, so the fix was to the matcher rather than a relaxed assertion.

## Packaging and release verification

Checked by building the wheel and running the CLI and the whole test suite from
an isolated virtualenv, from a directory outside the source tree so the
installed package was genuinely exercised rather than shadowed by the checkout.

| Check | Result |
|---|---|
| `python -m build --wheel` | `kryxai-0.1.0-py3-none-any.whl`, no deprecation warnings |
| Wheel contents | `compliance/sources.json`, `data/feeds/*.json` packaged; `kryxai` console script registered. `scoring/*.onnx` and `scoring/model_card.json` are packaged **only** in an opt-in build, because the model is a generated, gitignored artefact — a clean checkout builds a rules-only wheel (39 entries, verified) and an opt-in build 41 |
| `kryxai --version` / `capabilities` | work from a clean install |
| `kryxai corpus` + `kryxai scan` | work on a **base** install with no extras |
| Reports on a base install | JSON + English/Hindi HTML written; PDF skipped with an explicit hint |
| Reports with `[reports]` installed | PDF written (2.8 KB) |
| Full suite, source checkout | 300 passed, 17 skipped |
| Full suite, installed wheel | 251 passed, 25 skipped (frontend sources and the `onnx` writer are not shipped) |
| `go vet ./...` | clean |
| `npm run build` | succeeds |
| `python training/run_notebook_locally.py` | all 10 code cells execute clean, end to end |

Four packaging defects were found by that process and fixed:

1. `kryxai scan` raised `ModuleNotFoundError` for `reportlab` on a base install,
   because PDF was treated as mandatory despite being an optional extra. The
   single most common command could not run. PDF is now skipped gracefully and
   the omission is stated to the user.
2. The database, reports and the **RSA-3072 report-signing key** defaulted to the
   package's parent directory, so an installed wheel wrote them into
   `site-packages` — possibly read-only, and private key material in a
   world-readable location. Writable state now resolves to a per-user data
   directory; read-only resources still resolve from the installed package.
3. `starlette.testclient` now requires `httpx2`, so a clean environment could not
   collect the API tests at all. `httpx2` is in the `dev` and `all` extras.
4. The pre-existing `test_upload_temp_file_is_cleaned_up` asserted by globbing
   `kryxai-*` in the system temp directory, so it failed on any unrelated
   user directory with a similar name. It now asserts on exactly what the endpoint
   created.

## Defects found by executing the training notebook

Recorded because they are the reason `training/run_notebook_locally.py` exists.
A notebook that has never been run is a hypothesis, and every one of these would
have shipped broken while looking correct on inspection.

| Defect | Consequence if shipped |
|---|---|
| `log1p` applied in the notebook but not in `features_for` | The model would be trained on one vector and served another. Every score wrong, nothing would catch it. |
| `StandardScaler` excluded from the exported graph | The runtime feeds raw features; every score would be wrong but plausible. |
| Final `Sigmoid` added, but `MLPRegressor.predict` is linear | Parity broke by ~0.5. Caught by the notebook's own parity assertion. |
| `output[0][0]` read as a scalar | Under numpy 2.x this raises, the bare `except` swallowed it, and the model silently reported "no score" while appearing to load fine. |
| `onnx.helper.make_string_string_entry` | Does not exist in onnx 1.22; the notebook would have failed at the last step, after training. |
| Grouped but not stratified split | The test set held the entire `ok` band; the model scored 0.5 accuracy. |
| `(mean @ W0) / sd` | Shape error: a `(hidden,)` vector divided by a `(features,)` one. |
| `onnx_model_path` default of `""` | Made the auto-discovery branch unreachable, so an installed model was silently never loaded. |

## Defects found by auditing the served model against real scans

Recorded because the training notebook is self-consistent by construction: it
trains and evaluates on data from its own generator, so it cannot notice a
mismatch between that data and what the product actually sees. These were found
by running `run_scan` over the shipped corpus and comparing.

| Defect | Consequence if shipped |
|---|---|
| `run_scan` scored each **finding**, but training used one row per **session** | The model was fed a distribution it never saw, and a clean session produced no findings so it was never scored at all — the only examples teaching the model what "acceptable" looks like. |
| The representative finding was chosen by `min()` on severity alone | `min` returns the *first* minimum, so two equally-severe findings were resolved by list order. The engine passes detector order and the report passes sorted order, so the same session was represented differently in training and serving: a 0.008 score difference on a real capture, passing every other assertion. |
| `mailflows.imap_healthy()` / `pop3_healthy()` stopped before the handshake | `11_imap_healthy` shipped named and documented as a clean IMAP-to-TLS 1.2 upgrade while containing no TLS at all: every TLS feature read as zero. `expect_clean` could not catch it, because a capture with no handshake also has no suppressed capability. The unit test masked it by appending `smtp_upgraded()` — SMTP plaintext in front of the TLS records. |
| POP3 capability vocabulary was absent from `_KNOWN_CAPABILITIES` | With length treated as evidence of substitution, POP3's own `USER` and `UIDL` (four characters, like `STLS`) were reported as tampered upgrade tokens, raising a high-severity `A1_tamper_signature` on clean POP3 traffic with empty evidence. |
| `sessions[].model_score` was emitted only when a model was configured | The same expression meant `undefined` on a rules-only install and a number on one with a model; a consumer could not tell a missing key from a deliberate null. |
| A loader check on feature names that was optional while the installer required them | A model could be accepted whose 46-long vector's meaning was never recorded. Both now require the exact ordered names. |
| `cross_session_peer_sessions` is constant (1.0) across all training captures | Serving an eleven-session capture fed the model a log-space value it had never seen; the ReLU stack saturated and a session **with no findings at all scored 1.0**, which also failed the corpus ordering test. Every feature now has a recorded training min/max in the model card; out-of-range values are clamped at scoring time and the clamped names are reported (`report.model.clamped_features`), so an unusual capture is scored conservatively and transparently rather than at an arbitrary saturation point. |
| The corpus ordering test bucketed the exposure band by suppression code alone | The model's own training labels put "no upgrade offered; mail in cleartext" in the exposure band, but the test filed such a session under weak-crypto purely because no middlebox suppression occurred — and the model then "failed" an ordering test that had mislabelled A3 plaintext-on-implicit-port. The band is now judged by the traffic (mail readable on the wire), matching the labels. |
| The coverage row for statutory mapping read `compliance["provisions"]` while the summary emits `items` | The DPDP coverage row could never report `demonstrated`, so a capture that mapped 2–4 findings to a provision still showed the requirement as unexercised. Corrected to read the mapped `items`. A guard test asserts a clean capture still reports `clean`, because `provisions` is a static catalogue and keying the row on it would claim demonstration on every capture. |
| Posture returned a bare number per dimension | The posture score was not explainable: a reader saw five percentages and a grade with no account of what drove them. Each dimension now carries the inputs it was measured over, a rationale, its point contribution, and a reason when it is `not_assessed`; the points are asserted to sum to the reported score. The HTML and PDF reports gained the rationale column and the DPDP verification banner — the JSON carried both, but the human-readable deliverable a reviewer actually reads did not. |

A consequence worth stating separately: with the bad fixture in place, a clean
IMAP session scored **0.2489** while a session with a weak cipher suite and no
forward secrecy scored **0.1632** — the model ranked a healthy capture above a
genuinely weak one, and the notebook's `held_out_accuracy = 1.0` said nothing
because its test set came from its own generator. With the fixture corrected and
the ordering made total, all three control captures score ≤ 0.01 and the ordering
is coherent (clean 0.00–0.01, weak-crypto 0.01–0.71, exposure 0.76–1.00),
enforced by `test_the_model_orders_the_shipped_corpus_coherently`.
