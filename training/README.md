# KryxAI model training

Everything needed to reproduce the optional ONNX risk model, and an honest
account of what it is worth.

## What is in here

| File | Purpose |
| --- | --- |
| `kryxai_train.ipynb` | The training run. Opens in Google Colab. |
| `dataset.py` | Generates the labelled synthetic corpus. |
| `build_notebook.py` | Regenerates the `.ipynb` from reviewed cell sources. |
| `run_notebook_locally.py` | Executes the notebook's cells locally, for verification. |
| `export/install_model.py` | Validates a trained model and installs it into the package. |
| `README.md` | This file. |

The model card is **generated**, not hand-written: the notebook writes
`kryxai/scoring/model_card.json` from the run that produced the model, and
`install_model.py` refuses a model whose card does not match the build. A prose
card maintained by hand is a card that quietly becomes false the next time
`FEATURE_NAMES` changes, so there is not one.

`kryxai_train.ipynb` is generated. Edit `build_notebook.py` and re-run it rather
than editing the notebook, so the cell sources stay reviewable as plain text and
the diff shows what actually changed.

## Running it

In Colab: open the notebook, set `REPO_URL` in the first code cell, run all
cells top to bottom.

Locally, to check the pipeline still works before pushing a notebook:

```
python training/run_notebook_locally.py
```

This runs the notebook's code cells with the clone and `pip install` steps
replaced by the local checkout. Every other cell runs exactly as written, which
is the point: a notebook that has never been executed is a hypothesis, not a
result. Doing this caught four defects that would otherwise have shipped.

Installing the result:

```
python training/export/install_model.py dist/risk_model.onnx
```

## What the model is

A 46-feature MLP that maps one mail session's observed cryptography to a risk
score in 0–1, where 0 is an acceptable configuration and 1 is mail exposed in
cleartext. It is loaded by `kryxai.scoring.fusion.LearnedRiskModel` and is
entirely optional: KryxAI runs and scores correctly with no model installed, and
the rule-based score stands alone in that case.

## What the model is not

**It is not trained on real traffic.** Every capture it learns from is
synthesised by `dataset.py` inside this repository. No real citizen mail is
involved and no network is contacted. Its scores say nothing about any real
deployment, and the model card says so in its `limitations` field.

**It does not beat the rules, and on this corpus it cannot.** This is the most
important thing to understand about the exercise. The labels are the weakness
profiles that were injected when each capture was generated, and KryxAI's rule
engine was written to detect exactly those weaknesses. The rule engine is
therefore already a near-perfect classifier on this data, and the measured
result is that the model reaches parity with it and no more.

Parity is a real result, but a narrow one. It shows the pipeline is
reproducible and the export is faithful. It does **not** show that a learned
model is better than the rules. Establishing that would need labelled real
captures, which this project does not have, and the honest position is to say so
rather than to present parity as an improvement.

**It does not replace the rules.** Where the model and the rules disagree, the
report records both `rule_score` and `model_score` alongside the fused `total`,
so the disagreement is visible rather than resolved silently in the model's
favour.

## How the labels avoid circularity

This is the single design decision that makes the numbers worth anything, so it
is worth stating plainly.

The tempting shortcut is to label each capture with whatever KryxAI's rule
engine concluded about it. That produces a dataset in which the target is a
function of the rules, so a model trained on it learns nothing but
`policy/kb.py`, scores near-perfectly, and that score is an artefact of the
label rather than evidence of anything.

Instead, each capture is generated around a **declared weakness profile** and
labelled with that profile. `ok` means a working modern handshake.
`weak_crypto` means a 1024-bit key, an expired certificate, or a handshake
without forward secrecy. `exposure` means the upgrade was suppressed or never
offered, so mail travelled in cleartext. The label is what a reviewer would say
on looking at the handshake, and it was fixed before the tool ever ran.

`dataset.py` records that profile explicitly, and the notebook asserts the bands
are separable from the feature vector before fitting anything.

## How the split avoids fooling itself

Two independent ways a split can flatter a model:

- **A certificate in both halves.** The model recognises the certificate rather
  than the property. Prevented by grouping on certificate identity, so an
  identity is entirely in one half.
- **An entire weakness category held out.** Grouping alone does not prevent
  this; with one group per profile, a held-out group can be a whole category, and
  the model is then asked to classify something it has never seen.

The split is therefore stratified *and* grouped, via `StratifiedGroupKFold`, and
the notebook asserts both properties rather than trusting them. An earlier draft
got this wrong: the test set held only the `ok` and one `weak_crypto` band, the
model never saw a healthy session, and it scored 0.5 accuracy. The assertion now
present would have caught that immediately.

## How training and serving are kept on the same vector

The unit is the **session**, not the finding, and that has to be true in both
places or the model is being fed something it never saw:

- Training builds one row per session with `fusion.session_feature_row()`.
- `run_scan()` scores each session with the *same function on the same inputs*
  and gives each finding in that session the session's score.

Two bugs this caught, both of which a naive "the notebook ran clean" check
misses:

1. **Serving was per-finding.** `run_scan()` originally scored each finding
   independently, so the model saw one row per complaint rather than one per
   session — and a clean session, which produces no findings, was never scored at
   all. The clean examples are the only ones teaching the model what
   "acceptable" looks like, so the product would have presented it with a
   distribution the training set did not contain. Now asserted by
   `test_run_scan_scores_the_same_vector_training_saw`, which recomputes the
   training-time row and requires the served score to match to 1e-6.
2. **The representative finding was chosen by list order.** A session is
   represented by its most serious finding, but `min()` on severity alone
   returns the *first* minimum, so two equally-severe findings were resolved
   arbitrarily. The engine passes detector order and the report passes sorted
   order, so the same session could be represented by different findings in
   training and serving — a 0.008 score difference on a real capture, enough to
   pass every assertion while being wrong. The ordering is now total: severity,
   then strongest detection weight, then code.

## How the export is kept honest

Three checks, all in the notebook, all fatal if they fail:

1. The ONNX file's declared `kryxai_feature_schema_version` and
   `kryxai_feature_names` match this build, in order.
2. The exported graph agrees with the fitted pipeline on held-out rows, to
   within 1e-4.
3. The file loads through `LearnedRiskModel` and scores a real
   `features_for()` vector from a real scan.

Two subtleties that were wrong in the first draft and are worth not getting
wrong again:

- **The `StandardScaler` is folded into the first layer**, so the graph consumes
  *raw* features. The runtime loader is handed a raw vector from
  `features_for` and has no scaler of its own. A graph expecting pre-scaled
  input would be fed wrong numbers on every call and would still return a
  plausible-looking score.
- **The log-compression of unbounded columns lives in `features_for`**, in the
  package, not in the notebook. If it lived here it would silently drift from
  the runtime, and every score would be wrong in a way nothing would catch.

`install_model.py` re-checks all of this independently before copying anything
into the package, and refuses to install a model that fails. It also scores a
real scan, so a model that loads but produces nonsense is caught.

## Limitations, collected

- Synthetic data only. No validation against real mail traffic.
- The label space is the injected categories, which is narrower than the space
  of real-world misconfiguration.
- TLS 1.3 encrypts the certificate, so those features are zero by construction
  and a TLS 1.3 session looks unassessed to the model.
- Key size is a proxy for key strength. A 2048-bit RSA key is scored as
  adequate, which is a policy statement, not a cryptographic measurement.
- 56 captures across 7 profiles is a small corpus. The numbers are stable but
  they are not evidence of generalisation.

## Current status

A model trained from this pipeline is installed at
`kryxai/scoring/risk_model.onnx` with its card at `kryxai/scoring/model_card.json`.
It reaches parity with the rules on held-out synthetic data.

Removing it returns KryxAI to the validated rules-only path, which is the
recommended default for any use where the model's provenance matters. It can
also be disabled without uninstalling, by setting
`KRYXAI_ONNX_MODEL_PATH=` (empty).
