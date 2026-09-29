"""Validate a trained ONNX model and install it into the package.

Run this after the Colab notebook produces `risk_model.onnx`. It refuses to
install anything that does not satisfy the runtime contract, because a model
that is silently misapplied is worse than no model at all.

    python training/export/install_model.py path/to/risk_model.onnx

Checks performed before anything is copied:

1. onnxruntime can open the file and run inference.
2. The input shape matches this build's feature count.
3. `kryxai_feature_schema_version` matches `fusion.FEATURE_SCHEMA_VERSION`.
4. `kryxai_feature_names` matches `fusion.FEATURE_NAMES` exactly, in order.
5. The model card is present and consistent with the artefact.
6. The model's output is finite and inside the expected 0-1 range on a real
   feature vector drawn from the synthetic corpus.

Only then is the file copied to `kryxai/scoring/risk_model.onnx` and the
package-data entry is already in place to ship it.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

TARGET = REPO / "kryxai" / "scoring" / "risk_model.onnx"
CARD = REPO / "kryxai" / "scoring" / "model_card.json"


class CheckFailed(Exception):
    pass


def check(cond: bool, message: str) -> None:
    if not cond:
        raise CheckFailed(message)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    src = Path(argv[1]).resolve()
    if not src.is_file():
        print(f"FAIL  model file not found: {src}")
        return 1

    import onnxruntime as ort  # noqa: PLC0415

    from kryxai.scoring import fusion

    print(f"model  {src}")
    print(f"schema v{fusion.FEATURE_SCHEMA_VERSION}, {len(fusion.FEATURE_NAMES)} features\n")

    try:
        check(
            src.stat().st_size > 0,
            "model file is empty",
        )

        session = ort.InferenceSession(str(src), providers=["CPUExecutionProvider"])
        print("ok    onnxruntime opened the model")

        meta = session.get_modelmeta().custom_metadata_map or {}

        declared = meta.get("kryxai_feature_schema_version")
        check(
            declared is not None,
            "model does not declare kryxai_feature_schema_version. The notebook "
            "must embed the schema version in the ONNX metadata.",
        )
        check(
            int(declared) == fusion.FEATURE_SCHEMA_VERSION,
            f"schema mismatch: model v{declared}, this build v"
            f"{fusion.FEATURE_SCHEMA_VERSION}. Retrain the model.",
        )
        print(f"ok    schema v{declared} matches this build")

        names = meta.get("kryxai_feature_names")
        check(
            names is not None,
            "model does not declare kryxai_feature_names",
        )
        got = names.split(",")
        check(
            got == fusion.FEATURE_NAMES,
            "feature names differ from this build:\n"
            f"  only in model: {[n for n in got if n not in fusion.FEATURE_NAMES]}\n"
            f"  only in build: {[n for n in fusion.FEATURE_NAMES if n not in got]}",
        )
        print(f"ok    all {len(got)} feature names match, in order")

        inp = session.get_inputs()[0]
        shape = inp.shape
        check(
            len(shape) in (1, 2) and (shape[-1] in (None, len(fusion.FEATURE_NAMES))),
            f"model input shape {shape} does not accept a "
            f"{len(fusion.FEATURE_NAMES)}-feature vector",
        )
        print(f"ok    input accepts {len(fusion.FEATURE_NAMES)} features (shape {shape})")

        # Run it on a genuine feature vector, not a zero vector: a zero vector can
        # satisfy shapes while a real one exposes NaN handling problems.
        from kryxai.config import Settings
        from kryxai.engine import run_scan
        from kryxai.pcap import corpus
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            corpus.generate(Path(tmp))
            cap = next(Path(tmp).glob("*.pcap"))
            report = run_scan(cap, Settings(blockchain_difficulty=1), persist=False).report
            check(bool(report["sessions"]), f"corpus scan of {cap.name} produced no sessions")
            row = fusion.session_feature_row(report["sessions"][0], [], {})
            value = fusion.LearnedRiskModel(str(src)).score(row)

        check(value is not None, "model ran but returned no score")
        check(
            value == value and value not in (float("inf"), float("-inf")),
            f"model returned a non-finite score: {value}",
        )
        check(0.0 <= value <= 1.0, f"model returned {value}, outside the expected 0-1 range")
        print(f"ok    real capture scored {value:.4f}, finite and in range")

        check(CARD.is_file(), f"model card missing at {CARD}. The notebook writes it.")
        card = json.loads(CARD.read_text(encoding="utf-8"))
        for key in ("feature_schema_version", "feature_names", "metrics", "trained_on", "limitations"):
            check(key in card, f"model card is missing '{key}'")
        check(
            card["feature_schema_version"] == fusion.FEATURE_SCHEMA_VERSION,
            "model card schema version does not match this build",
        )
        check(
            card["feature_names"] == fusion.FEATURE_NAMES,
            "model card feature names do not match this build",
        )
        check(bool(card.get("limitations")), "model card states no limitations")
        print("ok    model card present and consistent")

    except CheckFailed as exc:
        print(f"\nFAIL  {exc}")
        print("\nThe model was NOT installed. KryxAI continues to use the rules alone.")
        return 1

    shutil.copy2(src, TARGET)
    print(f"\ninstalled {TARGET}")
    print(
        "KryxAI will now load it automatically. Set KRYXAI_ONNX_MODEL_PATH= to an "
        "empty value to fall back to the rules alone."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
