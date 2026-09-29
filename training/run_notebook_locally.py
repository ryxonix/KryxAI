"""Run training/kryxai_train.ipynb's code cells locally, in order.

The notebook is meant for Colab, where a `!pip install` line and a git clone do
the setup. Locally those two are replaced: the clone becomes a path to this
checkout and the install is assumed done. Everything else runs exactly as
written, because a notebook that has never been executed is a hypothesis.

    python training/run_notebook_locally.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

SKIP_MARKERS = ("git clone", "pip install")


def main() -> int:
    nb = json.loads((HERE / "kryxai_train.ipynb").read_text(encoding="utf-8"))
    ns: dict = {"__name__": "__main__"}

    # The clone cell would normally put the checkout on sys.path; do the same.
    sys.path.insert(0, str(REPO))

    executed = 0
    for number, cell in enumerate(nb["cells"]):
        if cell["cell_type"] != "code":
            continue
        source = cell["source"]
        if isinstance(source, list):
            source = "".join(source)

        # Cell 1 clones; cell 2 is a shell escape. Both are handled here instead.
        if any(marker in source for marker in SKIP_MARKERS):
            print(f"\n{'=' * 70}\n[cell {number}] SKIPPED (setup: clone/install)\n{'=' * 70}")
            continue

        # Cell 1 also sets HERE by cloning. Without the clone, point it at this
        # checkout, stand in for NOTEBOOK_TAG, and skip its SystemExit on the
        # empty REPO_URL.
        if "REPO_URL = \"\"" in source:
            print(f"\n{'=' * 70}\n[cell {number}] SKIPPED (clones the repo)\n{'=' * 70}")
            ns["HERE"] = REPO
            ns["NOTEBOOK_TAG"] = os.environ.get("NOTEBOOK_TAG", "local")
            continue

        print(f"\n{'=' * 70}\n[cell {number}]\n{'=' * 70}")
        try:
            exec(compile(source, f"<cell {number}>", "exec"), ns)
        except Exception:
            import traceback

            traceback.print_exc()
            print(f"\nFAILED in cell {number}")
            return 1
        executed += 1

    print(f"\n{'=' * 70}\nall {executed} code cells ran clean\n{'=' * 70}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
