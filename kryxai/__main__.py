"""Allow ``python -m kryxai`` to run the CLI.

The package is normally invoked through the ``kryxai`` console script, but the
launcher scripts use ``python -m kryxai`` so that the interpreter inside the
virtualenv is used explicitly. Without this module that form fails with
"'kryxai' is a package and cannot be directly executed".
"""

from __future__ import annotations

from kryxai.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
