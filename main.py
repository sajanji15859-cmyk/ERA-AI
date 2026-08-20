"""Deprecated entry point — kept as a facade for the ``era`` CLI.

Use ``era`` (or ``python -m era``) instead. The original version of this file
launched the REPL at module level, which started a blocking ``input()`` loop
even when ``main`` was merely imported. This facade is import-safe.

This module will be removed once the package layout has settled (Phase 1+).
"""

from __future__ import annotations

import warnings

warnings.warn(
    "Running ERA-AI via main.py is deprecated; use the `era` CLI or `python -m era`.",
    DeprecationWarning,
    stacklevel=2,
)

from era.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
