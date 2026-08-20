"""Allow ``python -m era`` as an alternative to the ``era`` console script."""

from __future__ import annotations

import sys

from era.cli import main

if __name__ == "__main__":
    sys.exit(main())
