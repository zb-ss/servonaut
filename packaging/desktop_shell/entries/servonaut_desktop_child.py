"""Entry script for the Servonaut desktop private child executable."""

from __future__ import annotations

import sys

from servonaut.desktop.child import main

if __name__ == "__main__":
    sys.exit(main())
