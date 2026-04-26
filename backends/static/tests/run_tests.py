#!/usr/bin/env python3
"""Lance les tests unitaires de la partie static (backends.static et tools.static)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main():
    suite = unittest.TestLoader().discover(
        str(Path(__file__).parent),
        pattern="test_*.py",
        top_level_dir=str(ROOT),
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
