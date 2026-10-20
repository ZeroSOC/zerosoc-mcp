"""Every member's tests/ on the import path, for the fakes and fixtures its tests share.

A member is a directory under clients/ or servers/; nothing at the root names one, so a new client
needs no edit here.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for tests in sorted([*ROOT.glob("clients/*/tests"), *ROOT.glob("servers/*/tests")]):
    if str(tests) not in sys.path:
        sys.path.insert(0, str(tests))
