"""
pytest configuration.

Tests target business logic (filtering, deduplication, security,
validation) and must touch neither the network nor Discord. Purely
network-facing modules are stubbed out when absent, so the CI can run
with a minimal install.
"""

import sys
import types
from pathlib import Path

# The package lives at the repo root, not in a src/ folder.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

for name in ("aiohttp", "feedparser"):
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = types.ModuleType(name)