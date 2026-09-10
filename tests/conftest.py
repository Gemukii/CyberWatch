"""
Configuration pytest.

Les tests portent sur la logique métier (filtrage, déduplication, sécurité,
validation) et ne doivent toucher ni le réseau ni Discord. Les modules
purement réseau sont donc remplacés par des stubs quand ils sont absents,
ce qui permet à la CI de tourner avec une installation minimale.
"""

import sys
import types
from pathlib import Path

# Le paquet est à la racine du dépôt, pas dans un dossier src/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

for name in ("aiohttp", "feedparser"):
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = types.ModuleType(name)
