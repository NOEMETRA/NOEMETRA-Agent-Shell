import sys
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1]
VOICE_DIR = PLUGIN_DIR.parent / "voice-document-assistant"

for p in (PLUGIN_DIR, VOICE_DIR):
    if p.is_dir() and str(p) not in sys.path:
        sys.path.insert(0, str(p))
