import sys
from pathlib import Path

# Ensure the plugin package directory is first in sys.path
PLUGIN_DIR = Path(__file__).resolve().parents[1]
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))
