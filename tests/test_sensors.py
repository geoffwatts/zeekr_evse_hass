"""Guards sensor entity ids/names/units/values against accidental change.

Unique ids matter: changing one orphans the user's existing entity. The golden
file was generated from the pre-refactor class-based sensors. Regenerate it with
``python tests/sensor_snapshot.py . > tests/sensor_snapshot.json`` only when an
entity change is intentional.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sensor_entities_match_golden_snapshot():
    out = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "sensor_snapshot.py"), str(ROOT)],
        capture_output=True, text=True, check=True,
    ).stdout
    assert json.loads(out) == json.loads((ROOT / "tests" / "sensor_snapshot.json").read_text())
