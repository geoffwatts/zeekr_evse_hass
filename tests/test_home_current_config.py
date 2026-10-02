"""Tests for parsing the 0xA9 installation-config response.

Run with: python -m pytest tests/
"""

import importlib.util
import sys
from pathlib import Path

_PROTOCOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "zeekr_charger"
    / "lib"
    / "protocol.py"
)
_spec = importlib.util.spec_from_file_location("zeekr_protocol_a9", _PROTOCOL_PATH)
protocol = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = protocol
_spec.loader.exec_module(protocol)

parse = protocol.parse_home_current_config


def test_c0_selector_form():
    cfg = parse(bytes([0xC0, 32]), bytes([16]))
    assert cfg.grid_capacity_a == 32
    assert cfg.max_current_capacity_a == 32
    assert cfg.present_current_limit_a == 16
    assert cfg.home_cfg_hex == "c020"
    assert cfg.grid_phase is None


def test_direct_form_has_all_fields():
    cfg = parse(bytes([40, 1, 2, 0, 1, 0]), bytes([20]))
    assert (cfg.grid_capacity_a, cfg.grid_phase, cfg.earthing_sys) == (40, 1, 2)
    assert (cfg.solar_pv, cfg.solar_phase) == (0, 1)
    assert cfg.present_current_limit_a == 20


def test_8e_form_skips_status_byte():
    # Regression: the 8E branch used to be shadowed by the generic >=6 branch,
    # which read the 0x8E status byte as a 142 A grid capacity.
    cfg = parse(bytes([0x8E, 32, 3, 1, 0, 0]), bytes([16]))
    assert cfg.grid_capacity_a == 32
    assert cfg.grid_phase == 3
    assert cfg.earthing_sys == 1
    assert cfg.present_current_limit_a == 16


def test_8e_short_form_only_grid_capacity():
    cfg = parse(bytes([0x8E, 25]))
    assert cfg.grid_capacity_a == 25
    assert cfg.present_current_limit_a is None
    assert cfg.grid_phase is None


def test_too_short_or_unrecognised_is_empty():
    for payload in (b"", b"\x20", bytes([1, 2, 3, 4, 5])):
        cfg = parse(payload, b"\x10")
        assert cfg == protocol.CurrentConfig()
