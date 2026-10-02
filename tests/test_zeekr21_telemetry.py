"""Tests for the 21-byte B5 telemetry, from a real capture.

Frames were captured through an ESPHome Bluetooth proxy from a single-phase 7 kW
Neo during a 281 s charge at ~14.5 A / 234 V. The vendor app showed 14.5 A,
233.6 V, and 0.261 kWh when charging stopped.

Run with: python -m pytest tests/
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_PROTOCOL_PATH = (
    Path(__file__).resolve().parents[1] / "custom_components" / "zeekr_charger" / "lib" / "protocol.py"
)
_spec = importlib.util.spec_from_file_location("zeekr_protocol_21", _PROTOCOL_PATH)
protocol = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = protocol
_spec.loader.exec_module(protocol)

# (payload hex, energy kWh, voltage V, current A, runtime s)
CAPTURED = [
    ("06002b9abf6a0000fc5d00002b00010000000f011e", 0.00, 240.60, 0.43, 1),     # session start
    ("06009d0ca7590d007c5b0000ad058e0000000f011e", 0.13, 234.20, 14.53, 142),  # mid session
    ("06009d0ca7591a007c5b0000ab05190100000f011e", 0.26, 234.20, 14.51, 281),  # last frame
]
END_OF_SESSION_SUMMARY = "08011a001b010000"  # state 08, 0.26 kWh, 283 s


@pytest.mark.parametrize("payload_hex,energy,voltage,current,runtime", CAPTURED)
def test_zeekr21_values(payload_hex, energy, voltage, current, runtime):
    t = protocol.parse_b5_telemetry(bytes.fromhex(payload_hex))

    assert t is not None
    assert t.layout == "zeekr21"
    assert t.state == 0x06
    assert t.session_energy_kwh == pytest.approx(energy)
    assert t.voltage_v == pytest.approx(voltage)
    assert t.current_a == pytest.approx(current)
    assert t.session_runtime_seconds == runtime
    assert t.phase_flags == 0  # bytes 6-7 are energy, not phase flags
    assert t.temperature_c == 30


def test_energy_is_not_read_from_the_runtime_bytes():
    # Regression: runtime (bytes 14-15) was once read as energy in 0.01 kWh,
    # which showed 2.81 kWh for a 0.26 kWh session.
    t = protocol.parse_b5_telemetry(bytes.fromhex(CAPTURED[2][0]))
    assert t.session_energy_kwh < 1


def test_end_of_session_summary_is_a_state_not_a_limit_snapshot():
    state = protocol.parse_heartbeat_state(bytes.fromhex(END_OF_SESSION_SUMMARY))
    assert state.state == "finishing"
    assert state.car_connected and not state.charging
    assert state.port == 1


def test_telemetry_frame_sets_charging_heartbeat_state():
    state = protocol.parse_heartbeat_state(bytes.fromhex(CAPTURED[1][0]))
    assert state.state == "charging" and state.charging
    assert state.temperature_c == 30
