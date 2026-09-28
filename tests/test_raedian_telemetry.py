"""Tests for parsing the 33-byte Raedian B5 telemetry heartbeat.

Payloads are real heartbeats captured from a Raedian Neo (single-phase
connection) while charging at ~14.4 A.

Run with: python -m pytest tests/
"""

import importlib.util
import sys
from pathlib import Path

import pytest

# Load protocol.py directly so the tests don't need Home Assistant installed
_PROTOCOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "zeekr_charger"
    / "lib"
    / "protocol.py"
)
_spec = importlib.util.spec_from_file_location("zeekr_protocol", _PROTOCOL_PATH)
protocol = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = protocol  # dataclasses look the module up here
_spec.loader.exec_module(protocol)

# (payload hex, energy kWh, voltage V, current A, runtime s)
CAPTURED = [
    ("0601552700005c0054560000a0050a00000000000a0000000000b9040000200121", 0.92, 221.00, 14.40, 1209),
    ("0601552700005d0040560000a0050a00000000000a0000000000ba040000200121", 0.93, 220.80, 14.40, 1210),
    ("0601552700005d0036560000a0050a00000000000a0000000000bb040000200121", 0.93, 220.70, 14.40, 1211),
    ("0601552700005e0036560000a1050a00000000000a0000000000ca040000200121", 0.94, 220.70, 14.41, 1226),
]


@pytest.mark.parametrize("payload_hex,energy,voltage,current,runtime", CAPTURED)
def test_raedian_telemetry_values(payload_hex, energy, voltage, current, runtime):
    telemetry = protocol.parse_b5_telemetry(bytes.fromhex(payload_hex))

    assert telemetry is not None
    assert telemetry.layout == "raedian33"
    assert telemetry.state == 0x06
    assert telemetry.port == 1
    assert telemetry.sequence_number == 10069
    assert telemetry.session_energy_kwh == pytest.approx(energy)
    assert telemetry.voltage_v == pytest.approx(voltage)
    assert telemetry.current_a == pytest.approx(current)
    assert telemetry.session_runtime_seconds == runtime
    assert telemetry.temperature_c == 33
    assert telemetry.phase_flags == 0


def test_raedian_long_capture_energy_matches_power():
    # First and last heartbeat of a 17-minute capture at a steady ~14.4 A
    first = protocol.parse_b5_telemetry(bytes.fromhex(CAPTURED[0][0]))
    last = protocol.parse_b5_telemetry(bytes.fromhex(
        "060155270000b7002c560000a3050a00000000000a0000000000b6080000200124"
    ))

    assert last.session_energy_kwh == pytest.approx(1.83)
    assert last.session_runtime_seconds == 2230
    assert last.temperature_c == 36

    # Energy counted by the charger vs. V x I over the elapsed runtime
    elapsed_h = (last.session_runtime_seconds - first.session_runtime_seconds) / 3600
    energy_from_power = last.phase_power_w[0] / 1000 * elapsed_h
    energy_counted = last.session_energy_kwh - first.session_energy_kwh
    assert energy_counted == pytest.approx(energy_from_power, abs=0.02)


def test_raedian_phase_values():
    # Last captured payload: 220.70 V x 14.41 A on L1, L2/L3 floating on a single-phase connection
    telemetry = protocol.parse_b5_telemetry(bytes.fromhex(CAPTURED[3][0]))

    assert telemetry.l2_voltage_centi_v == 10
    assert telemetry.l2_current_centi_a == 0
    assert telemetry.l3_voltage_centi_v == 10
    assert telemetry.l3_current_centi_a == 0

    assert telemetry.phase_voltage_v == pytest.approx((220.70, 0.10, 0.10))
    assert telemetry.phase_current_a == pytest.approx((14.41, 0.0, 0.0))

    power_l1, power_l2, power_l3 = telemetry.phase_power_w
    assert power_l1 == pytest.approx(220.70 * 14.41)
    assert power_l2 == 0
    assert power_l3 == 0


def test_raedian_three_phase_power():
    # Synthetic 3-phase payload using the inferred layout: 230 V / 16 A on every phase
    payload = bytearray.fromhex(CAPTURED[0][0])
    for base in (8, 14, 20):
        payload[base:base + 2] = (23000).to_bytes(2, "little")
        payload[base + 4:base + 6] = (1600).to_bytes(2, "little")
    telemetry = protocol.parse_b5_telemetry(bytes(payload))

    assert telemetry.phase_power_w == pytest.approx((3680.0, 3680.0, 3680.0))


def test_zeekr_layout_has_no_l2_l3_power():
    payload = bytes([0x06, 0x00]) + bytes(19)
    _, power_l2, power_l3 = protocol.parse_b5_telemetry(payload).phase_power_w

    assert power_l2 is None
    assert power_l3 is None


def test_raedian_heartbeat_state_is_charging():
    state = protocol.parse_heartbeat_state(bytes.fromhex(CAPTURED[0][0]))

    assert state.charging is True
    assert state.car_connected is True
    assert state.state == "charging"
    assert state.temperature_c == 33
    assert state.telemetry is not None


def test_zeekr_21_byte_layout_unchanged():
    # A 21-byte payload must still go through the original Zeekr parser
    payload = bytes([0x06, 0x00]) + bytes(19)
    telemetry = protocol.parse_b5_telemetry(payload)

    assert telemetry is not None
    assert telemetry.layout == "zeekr21"


def test_other_lengths_rejected():
    assert protocol.parse_b5_telemetry(bytes(20)) is None
    assert protocol._parse_b5_telemetry_raedian(bytes(32)) is None
