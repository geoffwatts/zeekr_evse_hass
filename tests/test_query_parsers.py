"""Tests for the config-JSON, WiFi-status and network-status parsers.

Run with: python -m pytest tests/
"""

import importlib.util
import json
import sys
from pathlib import Path

_PROTOCOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "zeekr_charger"
    / "lib"
    / "protocol.py"
)
_spec = importlib.util.spec_from_file_location("zeekr_protocol_q", _PROTOCOL_PATH)
protocol = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = protocol
_spec.loader.exec_module(protocol)


def _json_response(obj, header=b"\xc0\x01"):
    return header + json.dumps(obj).encode()


def test_config_json_flattens_type_code_pairs_and_renames_c1():
    data = _json_response(
        {"rated_power": [3, 7400], "rate_charging_current": [3, 32], "model_number": [2, "Neo"], "plain": "x"}
    )
    assert protocol.parse_config_json(0xC1, data) == {
        "rated_power_w": 7400,
        "rated_charging_current_a": 32,
        "model_number": "Neo",
        "plain": "x",
    }


def test_config_json_other_opcodes_keep_names():
    data = _json_response({"rated_power": [3, 7400]})
    assert protocol.parse_config_json(0xC4, data) == {"rated_power": 7400}


def test_config_json_without_json_returns_raw_hex():
    assert protocol.parse_config_json(0xC1, b"\xc0\x01") == {"raw_hex": "c001"}


def test_config_json_truncated_json_returns_raw_hex():
    data = b'\xc0\x01{"a": [1,'
    assert protocol.parse_config_json(0xC1, data) == {"raw_hex": data.hex()}


def test_wifi_status_raedian_layout():
    # 02 'SSID' 0A 'password' 03 - format byte first, trailing control byte
    data = b"\x02MyNet\x0apassword\x03"
    r = protocol.parse_wifi_status(data)
    assert r["wifi_status"] == "Connected"
    assert r["wifi_status_code"] == 0
    assert r["wifi_response_type"] == "0x02"
    assert r["password"] == "password"


def test_wifi_status_zeekr_layout():
    data = b"\xc0\x02MyNet\npassword\x01"
    r = protocol.parse_wifi_status(data)
    assert r["wifi_status"] == "Connected"
    assert r["wifi_data_format"] == 2
    assert r["password"] == "password"
    # Characterisation of current behaviour: the body is taken from byte 1, so
    # the format byte is still part of the SSID text.
    assert r["ssid"] == "\x02MyNet"


def test_wifi_status_unknown_format():
    r = protocol.parse_wifi_status(b"\x11\x22abc")
    assert r["wifi_status"].startswith("Unknown data format: 0x22")
    assert r["wifi_status_code"] == 0x22
    assert r["ssid_or_value"] == "\x22abc"


def test_wifi_status_too_short_is_empty():
    assert protocol.parse_wifi_status(b"\x02") == {}


def test_network_status_full():
    data = (0x200).to_bytes(2, "little") + (1).to_bytes(2, "little") + (0x1006).to_bytes(4, "little")
    assert protocol.parse_network_status(data) == {
        "network_result": 0x200,
        "networking_mode": 1,
        "result_detail": 0x1006,
        "result_detail_desc": "Password Invalid, Startup Failed",
    }


def test_network_status_unknown_code_and_short_payloads():
    data = (0).to_bytes(2, "little") + (0).to_bytes(2, "little") + (0xBEEF).to_bytes(4, "little")
    assert protocol.parse_network_status(data)["result_detail_desc"] == "Unknown Error (0xBEEF)"
    assert protocol.parse_network_status(b"\x01\x00") == {"network_result": 1}
    assert protocol.parse_network_status(b"") == {}
