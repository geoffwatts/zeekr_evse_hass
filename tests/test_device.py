"""Tests for naming the device after the model the charger reports.

Home Assistant itself isn't needed: the few imports device.py uses are stubbed.
"""

import importlib.util
import sys
import types
from pathlib import Path

_COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "zeekr_charger"


def _load_device_module():
    for name in ("homeassistant", "homeassistant.core", "homeassistant.helpers"):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["homeassistant.core"].HomeAssistant = object
    device_registry = types.ModuleType("homeassistant.helpers.device_registry")
    device_registry.DeviceInfo = dict
    sys.modules["homeassistant.helpers.device_registry"] = device_registry
    sys.modules["homeassistant.helpers"].device_registry = device_registry

    package = types.ModuleType("zeekr_charger")
    package.__path__ = [str(_COMPONENT)]
    sys.modules["zeekr_charger"] = package
    for module_name in ("const", "device"):
        spec = importlib.util.spec_from_file_location(
            f"zeekr_charger.{module_name}", _COMPONENT / f"{module_name}.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return sys.modules["zeekr_charger.device"]


device = _load_device_module()

# Basic info (0xC1) as reported by a Raedian Neo
RAEDIAN_BASIC_INFO = {
    "model_number": "Neo",
    "charge_point_number": "EB1100RA",
    "hardware_version": "V1.3",
    "p_board_software_version": "V2.0.4",
    "charge_point_type": "Neo",
    "rated_power_w": 22000,
}


def test_raedian_neo_is_named_after_its_model():
    fields = device.device_fields("EB1100RA", RAEDIAN_BASIC_INFO)

    assert fields == {
        "manufacturer": "Raedian",
        "model": "Neo",
        "name": "Raedian Neo EB1100RA",
        "sw_version": "V2.0.4",
        "hw_version": "V1.3",
    }


def test_unknown_model_keeps_zeekr_as_manufacturer():
    fields = device.device_fields("ABC123", {"model_number": "Wallbox X"})

    assert fields["manufacturer"] == "Zeekr"
    assert fields["model"] == "Wallbox X"
    assert fields["name"] == "Zeekr Wallbox X ABC123"


def test_no_basic_info_falls_back_to_old_name():
    fields = device.device_fields("EB1100RA", {})

    assert fields == {
        "manufacturer": "Zeekr",
        "model": "Wallbox Charger",
        "name": "Zeekr Charger EB1100RA",
    }
