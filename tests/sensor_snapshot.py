"""Snapshot every sensor entity's static attrs + values using stubbed HA modules.
usage: snapshot.py <repo_root> > out.json
"""
import importlib, json, sys, types, enum, datetime
from unittest.mock import MagicMock

root = sys.argv[1]

def mod(name, **attrs):
    m = types.ModuleType(name); m.__dict__.update(attrs); sys.modules[name] = m; return m

class _E(enum.Enum): pass
def strenum(name, names):
    return enum.Enum(name, {n: n for n in names})

class CoordinatorEntity:
    def __init__(self, coordinator): self.coordinator = coordinator
    def __class_getitem__(cls, i): return cls
class SensorEntity: pass
import dataclasses
@dataclasses.dataclass(frozen=True, kw_only=True)
class SensorEntityDescription:
    key: str
    name: object = None
    icon: object = None
    device_class: object = None
    native_unit_of_measurement: object = None
    state_class: object = None
    entity_category: object = None
SDC = strenum("SDC", ["CURRENT","VOLTAGE","POWER","ENERGY","DATE","DURATION","TEMPERATURE"])
SSC = strenum("SSC", ["MEASUREMENT","TOTAL_INCREASING"])
class Units:
    def __getattr__(self, n): return n
def units(name, **kw): return type(name, (), kw)
mod("homeassistant"); mod("homeassistant.components")
mod("homeassistant.components.sensor", SensorDeviceClass=SDC, SensorEntity=SensorEntity,
    SensorStateClass=SSC, SensorEntityDescription=SensorEntityDescription)
mod("homeassistant.config_entries", ConfigEntry=object)
mod("homeassistant.const",
    UnitOfElectricCurrent=units("A", AMPERE="A"), UnitOfElectricPotential=units("V", VOLT="V"),
    UnitOfEnergy=units("E", KILO_WATT_HOUR="kWh"), UnitOfPower=units("P", WATT="W", KILO_WATT="kW"),
    Platform=strenum("Platform",["SENSOR","BINARY_SENSOR","SWITCH","NUMBER","BUTTON"]), UnitOfTemperature=units("T", CELSIUS="C"), UnitOfTime=units("Ti", SECONDS="s"))
mod("homeassistant.core", HomeAssistant=object, callback=lambda f: f)
mod("homeassistant.helpers"); mod("homeassistant.helpers.entity_platform", AddEntitiesCallback=object)
mod("homeassistant.helpers.update_coordinator", CoordinatorEntity=CoordinatorEntity)
mod("homeassistant.helpers.entity", EntityCategory=strenum("EC", ["DIAGNOSTIC","CONFIG"]))
mod("homeassistant.helpers.device_registry", DeviceInfo=dict)
mod("homeassistant.helpers.typing", ConfigType=dict)
mod("homeassistant.exceptions", ConfigEntryNotReady=Exception)

sys.path.insert(0, root)
sensor = importlib.import_module("custom_components.zeekr_charger.sensor")

DATA = {
  "basic_info": {"charge_point_number": "SN123", "c_board_software_version": "1.2.3", "p_board_software_version": "9",
                 "production_date": "2024/8/14", "rated_power_w": 7400, "model_number": "Neo", "hardware_version": "hw1",
                 "manufacturer": "Zeekr", "firmware_version": "f1"},
  "protection_info": {"grounding_detection": 1, "relay_adhesion_detection": 0, "detection_of_improper_gun_line": 1, "rcd_detection": 0},
  "wifi_status": {"ssid": "Net", "result_detail": 0x1006, "wifi_status": "Connected"},
  "wifi_config": {"wifi_function_enable": 1},
  "power_status": {"configured_limit_amps": 16, "limit_amps": 32, "max_current_capacity": 32},
  "current_config": {"grid_capacity_a": 40, "max_current_capacity_a": 40},
  "heartbeat_state": {"state": "charging", "temperature_c": 31},
  "telemetry": {"session_energy_kwh": 1.5, "voltage_v": 230.1, "current_a": 14.4, "power_w": 3300, "temperature_c": 33,
                "session_runtime_seconds": 120, "phase_flags": 0x07,
                "voltage_l1_v": 230.0, "voltage_l2_v": 231.0, "voltage_l3_v": 232.0,
                "current_l1_a": 1.0, "current_l2_a": 2.0, "current_l3_a": 3.0,
                "power_l1_w": 100.0, "power_l2_w": 200.0, "power_l3_w": 300.0},
  "charge_mode": 5,
}
class FakeClient: serial = "SN123"
class FakeCoord:
    client = FakeClient()
    def __init__(self, data): self.data = data
    def get_connection_status(self):
        return {"connected": True, "should_reconnect": True, "reconnect_attempts": 2, "max_reconnect_attempts": 10,
                "discovered_address": "AA", "has_token": True, "last_heartbeat_time": 5, "heartbeat_count": 7}

def val(x):
    return x.isoformat() if isinstance(x, datetime.date) else (x.name if isinstance(x, enum.Enum) else x)

def snap(data):
    added = []
    class Hass: pass
    h = Hass(); h.data = {"zeekr_charger": {"e": types.SimpleNamespace(coordinator=FakeCoord(data))}}
    import asyncio
    asyncio.run(sensor.async_setup_entry(h, types.SimpleNamespace(entry_id="e"), added.extend))
    out = {}
    for e in added:
        desc = getattr(e, "entity_description", None)
        def g(n):
            v = getattr(e, n, None)
            if v is None and desc is not None:
                v = getattr(desc, n.replace("_attr_", "").replace("native_unit_of_measurement", "native_unit_of_measurement"), None)
            return val(v)
        out[g("_attr_unique_id")] = {k: g(k) for k in (
            "_attr_name","_attr_native_unit_of_measurement","_attr_device_class","_attr_state_class",
            "_attr_icon","_attr_entity_category")}
        out[g("_attr_unique_id")]["value"] = val(e.native_value)
        out[g("_attr_unique_id")]["attrs"] = getattr(e, "extra_state_attributes", None)
    return out

import copy
empty = {k: ({} if isinstance(v, dict) else None) for k, v in DATA.items()}
print(json.dumps({"full": snap(DATA), "empty": snap(empty)}, indent=1, sort_keys=True, default=str))
