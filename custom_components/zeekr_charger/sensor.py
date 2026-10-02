"""Sensor platform for Zeekr charger."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfPower,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .device import build_device_info

DIAGNOSTIC = EntityCategory.DIAGNOSTIC


# ---- value helpers -------------------------------------------------------

def _float(value: Any) -> float | None:
    return float(value) if value is not None else None


def _int(value: Any) -> int | None:
    return int(value) if value is not None else None


def _enabled(value: Any) -> str | None:
    """Protection flags are reported as 1 (on) / 0 (off)."""
    if value is None:
        return None
    return "Enabled" if value == 1 else "Disabled"


def _kilowatts(watts: Any) -> float | None:
    return float(watts) / 1000.0 if watts is not None else None


def _production_date(value: Any) -> date | None:
    """Production date is reported as e.g. "2024/8/14"."""
    if not value:
        return None
    try:
        year, month, day = (int(part) for part in str(value).split("/"))
        return date(year, month, day)
    except ValueError:
        return None


def _phase_status(phase_flags: Any) -> str | None:
    if phase_flags is None:
        return None
    # Lower bits are per-phase flags; chargers sometimes add higher-order
    # status bits, so only count the active phase bits.
    active_bits = phase_flags & 0x07
    if active_bits == 0 or (active_bits & (active_bits - 1) == 0):
        return "Single Phase"
    return f"Multi Phase (flags: 0x{phase_flags:02X})"


def _first_version_string(basic_info: dict[str, Any]) -> str | None:
    for key, value in basic_info.items():
        if any(term in key.lower() for term in ("version", "firmware", "ver")) and isinstance(value, str):
            return value
    return None


def _software_version(basic_info: dict[str, Any]) -> str | None:
    for field in ("c_board_software_version", "software_version", "firmware_version"):
        if field in basic_info:
            return basic_info[field]
    return None


def _rated_capacity(data: dict[str, Any]) -> float | None:
    """Prefer the 0xE0 power status; fall back to the 0xA9 installation config."""
    for section, key in (("power_status", "max_current_capacity"), ("current_config", "max_current_capacity_a")):
        value = data.get(section, {}).get(key)
        if value is not None and value > 0:
            return float(value)
    return None


def _charge_rate(data: dict[str, Any]) -> float | None:
    """The configured limit when set, otherwise the home limit."""
    power_status = data.get("power_status", {})
    configured = power_status.get("configured_limit_amps")
    if configured is not None and configured > 0:
        return float(configured)
    return _float(power_status.get("limit_amps"))


def _temperature(data: dict[str, Any]) -> float | None:
    temp = data.get("heartbeat_state", {}).get("temperature_c")
    if temp is None:
        temp = data.get("telemetry", {}).get("temperature_c")
    return _float(temp)


def _charger_state(coordinator, data: dict[str, Any]) -> str:
    # Only report a charger state while the BLE link is actually up
    if not coordinator.get_connection_status().get("connected"):
        return "disconnected"
    return data.get("heartbeat_state", {}).get("state", "unknown")


def _field(section: str, key: str, convert: Callable[[Any], Any] = lambda v: v) -> Callable[[dict], Any]:
    """Build a value_fn reading ``data[section][key]`` through ``convert``."""
    return lambda data: convert(data.get(section, {}).get(key))


# ---- description-driven sensors ------------------------------------------

@dataclass(frozen=True, kw_only=True)
class ZeekrSensorDescription(SensorEntityDescription):
    """Describes a sensor whose value is a pure function of coordinator data."""

    value_fn: Callable[[dict[str, Any]], Any]
    # unique_id suffix; kept identical to the pre-refactor class-name based ids
    # so existing entities are not orphaned
    legacy_id: str


def _desc(legacy_id: str, name: str, value_fn, **kw) -> ZeekrSensorDescription:
    return ZeekrSensorDescription(key=legacy_id, legacy_id=legacy_id, name=name, value_fn=value_fn, **kw)


_A = UnitOfElectricCurrent.AMPERE
_V = UnitOfElectricPotential.VOLT
_W = UnitOfPower.WATT
MEASUREMENT = SensorStateClass.MEASUREMENT

SENSORS: tuple[ZeekrSensorDescription, ...] = (
    _desc("zeekrchargercurrentlimitsensor", "Charge Rate", _charge_rate,
          native_unit_of_measurement=_A, device_class=SensorDeviceClass.CURRENT, icon="mdi:lightning-bolt"),
    _desc("zeekrchargermaxcurrentcapacitysensor", "Rated Current Capacity", _rated_capacity,
          native_unit_of_measurement=_A, device_class=SensorDeviceClass.CURRENT,
          icon="mdi:lightning-bolt-outline", entity_category=DIAGNOSTIC),
    _desc("zeekrchargerserialsensor", "Serial Number", _field("basic_info", "charge_point_number"),
          icon="mdi:identifier", entity_category=DIAGNOSTIC),
    _desc("zeekrchargerversionsensor", "Firmware Version", lambda d: _first_version_string(d.get("basic_info", {})),
          icon="mdi:chip", entity_category=DIAGNOSTIC),
    _desc("zeekrchargersoftwareversionsensor", "Software Version", lambda d: _software_version(d.get("basic_info", {})),
          icon="mdi:chip", entity_category=DIAGNOSTIC),
    _desc("zeekrchargerproductiondatesensor", "Production Date", _field("basic_info", "production_date", _production_date),
          device_class=SensorDeviceClass.DATE, icon="mdi:calendar", entity_category=DIAGNOSTIC),
    _desc("zeekrchargerratedpowersensor", "Rated Power", _field("basic_info", "rated_power_w", _kilowatts),
          native_unit_of_measurement=UnitOfPower.KILO_WATT, device_class=SensorDeviceClass.POWER,
          state_class=MEASUREMENT, icon="mdi:flash", entity_category=DIAGNOSTIC),
    _desc("zeekrchargermodelsensor", "Model", _field("basic_info", "model_number"),
          icon="mdi:ev-station", entity_category=DIAGNOSTIC),
    # Safety sensors
    _desc("zeekrchargergroundingdetectionsensor", "Grounding Detection",
          _field("protection_info", "grounding_detection", _enabled), icon="mdi:earth", entity_category=DIAGNOSTIC),
    _desc("zeekrchargerrelayadhesionsensor", "Relay Adhesion Detection",
          _field("protection_info", "relay_adhesion_detection", _enabled), icon="mdi:connection", entity_category=DIAGNOSTIC),
    _desc("zeekrchargerimpropergunlinesensor", "Improper Cable Detection",
          _field("protection_info", "detection_of_improper_gun_line", _enabled), icon="mdi:alert-circle",
          entity_category=DIAGNOSTIC),
    _desc("zeekrchargerrcddetectionsensor", "RCD Detection",
          _field("protection_info", "rcd_detection", _enabled), icon="mdi:shield-check", entity_category=DIAGNOSTIC),
    # Network
    _desc("zeekrchargerwifissidsensor", "WiFi SSID",
          _field("wifi_status", "ssid", lambda v: str(v) if v else None), icon="mdi:wifi", entity_category=DIAGNOSTIC),
    # Energy / telemetry
    _desc("zeekrchargersessionenergysensor", "Session Energy", _field("telemetry", "session_energy_kwh", _float),
          native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR, device_class=SensorDeviceClass.ENERGY,
          state_class=SensorStateClass.TOTAL_INCREASING, icon="mdi:lightning-bolt"),
    _desc("zeekrchargervoltagesensor", "Voltage", _field("telemetry", "voltage_v", _float),
          native_unit_of_measurement=_V, device_class=SensorDeviceClass.VOLTAGE, state_class=MEASUREMENT,
          icon="mdi:lightning-bolt", entity_category=DIAGNOSTIC),
    _desc("zeekrchargercurrentsensor", "In-use Current", _field("telemetry", "current_a", _float),
          native_unit_of_measurement=_A, device_class=SensorDeviceClass.CURRENT, state_class=MEASUREMENT,
          icon="mdi:current-ac"),
    _desc("zeekrchargerpowersensor", "Charging Power", _field("telemetry", "power_w", _float),
          native_unit_of_measurement=_W, device_class=SensorDeviceClass.POWER, state_class=MEASUREMENT,
          icon="mdi:flash"),
    _desc("zeekrchargertemperaturesensor", "Charger Temperature", _temperature,
          native_unit_of_measurement=UnitOfTemperature.CELSIUS, state_class=MEASUREMENT,
          device_class=SensorDeviceClass.TEMPERATURE, icon="mdi:thermometer", entity_category=DIAGNOSTIC),
    _desc("zeekrchargersessionruntimesensor", "Session Runtime", _field("telemetry", "session_runtime_seconds", _int),
          native_unit_of_measurement=UnitOfTime.SECONDS, device_class=SensorDeviceClass.DURATION,
          state_class=SensorStateClass.TOTAL_INCREASING, icon="mdi:timer", entity_category=DIAGNOSTIC),
    _desc("zeekrchargerphasestatussensor", "Phase Status", _field("telemetry", "phase_flags", _phase_status),
          icon="mdi:sine-wave", entity_category=DIAGNOSTIC),
    _desc("zeekrchargergridcapacitysensor", "Grid Capacity", _field("current_config", "grid_capacity_a", _float),
          native_unit_of_measurement=_A, device_class=SensorDeviceClass.CURRENT, state_class=MEASUREMENT,
          icon="mdi:transmission-tower", entity_category=DIAGNOSTIC),
)

# Per-phase telemetry (L1-L3): (legacy class id, name, telemetry key, unit, device class, icon, category)
_PHASE_KINDS = (
    ("zeekrchargerphasevoltagesensor", "Voltage L{p}", "voltage_l{p}_v", _V, SensorDeviceClass.VOLTAGE,
     "mdi:sine-wave", DIAGNOSTIC),
    ("zeekrchargerphasecurrentsensor", "Current L{p}", "current_l{p}_a", _A, SensorDeviceClass.CURRENT,
     "mdi:current-ac", None),
    ("zeekrchargerphasepowersensor", "Charging Power L{p}", "power_l{p}_w", _W, SensorDeviceClass.POWER,
     "mdi:flash", None),
)

PHASE_SENSORS: tuple[ZeekrSensorDescription, ...] = tuple(
    ZeekrSensorDescription(
        key=f"{legacy_id}_l{phase}",
        legacy_id=f"{legacy_id}_l{phase}",
        name=name.format(p=phase),
        value_fn=_field("telemetry", key.format(p=phase), _float),
        native_unit_of_measurement=unit,
        device_class=device_class,
        state_class=MEASUREMENT,
        icon=icon,
        entity_category=category,
    )
    for legacy_id, name, key, unit, device_class, icon, category in _PHASE_KINDS
    for phase in (1, 2, 3)
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger sensors from a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator

    entities: list[SensorEntity] = [
        ZeekrChargerSensor(coordinator, description) for description in (*SENSORS, *PHASE_SENSORS)
    ]
    entities += [
        ZeekrChargerStateSensor(coordinator),
        ZeekrChargerWifiStatusSensor(coordinator),
        ZeekrChargerConnectionStatusSensor(coordinator),
        ZeekrChargerReconnectAttemptsSensor(coordinator),
        ZeekrChargerChargeModeSensor(coordinator),
    ]
    async_add_entities(entities)


class ZeekrChargerBaseSensor(CoordinatorEntity, SensorEntity):
    """Common setup for all Zeekr charger sensors."""

    _legacy_id: str

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_device_info = build_device_info(coordinator)
        self._attr_unique_id = f"{coordinator.client.serial}_{self._legacy_id}"


class ZeekrChargerSensor(ZeekrChargerBaseSensor):
    """A sensor driven by a ZeekrSensorDescription."""

    entity_description: ZeekrSensorDescription

    def __init__(self, coordinator, description: ZeekrSensorDescription) -> None:
        self._legacy_id = description.legacy_id
        super().__init__(coordinator)
        self.entity_description = description

    @property
    def native_value(self):
        return self.entity_description.value_fn(self.coordinator.data)


class ZeekrChargerStateSensor(ZeekrChargerBaseSensor):
    """Sensor for charger state."""

    _legacy_id = "zeekrchargerstatesensor"
    _attr_name = "Charger State"
    _attr_icon = "mdi:ev-station"

    @property
    def native_value(self) -> str | None:
        return _charger_state(self.coordinator, self.coordinator.data)


class ZeekrChargerWifiStatusSensor(ZeekrChargerBaseSensor):
    """Sensor for WiFi status with error code mapping based on Android app E4 logic."""

    _legacy_id = "zeekrchargerwifistatussensor"

    _attr_name = "WiFi Status"
    _attr_icon = "mdi:wifi-settings"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def _get_wifi_error_description(self, error_code: int) -> str:
        """Translate WiFi error codes from Android app E4 logic."""
        # Based on CheckNetworkStatusResponse.smali error code mapping
        error_mappings = {
            0x200: "Success",
            0x400: "Client Problem", 
            0x500: "Server Problem",
            0x1401: "DHCP Startup Failed, WiFi Startup Failed",
            0x1502: "IP Setup Failed",
            0x5023: "Unknown WiFi Error, Startup Failed",
            0x1005: "SSID Invalid, Startup Failed",
            0x1006: "Password Invalid, Startup Failed",
            0x1001: "WiFi Module Not Found",
            0x1002: "WiFi Module Not Supported, WiFi Startup Failed", 
            0x1003: "WiFi Hardware Switch Not Opened, Startup Failed",
        }
        return error_mappings.get(error_code, f"Unknown Error (0x{error_code:04X})")

    @property
    def native_value(self) -> str | None:
        """Return the WiFi status with error code mapping."""
        # Check for network status response (0xD3) with error codes
        # This would come from CheckNetworkStatusResponse in the Android app
        wifi_status = self.coordinator.data.get("wifi_status", {})
        
        # Look for network status error codes
        network_status = wifi_status.get("network_status")
        if network_status is not None:
            if isinstance(network_status, int):
                return self._get_wifi_error_description(network_status)
            return str(network_status)
        
        # Check for result detail codes (from CheckNetworkStatusResponse)
        result_detail = wifi_status.get("result_detail")
        if result_detail is not None:
            if isinstance(result_detail, int):
                return self._get_wifi_error_description(result_detail)
            return str(result_detail)
        
        # Check for basic WiFi status
        status = wifi_status.get("wifi_status")
        if status is not None:
            if isinstance(status, int):
                return self._get_wifi_error_description(status)
            return str(status)
        
        # Fallback to basic connection status
        wifi_config = self.coordinator.data.get("wifi_config", {})
        wifi_function_enable = wifi_config.get("wifi_function_enable")
        if wifi_function_enable is not None:
            if isinstance(wifi_function_enable, int):
                return "Enabled" if wifi_function_enable == 1 else "Disabled"
            return str(wifi_function_enable)
        
        return "Unknown"


class ZeekrChargerConnectionStatusSensor(ZeekrChargerBaseSensor):
    """Sensor for BLE connection status."""

    _legacy_id = "zeekrchargerconnectionstatussensor"

    _attr_name = "Connection Status"
    _attr_icon = "mdi:bluetooth"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    

    @property
    def native_value(self) -> str | None:
        """Return the connection status."""
        connection_status = self.coordinator.get_connection_status()
        if connection_status.get("connected"):
            return "Connected"
        elif connection_status.get("should_reconnect"):
            return "Reconnecting"
        else:
            return "Disconnected"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        connection_status = self.coordinator.get_connection_status()
        return {
            "should_reconnect": connection_status.get("should_reconnect", False),
            "reconnect_attempts": connection_status.get("reconnect_attempts", 0),
            "max_reconnect_attempts": connection_status.get("max_reconnect_attempts", 0),
            "discovered_address": connection_status.get("discovered_address"),
            "has_token": connection_status.get("has_token", False),
            "last_heartbeat_time": connection_status.get("last_heartbeat_time", 0),
            "heartbeat_count": connection_status.get("heartbeat_count", 0),
        }


class ZeekrChargerReconnectAttemptsSensor(ZeekrChargerBaseSensor):
    """Sensor for reconnection attempts count."""

    _legacy_id = "zeekrchargerreconnectattemptssensor"

    _attr_name = "Reconnect Attempts"
    _attr_icon = "mdi:bluetooth-connect"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> int | None:
        """Return the number of reconnection attempts."""
        connection_status = self.coordinator.get_connection_status()
        return connection_status.get("reconnect_attempts", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        connection_status = self.coordinator.get_connection_status()
        return {
            "max_reconnect_attempts": connection_status.get("max_reconnect_attempts", 0),
            "connected": connection_status.get("connected", False),
            "should_reconnect": connection_status.get("should_reconnect", False),
        }


class ZeekrChargerChargeModeSensor(ZeekrChargerBaseSensor):
    """Sensor for current charge mode setting."""

    _legacy_id = "zeekrchargerchargemodesensor"

    _attr_name = "Charge Mode"
    _attr_icon = "mdi:ev-station"


    @property
    def native_value(self) -> str | None:
        """Return the current charge mode."""
        charge_mode = self.coordinator.data.get("charge_mode")
        if charge_mode is not None:
            return self._mode_to_text(charge_mode)
        return None

    def _mode_to_text(self, mode: int) -> str:
        """Convert numeric charge mode to text."""
        mode_map = {
            0x00: "Plug & Charge (Auto)",
            0x01: "Auth (Press start to charge)",
            0x02: "Scheduled",
            0x03: "Keyboard/Button",
            0x04: "Cost Effective",
            0x05: "Solar Only",
            0x10: "ECO Mode",
            0x12: "Solar Plus",
            0x26: "Selector/Config Mode",  # Value 38 (0x26) seen in earlier dumps
            0x8E: "Unknown/Error State",   # Value 142 (0x8E) seen in practice
            0xC0: "Configuration Mode",    # Value 192 (0xC0) seen in later dumps
            0x270F: "Unknown",
        }
        return mode_map.get(mode, f"Unknown Mode (0x{mode:02X})")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        charge_mode = self.coordinator.data.get("charge_mode")
        return {
            "raw_mode": charge_mode,
            "is_auto_mode": charge_mode == 0x00,
            "is_authorized_mode": charge_mode == 0x01,
        }
