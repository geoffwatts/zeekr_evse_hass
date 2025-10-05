"""Sensor platform for Zeekr charger."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfElectricCurrent
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN



async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger sensors from a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator

    entities = [
        ZeekrChargerCurrentLimitSensor(coordinator),
        ZeekrChargerMaxCurrentCapacitySensor(coordinator),
        ZeekrChargerStateSensor(coordinator),
        ZeekrChargerSerialSensor(coordinator),
        ZeekrChargerVersionSensor(coordinator),
        ZeekrChargerSoftwareVersionSensor(coordinator),
        ZeekrChargerProductionDateSensor(coordinator),
        ZeekrChargerRatedPowerSensor(coordinator),
        ZeekrChargerModelSensor(coordinator),
        # Removed manufacturer sensor - not needed
        # Safety sensors
        ZeekrChargerGroundingDetectionSensor(coordinator),
        ZeekrChargerRelayAdhesionSensor(coordinator),
        ZeekrChargerImproperGunLineSensor(coordinator),
        ZeekrChargerRcdDetectionSensor(coordinator),
        # Network sensors
        # Energy sensors
        ZeekrChargerSessionEnergySensor(coordinator),
        ZeekrChargerLifetimeEnergySensor(coordinator),
        ZeekrChargerVoltageSensor(coordinator),
        ZeekrChargerCurrentSensor(coordinator),
        ZeekrChargerSessionRuntimeSensor(coordinator),
        ZeekrChargerPhaseStatusSensor(coordinator),
        ZeekrChargerGridCapacitySensor(coordinator),
        ZeekrChargerWifiSsidSensor(coordinator),
        ZeekrChargerWifiStatusSensor(coordinator),
        ZeekrChargerConnectionStatusSensor(coordinator),
        ZeekrChargerReconnectAttemptsSensor(coordinator),
        ZeekrChargerChargeModeSensor(coordinator),
    ]

    async_add_entities(entities)


class ZeekrChargerSensor(CoordinatorEntity, SensorEntity):
    """Base class for Zeekr charger sensors."""

    def __init__(self, coordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.client.serial)},
            name=f"Zeekr Charger {coordinator.client.serial}",
            manufacturer="Zeekr",
            model="Wallbox Charger",
        )
        self._attr_unique_id = f"{coordinator.client.serial}_{self.__class__.__name__.lower()}"


class ZeekrChargerCurrentLimitSensor(ZeekrChargerSensor):
    """Sensor for current charge rate (charging limit)."""

    _attr_name = "Charge Rate"
    _attr_native_unit_of_measurement = UnitOfElectricCurrent.AMPERE

    _attr_icon = "mdi:lightning-bolt"

    @property
    def native_value(self) -> float | None:
        """Return the current charge rate in amperes."""
        power_status = self.coordinator.data.get("power_status", {})
        # Show configured limit if available, otherwise show home limit
        configured_limit = power_status.get("configured_limit_amps")
        if configured_limit is not None and configured_limit > 0:
            return float(configured_limit)
        
        # Fallback to home limit if no configured limit
        limit_amps = power_status.get("limit_amps")
        if limit_amps is not None:
            return float(limit_amps)
        return None


class ZeekrChargerMaxCurrentCapacitySensor(ZeekrChargerSensor):
    """Sensor for rated current capacity."""

    _attr_name = "Rated Current Capacity"
    _attr_native_unit_of_measurement = UnitOfElectricCurrent.AMPERE
    _attr_icon = "mdi:lightning-bolt-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> float | None:
        """Return the maximum current capacity in amperes."""
        # Prefer power_status (from 0xE0 query) as it's more reliable
        power_status = self.coordinator.data.get("power_status", {})
        max_capacity = power_status.get("max_current_capacity")
        if max_capacity is not None and max_capacity > 0:
            return float(max_capacity)
        
        # Fallback to current_config (from 0xA9 query)  
        current_config = self.coordinator.data.get("current_config", {})
        max_capacity = current_config.get("max_current_capacity_a")
        if max_capacity is not None and max_capacity > 0:
            return float(max_capacity)
        
        return None






class ZeekrChargerSerialSensor(ZeekrChargerSensor):
    """Sensor for charger serial number."""

    _attr_name = "Serial Number"
    _attr_icon = "mdi:identifier"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the charger serial number."""
        basic_info = self.coordinator.data.get("basic_info", {})
        # The serial number is stored in charge_point_number field
        return basic_info.get("charge_point_number")


class ZeekrChargerVersionSensor(ZeekrChargerSensor):
    """Sensor for charger firmware version."""

    _attr_name = "Firmware Version"
    _attr_icon = "mdi:chip"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the firmware version."""
        basic_info = self.coordinator.data.get("basic_info", {})
        # Look for version in various field formats
        for key, value in basic_info.items():
            if any(term in key.lower() for term in ["version", "firmware", "ver"]) and isinstance(value, str):
                return value
        return None


class ZeekrChargerStateSensor(ZeekrChargerSensor):
    """Sensor for charger state."""

    _attr_name = "Charger State"
    _attr_icon = "mdi:ev-station"


    @property
    def native_value(self) -> str | None:
        """Return the charger state."""
        # Check if Bluetooth is connected - only show charger state when actually connected
        connection_status = self.coordinator.get_connection_status()
        if not connection_status.get("connected"):
            return "disconnected"
        
        heartbeat_state = self.coordinator.data.get("heartbeat_state", {})
        return heartbeat_state.get("state", "unknown")


class ZeekrChargerSoftwareVersionSensor(ZeekrChargerSensor):
    """Sensor for charger software version."""

    _attr_name = "Software Version"
    _attr_icon = "mdi:chip"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the software version."""
        basic_info = self.coordinator.data.get("basic_info", {})
        # Try different possible field names
        for field in ["c_board_software_version", "software_version", "firmware_version"]:
            if field in basic_info:
                return basic_info[field]
        return None


class ZeekrChargerProductionDateSensor(ZeekrChargerSensor):
    """Sensor for charger production date."""

    _attr_name = "Production Date"
    _attr_icon = "mdi:calendar"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the production date."""
        basic_info = self.coordinator.data.get("basic_info", {})
        return basic_info.get("production_date")


class ZeekrChargerRatedPowerSensor(ZeekrChargerSensor):
    """Sensor for rated power."""

    _attr_name = "Rated Power"
    _attr_native_unit_of_measurement = "kW"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:flash"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> float | None:
        """Return the rated power in kilowatts."""
        basic_info = self.coordinator.data.get("basic_info", {})
        rated_power = basic_info.get("rated_power_w")
        if rated_power is not None:
            # Convert watts to kilowatts
            return float(rated_power) / 1000.0
        return None


class ZeekrChargerModelSensor(ZeekrChargerSensor):
    """Sensor for charger model."""

    _attr_name = "Model"
    _attr_icon = "mdi:ev-station"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the charger model."""
        basic_info = self.coordinator.data.get("basic_info", {})
        model_number = basic_info.get("model_number")
        return model_number


class ZeekrChargerManufacturerSensor(ZeekrChargerSensor):
    """Sensor for charger manufacturer."""

    _attr_name = "Manufacturer"
    _attr_icon = "mdi:factory"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the charger manufacturer."""
        basic_info = self.coordinator.data.get("basic_info", {})
        return basic_info.get("manufacturer")


# Safety Sensors
class ZeekrChargerGroundingDetectionSensor(ZeekrChargerSensor):
    """Sensor for grounding detection status."""

    _attr_name = "Grounding Detection"
    _attr_icon = "mdi:earth"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the grounding detection status."""
        protection_info = self.coordinator.data.get("protection_info", {})
        grounding = protection_info.get("grounding_detection")
        if grounding is not None:
            return "Enabled" if grounding == 1 else "Disabled"
        return None


class ZeekrChargerRelayAdhesionSensor(ZeekrChargerSensor):
    """Sensor for relay adhesion detection status."""

    _attr_name = "Relay Adhesion Detection"
    _attr_icon = "mdi:connection"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the relay adhesion detection status."""
        protection_info = self.coordinator.data.get("protection_info", {})
        relay = protection_info.get("relay_adhesion_detection")
        if relay is not None:
            return "Enabled" if relay == 1 else "Disabled"
        return None


class ZeekrChargerImproperGunLineSensor(ZeekrChargerSensor):
    """Sensor for improper gun line detection status."""

    _attr_name = "Improper Cable Detection"
    _attr_icon = "mdi:alert-circle"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the improper gun line detection status."""
        protection_info = self.coordinator.data.get("protection_info", {})
        gun_line = protection_info.get("detection_of_improper_gun_line")
        if gun_line is not None:
            return "Enabled" if gun_line == 1 else "Disabled"
        return None


class ZeekrChargerRcdDetectionSensor(ZeekrChargerSensor):
    """Sensor for RCD detection status."""

    _attr_name = "RCD Detection"
    _attr_icon = "mdi:shield-check"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the RCD detection status."""
        protection_info = self.coordinator.data.get("protection_info", {})
        rcd = protection_info.get("rcd_detection")
        if rcd is not None:
            return "Enabled" if rcd == 1 else "Disabled"
        return None


# Network Sensors


class ZeekrChargerWifiSsidSensor(ZeekrChargerSensor):
    """Sensor for WiFi SSID."""

    _attr_name = "WiFi SSID"
    _attr_icon = "mdi:wifi"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the WiFi SSID."""
        # Check WiFi status (0xE4 response) for SSID
        wifi_status = self.coordinator.data.get("wifi_status", {})
        ssid = wifi_status.get("ssid")
        if ssid:
            return str(ssid)
        return None


class ZeekrChargerWifiStatusSensor(ZeekrChargerSensor):
    """Sensor for WiFi status with error code mapping based on Android app E4 logic."""

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




# Energy Sensors
class ZeekrChargerSessionEnergySensor(ZeekrChargerSensor):
    """Sensor for energy consumed in current session."""

    _attr_name = "Session Energy"
    _attr_native_unit_of_measurement = "kWh"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_icon = "mdi:lightning-bolt"

    @property
    def native_value(self) -> float | None:
        """Return the session energy in kWh."""
        telemetry = self.coordinator.data.get("telemetry", {})
        session_energy = telemetry.get("session_energy_kwh")
        if session_energy is not None:
            return float(session_energy)
        return None


class ZeekrChargerLifetimeEnergySensor(ZeekrChargerSensor):
    """Sensor for total lifetime energy consumption."""

    _attr_name = "Lifetime Energy"
    _attr_native_unit_of_measurement = "kWh"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_icon = "mdi:counter"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> float | None:
        """Return the lifetime energy in kWh."""
        telemetry = self.coordinator.data.get("telemetry", {})
        lifetime_energy = telemetry.get("lifetime_energy_kwh")
        if lifetime_energy is not None:
            return float(lifetime_energy)
        return None


class ZeekrChargerVoltageSensor(ZeekrChargerSensor):
    """Sensor for line voltage."""

    _attr_name = "Voltage"
    _attr_native_unit_of_measurement = "V"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:lightning-bolt"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> float | None:
        """Return the line voltage in volts."""
        telemetry = self.coordinator.data.get("telemetry", {})
        voltage = telemetry.get("voltage_v")
        if voltage is not None:
            return float(voltage)
        return None


class ZeekrChargerCurrentSensor(ZeekrChargerSensor):
    """Sensor for charging current."""

    _attr_name = "In-use Current"
    _attr_native_unit_of_measurement = UnitOfElectricCurrent.AMPERE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:current-ac"

    @property
    def native_value(self) -> float | None:
        """Return the charging current in amperes."""
        telemetry = self.coordinator.data.get("telemetry", {})
        current = telemetry.get("current_a")
        if current is not None:
            return float(current)
        return None


class ZeekrChargerSessionRuntimeSensor(ZeekrChargerSensor):
    """Sensor for session runtime duration."""

    _attr_name = "Session Runtime"
    _attr_native_unit_of_measurement = "s"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_icon = "mdi:timer"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> int | None:
        """Return the session runtime in seconds."""
        telemetry = self.coordinator.data.get("telemetry", {})
        runtime = telemetry.get("session_runtime_seconds")
        if runtime is not None:
            return int(runtime)
        return None


class ZeekrChargerPhaseStatusSensor(ZeekrChargerSensor):
    """Sensor for phase status flags."""

    _attr_name = "Phase Status"
    _attr_icon = "mdi:sine-wave"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str | None:
        """Return the phase status."""
        telemetry = self.coordinator.data.get("telemetry", {})
        phase_flags = telemetry.get("phase_flags")
        if phase_flags is not None:
            # Treat lower bits as per-phase flags; chargers sometimes add
            # higher-order status bits, so only count active phase bits.
            active_bits = phase_flags & 0x07
            if active_bits == 0 or (active_bits & (active_bits - 1) == 0):
                return "Single Phase"
            return f"Multi Phase (flags: 0x{phase_flags:02X})"
        return None


class ZeekrChargerGridCapacitySensor(ZeekrChargerSensor):
    """Sensor for grid capacity (from 0xA9 home current config query)."""

    _attr_name = "Grid Capacity"
    _attr_native_unit_of_measurement = UnitOfElectricCurrent.AMPERE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:transmission-tower"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    
    def __init__(self, coordinator) -> None:
        """Initialize the grid capacity sensor."""
        super().__init__(coordinator)

    @property
    def native_value(self) -> float | None:
        """Return the grid capacity in amperes."""
        current_config = self.coordinator.data.get("current_config", {})
        grid_capacity = current_config.get("grid_capacity_a")
        if grid_capacity is not None:
            result = float(grid_capacity)
            return result
        return None


class ZeekrChargerConnectionStatusSensor(ZeekrChargerSensor):
    """Sensor for BLE connection status."""

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


class ZeekrChargerReconnectAttemptsSensor(ZeekrChargerSensor):
    """Sensor for reconnection attempts count."""

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


class ZeekrChargerChargeModeSensor(ZeekrChargerSensor):
    """Sensor for current charge mode setting."""

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


