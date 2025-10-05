"""Binary sensor platform for Zeekr charger."""

from __future__ import annotations


from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorDeviceClass
from homeassistant.config_entries import ConfigEntry
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
    """Set up Zeekr charger binary sensors from a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator

    entities = [
        ZeekrChargerChargingBinarySensor(coordinator),
        ZeekrChargerCarConnectedBinarySensor(coordinator),
        ZeekrChargerHeartbeatBinarySensor(coordinator),
    ]

    async_add_entities(entities)


class ZeekrChargerBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Base class for Zeekr charger binary sensors."""

    def __init__(self, coordinator) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.client.serial)},
            name=f"Zeekr Charger {coordinator.client.serial}",
            manufacturer="Zeekr",
            model="Wallbox Charger",
        )
        self._attr_unique_id = f"{coordinator.client.serial}_{self.__class__.__name__.lower()}"




class ZeekrChargerChargingBinarySensor(ZeekrChargerBinarySensor):
    """Binary sensor for charging status."""

    _attr_name = "Charging"
    _attr_icon = "mdi:ev-station"
    _attr_device_class = BinarySensorDeviceClass.RUNNING

    @property
    def is_on(self) -> bool:
        """Return True if the charger is actively charging."""
        heartbeat_state = self.coordinator.data.get("heartbeat_state", {})
        return heartbeat_state.get("charging", False)


class ZeekrChargerCarConnectedBinarySensor(ZeekrChargerBinarySensor):
    """Binary sensor for car connection status."""

    _attr_name = "Car Connected"
    _attr_icon = "mdi:car-electric"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    @property
    def is_on(self) -> bool:
        """Return True if a car is connected to the charger."""
        heartbeat_state = self.coordinator.data.get("heartbeat_state", {})
        return heartbeat_state.get("car_connected", False)


class ZeekrChargerHeartbeatBinarySensor(ZeekrChargerBinarySensor):
    """Binary sensor for heartbeat status."""

    _attr_name = "Heartbeat Active <60s"
    _attr_icon = "mdi:heart-pulse"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def is_on(self) -> bool:
        """Return True if we're receiving heartbeats from the charger."""
        import time
        
        # Check if we have a session token and recent heartbeat data
        session_token = self.coordinator.data.get("session_token")
        last_heartbeat_time = self.coordinator.data.get("last_heartbeat_time", 0)
        current_time = time.time()
        
        # Consider heartbeat active if we have a token and received a heartbeat within the last 60 seconds
        return bool(session_token) and (current_time - last_heartbeat_time) < 60