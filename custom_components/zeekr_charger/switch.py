"""Switch platform for Zeekr charger."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
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
    """Set up Zeekr charger switch entities from a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator

    entities = [
        ZeekrChargerAutoChargeSwitch(coordinator),
    ]

    async_add_entities(entities)


class ZeekrChargerSwitch(CoordinatorEntity, SwitchEntity):
    """Base class for Zeekr charger switch entities."""

    def __init__(self, coordinator) -> None:
        """Initialize the switch entity."""
        super().__init__(coordinator)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.client.serial)},
            name=f"Zeekr Charger {coordinator.client.serial}",
            manufacturer="Zeekr",
            model="Wallbox Charger",
        )
        self._attr_unique_id = f"{coordinator.client.serial}_{self.__class__.__name__.lower()}"


class ZeekrChargerAutoChargeSwitch(ZeekrChargerSwitch):
    """Switch entity for auto charge mode (charge-on-plug-in vs authorized charging)."""

    _attr_name = "Plug & Charge"
    _attr_icon = "mdi:auto-fix"
    _attr_entity_category = EntityCategory.CONFIG

    @property
    def is_on(self) -> bool | None:
        """Return if auto charge mode is enabled."""
        charge_mode = self.coordinator.data.get("charge_mode")
        if charge_mode is not None:
            # 0x00 = auto mode (plug & charge), 0x01 = authorized mode
            return charge_mode == 0x00
        return None

    async def async_turn_on(self) -> None:
        """Turn on auto charge mode (charge-on-plug-in)."""
        try:
            await self.coordinator.client.set_charge_model(0x00)  # Auto mode
            await self.coordinator.async_request_refresh()
        except Exception as exc:
            raise

    async def async_turn_off(self) -> None:
        """Turn off auto charge mode (require authorization)."""
        try:
            await self.coordinator.client.set_charge_model(0x01)  # Authorized mode
            await self.coordinator.async_request_refresh()
        except Exception as exc:
            raise