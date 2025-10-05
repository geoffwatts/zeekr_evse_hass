"""Button platform for Zeekr charger."""

from __future__ import annotations

from typing import Any

from homeassistant.components.button import ButtonEntity
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
    """Set up Zeekr charger button entities from a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator

    entities = [
        ZeekrChargerAuthorizeChargeButton(coordinator),
        ZeekrChargerStopChargeButton(coordinator),
    ]

    async_add_entities(entities)


class ZeekrChargerButton(CoordinatorEntity, ButtonEntity):
    """Base class for Zeekr charger button entities."""

    def __init__(self, coordinator) -> None:
        """Initialize the button entity."""
        super().__init__(coordinator)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.client.serial)},
            name=f"Zeekr Charger {coordinator.client.serial}",
            manufacturer="Zeekr",
            model="Wallbox Charger",
        )
        self._attr_unique_id = f"{coordinator.client.serial}_{self.__class__.__name__.lower()}"


class ZeekrChargerAuthorizeChargeButton(ZeekrChargerButton):
    """Button entity for authorizing charge session."""

    _attr_name = "Start Charging"
    _attr_icon = "mdi:play"


    async def async_press(self) -> None:
        """Handle the button press."""
        try:
            await self.coordinator.client.authorize_charge()
            # Refresh data to get updated values
            await self.coordinator.async_request_refresh()
        except Exception as exc:
            raise


class ZeekrChargerStopChargeButton(ZeekrChargerButton):
    """Button entity for stopping charge session."""

    _attr_name = "Stop Charging"
    _attr_icon = "mdi:stop"


    async def async_press(self) -> None:
        """Handle the button press."""
        try:
            await self.coordinator.client.stop_charge()
            # Refresh data to get updated values
            await self.coordinator.async_request_refresh()
        except Exception as exc:
            raise
