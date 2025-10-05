"""Number platform for Zeekr charger."""

from __future__ import annotations

from typing import Any

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfElectricCurrent
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN, MIN_CHARGE_RATE, DEFAULT_MAX_CHARGE_RATE



async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger number entities from a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator

    entities = [
        ZeekrChargerCurrentLimitNumber(coordinator),
    ]

    async_add_entities(entities)


class ZeekrChargerNumber(CoordinatorEntity, NumberEntity):
    """Base class for Zeekr charger number entities."""

    def __init__(self, coordinator) -> None:
        """Initialize the number entity."""
        super().__init__(coordinator)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.client.serial)},
            name=f"Zeekr Charger {coordinator.client.serial}",
            manufacturer="Zeekr",
            model="Wallbox Charger",
        )
        self._attr_unique_id = f"{coordinator.client.serial}_{self.__class__.__name__.lower()}"


class ZeekrChargerCurrentLimitNumber(ZeekrChargerNumber):
    """Number entity for setting charge rate (current limit)."""

    _attr_name = "Charge Rate"
    _attr_native_unit_of_measurement = UnitOfElectricCurrent.AMPERE
    _attr_mode = NumberMode.BOX
    _attr_native_step = 1
    _attr_icon = "mdi:lightning-bolt"
    _attr_entity_category = EntityCategory.CONFIG

    @property
    def native_min_value(self) -> float:
        """Return the minimum charge rate (6A)."""
        return float(MIN_CHARGE_RATE)

    @property
    def native_max_value(self) -> float:
        """Return the maximum charge rate based on grid capacity."""
        # Get grid capacity from charger data
        current_config = self.coordinator.data.get("current_config", {})
        grid_capacity = current_config.get("grid_capacity_a")
        
        if grid_capacity is not None and grid_capacity > 0:
            return float(grid_capacity)
        
        # Fallback to power_status max_current_capacity if grid_capacity not available
        power_status = self.coordinator.data.get("power_status", {})
        max_capacity = power_status.get("max_current_capacity")
        
        if max_capacity is not None and max_capacity > 0:
            return float(max_capacity)
        
        # Final fallback to default
        return float(DEFAULT_MAX_CHARGE_RATE)

    @property
    def native_value(self) -> float | None:
        """Return the current charge rate (current limit) in amperes."""
        power_status = self.coordinator.data.get("power_status", {})
        limit_amps = power_status.get("limit_amps")
        if limit_amps is not None:
            return float(limit_amps)  # limit_amps is already in amperes
        return None

    async def async_set_native_value(self, value: float) -> None:
        """Set the charge rate (current limit) using C0 command."""
        amps = int(value)
        
        # Get grid capacity to enforce maximum limit
        grid_capacity = self.native_max_value
        
        # Clamp to valid range: minimum 6A, maximum grid capacity
        amps = max(MIN_CHARGE_RATE, min(amps, int(grid_capacity)))
        
        try:
            # Set current limit using the C0 command (POWER_CONTROL)
            success = await self.coordinator.client.set_current_limit(0, amps)
            
            if success:
                # Query power status to get updated current limit values
                power_status = await self.coordinator.client.query_power_status()
                if power_status:
                    pass  # power status available
                # Refresh data to get updated values
                await self.coordinator.async_request_refresh()
            else:
                raise RuntimeError("Failed to set charge rate")
            
        except Exception as exc:
            raise