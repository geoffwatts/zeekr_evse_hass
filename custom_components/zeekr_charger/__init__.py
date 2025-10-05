"""Home Assistant integration entry-point for Zeekr chargers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.typing import ConfigType

# Import these only when needed to avoid import issues during config flow
# from .lib import ZeekrBleClient
# from .coordinator import ZeekrChargerCoordinator
from .const import (
    CONF_DEVICE_ADDRESS,
    CONF_SERIAL,
    DATA_CLIENT,
    DATA_COORDINATOR,
    DOMAIN,
)

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SWITCH,
    Platform.NUMBER,
    Platform.BUTTON,
]


@dataclass
class ZeekrRuntimeData:
    """Runtime objects stored in hass.data for a config entry."""

    client: Any  # ZeekrBleClient
    coordinator: Any  # ZeekrChargerCoordinator


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the integration via YAML (unsupported)."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the integration from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    try:
        client = await _async_build_client(hass, entry)
    except Exception as err:
        raise ConfigEntryNotReady("Unable to initialise Zeekr BLE client") from err

    coordinator = await _async_build_coordinator(hass, entry, client)

    hass.data[DOMAIN][entry.entry_id] = ZeekrRuntimeData(client=client, coordinator=coordinator)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload an existing Zeekr charger entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    runtime: ZeekrRuntimeData | None = hass.data[DOMAIN].pop(entry.entry_id, None)
    if runtime:
        await _async_cleanup_runtime(runtime)

    return unload_ok


async def _async_build_client(hass: HomeAssistant, entry: ConfigEntry):
    """Instantiate the BLE client that will talk to the charger."""
    from .lib import ZeekrBleClient
    
    serial = entry.data[CONF_SERIAL]
    station_id = 88888
    address = entry.data.get(CONF_DEVICE_ADDRESS) or serial  # Use serial as BLE name if no address

    client = ZeekrBleClient(
        hass=hass,
        address=address,
        serial=serial,
        station_id=station_id,
    )

    # Connect to the charger
    if not await client.async_connect():
        raise ConfigEntryNotReady(f"Failed to connect to charger {serial}")

    return client


async def _async_build_coordinator(
    hass: HomeAssistant,
    entry: ConfigEntry,
    client,
):
    """Create and prime the data update coordinator."""
    from .coordinator import ZeekrChargerCoordinator
    
    coordinator = ZeekrChargerCoordinator(hass, client)
    
    # Start the heartbeat task
    await coordinator.async_start_heartbeat()
    
    # Perform initial data fetch
    await coordinator.async_config_entry_first_refresh()
    
    return coordinator


async def _async_cleanup_runtime(runtime: ZeekrRuntimeData) -> None:
    """Tear down runtime resources on unload."""
    if runtime.coordinator:
        await runtime.coordinator.async_shutdown()
    if runtime.client:
        await runtime.client.async_disconnect()
