"""Device registry info for the charger, based on what it reports about itself."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN

DEFAULT_MANUFACTURER = "Zeekr"
DEFAULT_MODEL = "Wallbox Charger"

# Model names (from the 0xC1 basic info "model_number") of chargers sold under
# another brand than Zeekr. The charger doesn't report a manufacturer itself.
MODEL_MANUFACTURERS = {
    "neo": "Raedian",
}


def device_fields(serial: str, basic_info: dict[str, Any] | None) -> dict[str, Any]:
    """Return manufacturer, model, name and versions for the device registry."""
    basic_info = basic_info or {}
    model = basic_info.get("model_number") or basic_info.get("charge_point_type")

    if not model:
        return {
            "manufacturer": DEFAULT_MANUFACTURER,
            "model": DEFAULT_MODEL,
            "name": f"{DEFAULT_MANUFACTURER} Charger {serial}",
        }

    manufacturer = MODEL_MANUFACTURERS.get(str(model).strip().lower(), DEFAULT_MANUFACTURER)
    fields: dict[str, Any] = {
        "manufacturer": manufacturer,
        "model": str(model),
        "name": f"{manufacturer} {model} {serial}",
    }
    if basic_info.get("p_board_software_version"):
        fields["sw_version"] = basic_info["p_board_software_version"]
    if basic_info.get("hardware_version"):
        fields["hw_version"] = basic_info["hardware_version"]
    return fields


def build_device_info(coordinator) -> DeviceInfo:
    """Build the DeviceInfo shared by all entities of this charger."""
    serial = coordinator.client.serial
    basic_info = (coordinator.data or {}).get("basic_info")
    return DeviceInfo(
        identifiers={(DOMAIN, serial)},
        **device_fields(serial, basic_info),
    )


def async_update_device(hass: HomeAssistant, serial: str, basic_info: dict[str, Any]) -> None:
    """Update an existing device once the charger has reported its basic info.

    A name the user set in the UI (name_by_user) is left alone by Home Assistant.
    """
    registry = dr.async_get(hass)
    device = registry.async_get_device(identifiers={(DOMAIN, serial)})
    if device is None:
        return
    registry.async_update_device(device.id, **device_fields(serial, basic_info))
