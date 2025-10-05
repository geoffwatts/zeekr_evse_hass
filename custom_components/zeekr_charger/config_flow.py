"""Config flow for the Zeekr charger integration."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from .const import (
    CONF_DEVICE_ADDRESS,
    CONF_SERIAL,
    CONFIG_FLOW_VERSION,
    DOMAIN,
)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SERIAL): str,
        vol.Optional(
            CONF_DEVICE_ADDRESS,
            description="BLE MAC address of the charger (e.g., AA:BB:CC:DD:EE:FF). Leave empty to auto-discover."
        ): str,
    }
)


class ZeekrChargerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for the Zeekr charger."""

    VERSION = CONFIG_FLOW_VERSION

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial step where the user configures the charger."""
        errors: dict[str, str] = {}

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors)

        serial = user_input[CONF_SERIAL].strip().upper()
        device_address = user_input.get(CONF_DEVICE_ADDRESS, "").strip()
        
        # Validate device address format if provided
        if device_address and not self._is_valid_mac_address(device_address):
            errors[CONF_DEVICE_ADDRESS] = "Invalid BLE MAC address format. Use format like AA:BB:CC:DD:EE:FF or AABBCCDDEEFF"
            return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors)

        unique_id = f"{serial}"

        await self.async_set_unique_id(unique_id)
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=serial,
            data={
                CONF_SERIAL: serial,
                CONF_DEVICE_ADDRESS: device_address or None,
            },
        )

    def _is_valid_mac_address(self, address: str) -> bool:
        """Check if the address is a valid MAC address format."""
        import re
        # MAC address pattern: XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$'
        return bool(re.match(mac_pattern, address))

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return ZeekrChargerOptionsFlowHandler(config_entry)


class ZeekrChargerOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options for the Zeekr charger config entry."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        """Manage the options for the custom component."""
        if user_input is not None:
            return self.async_create_entry(title="Zeekr Charger Options", data=user_input)

        data_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_DEVICE_ADDRESS,
                    default=self.config_entry.data.get(CONF_DEVICE_ADDRESS) or self.config_entry.options.get(CONF_DEVICE_ADDRESS, ""),
                ): str,
            }
        )

        return self.async_show_form(step_id="init", data_schema=data_schema)
