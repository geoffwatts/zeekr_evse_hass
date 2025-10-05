"""Constants for the Zeekr Charger integration."""

from __future__ import annotations

DOMAIN = "zeekr_charger"
DATA_CLIENT = f"{DOMAIN}_client"
DATA_COORDINATOR = f"{DOMAIN}_coordinator"
CONF_SERIAL = "serial"
CONF_DEVICE_ADDRESS = "device_address"
DEFAULT_SCAN_INTERVAL = 15
CONFIG_FLOW_VERSION = 1

# Charge rate limits
MIN_CHARGE_RATE = 6  # Minimum charge rate in Amps
DEFAULT_MAX_CHARGE_RATE = 32  # Default fallback if grid capacity unavailable

# BLE Characteristics
GATT_CHAR_NOTIFY = "0000ff02-0000-1000-8000-00805f9b34fb"
GATT_CHAR_NOTIFY2 = "0000abf2-0000-1000-8000-00805f9b34fb"
GATT_CHAR_WNR = "0000abf1-0000-1000-8000-00805f9b34fb"
