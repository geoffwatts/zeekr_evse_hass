"""
Zeekr Charger BLE Library for Home Assistant
"""

from .protocol import (
    GATT_CHAR_NOTIFY,
    GATT_CHAR_NOTIFY2,
    GATT_CHAR_WNR,
    OPC,
    RESPONSE_STATUS_TEXT,
    HeartbeatState,
    PowerStatus,
    CurrentConfig,
    build_identity_frame,
    parse_frame,
    parse_heartbeat_state,
    parse_power_status,
    parse_tlv_response,
)

from .ble_client import ZeekrBleClient

__all__ = [
    "ZeekrBleClient",
    "GATT_CHAR_NOTIFY",
    "GATT_CHAR_NOTIFY2", 
    "GATT_CHAR_WNR",
    "OPC",
    "RESPONSE_STATUS_TEXT",
    "HeartbeatState",
    "PowerStatus",
    "CurrentConfig",
    "build_identity_frame",
    "parse_frame",
    "parse_heartbeat_state",
    "parse_power_status",
    "parse_tlv_response",
]
