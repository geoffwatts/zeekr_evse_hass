"""
Clean BLE Client for Zeekr Charger Communication

To enable verbose BLE protocol logging (tx/rx chunks, opcodes, frame parsing details),
set VERBOSE_LOGGING = True at the top of this file.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant

# Using V1 plaintext mode only
from .protocol import (
    GATT_CHAR_NOTIFY,
    GATT_CHAR_NOTIFY2,
    GATT_CHAR_WNR,
    build_identity_frame,
    cmd_heartbeat,
    cmd_sync_time,
    cmd_get_employ_info,
    cmd_get_ble_info,
    cmd_set_current_limit,
    cmd_auth_charge,
    cmd_stop_charge,
    parse_frame,
    extract_token_from_response,
    parse_heartbeat_state,
    parse_power_status,
    parse_tlv_response,
    parse_b5_telemetry,
    pack_frame_request,
    HeartbeatState,
    PowerStatus,
    CurrentConfig,
    B5Telemetry,
)

_LOGGER = logging.getLogger(__name__)

# Verbose logging control - set to True to enable detailed BLE protocol logging
VERBOSE_LOGGING = False

# Simple focused logging for key events
def log_connection(message: str):
    """Log connection events"""
    _LOGGER.info(f"[CONNECTION] {message}")

def log_status(message: str):
    """Log charger status changes"""
    _LOGGER.info(f"[STATUS] {message}")

def log_hex_tx(data: bytes):
    """Log transmitted hex data"""
    if VERBOSE_LOGGING:
        _LOGGER.info(f"[TX] {data.hex().upper()}")

def log_hex_rx(data: bytes):
    """Log received hex data"""
    if VERBOSE_LOGGING:
        _LOGGER.info(f"[RX] {data.hex().upper()}")


class ZeekrBleClient:
    """Clean BLE client for Zeekr charger communication."""

    def __init__(
        self,
        hass: HomeAssistant,
        address: str,
        serial: str,
        station_id: int,
    ) -> None:
        """Initialize the BLE client."""
        self.hass = hass
        self.address = address
        self.serial = serial
        self.station_id = station_id
        self._client: Optional[BleakClient] = None
        self._token: Optional[bytes] = None
        self._connected = False
        self._last_heartbeat_time: float = 0.0
        self._heartbeat_count: int = 0
        self._charging_session_start: Optional[float] = None
        self._session_energy_offset_kwh: Optional[float] = None
        self._notification_callbacks: list[Callable[[bytes], None]] = []
        self._frame_buffer: dict[int, bytearray] = {}
        self._pending_responses: dict[int, asyncio.Future[bytes]] = {}
        self._last_heartbeat_state: HeartbeatState = HeartbeatState()
        self._last_telemetry: Optional[B5Telemetry] = None
        self._last_power_status: Optional[PowerStatus] = None
        
        # Reconnection logic
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_attempts: int = 0
        self._max_reconnect_attempts: int = 10
        self._reconnect_delay: float = 5.0  # Start with 5 seconds
        self._max_reconnect_delay: float = 300.0  # Max 5 minutes
        self._last_connection_attempt: float = 0.0
        self._connection_monitor_task: Optional[asyncio.Task] = None
        self._should_reconnect: bool = True
        self._discovered_address: Optional[str] = None

    # Using V1 plaintext mode only

    async def _discover_device(self) -> Optional[str]:
        """Discover the Zeekr charger device."""
        try:
            # If we have a proper MAC address format, use it directly
            if self._is_valid_mac_address(self.address):
                _LOGGER.info("Using provided MAC address: %s", self.address)
                return self.address.upper()
            
            # Otherwise, try to discover by name or other characteristics
            _LOGGER.info("Discovering Zeekr charger device by name: %s", self.address)
            
            # Get all discovered BLE devices
            discovered_devices = bluetooth.async_discovered_service_info(self.hass)
            
            for device_info in discovered_devices:
                device_name = device_info.name or ""
                device_address = device_info.address
                
                _LOGGER.debug("Found device: %s (%s)", device_name, device_address)
                
                # Look for devices that match our serial number or address
                if (device_name == self.address or 
                    device_name == self.serial or
                    self.address.lower() in device_name.lower() or
                    self.serial.lower() in device_name.lower()):
                    _LOGGER.info("Found Zeekr charger: %s (%s)", device_name, device_address)
                    return device_address
            
            _LOGGER.error(
                "Could not find Zeekr charger with name '%s'. "
                "Found devices: %s. "
                "Please provide the BLE MAC address directly in the Device Address field.",
                self.address,
                [f"{d.name or 'Unknown'} ({d.address})" for d in discovered_devices]
            )
            return None
            
        except Exception as exc:
            _LOGGER.error("Device discovery failed: %s", exc)
            return None

    def _is_valid_mac_address(self, address: str) -> bool:
        """Check if the address is a valid MAC address format."""
        import re
        # MAC address pattern: XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$'
        return bool(re.match(mac_pattern, address))

    async def async_connect(self) -> bool:
        """Connect to the charger."""
        try:
            # First, try to discover the device if we don't have a proper MAC address
            device_address = await self._discover_device()
            if not device_address:
                _LOGGER.error("Could not discover Zeekr charger device")
                return False

            _LOGGER.info("Found Zeekr charger at %s", device_address)
            self._discovered_address = device_address  # Store for reconnection
            
            # Try to get the device from Home Assistant's BLE stack first
            ha_device = self._lookup_ble_device(device_address)
            if ha_device is not None:
                _LOGGER.info("Using Home Assistant BLE device: %s", device_address)
                bleak_client = await establish_connection(
                    BleakClient,
                    ha_device,
                    f"zeekr_charger_{self.serial}",
                    max_attempts=3,
                )
            else:
                _LOGGER.info("Connecting directly to BLE address: %s", device_address)
                bleak_client = await establish_connection(
                    BleakClient,
                    device_address,
                    f"zeekr_charger_{self.serial}",
                    max_attempts=3,
                )
            
            # establish_connection returns a connected client or raises an exception
            if not bleak_client or not bleak_client.is_connected:
                _LOGGER.error("Failed to connect to BLE device")
                return False

            log_connection(f"Connected to charger at {device_address}")
            self._client = bleak_client
            
            # Try to maximize MTU (only if the client supports it)
            try:
                if hasattr(self._client, 'exchange_mtu'):
                    mtu = await self._client.exchange_mtu(517)
                    _LOGGER.debug("Negotiated MTU: %d", mtu)
                else:
                    _LOGGER.debug("MTU exchange not supported by this BLE client")
            except Exception as exc:
                _LOGGER.warning("MTU exchange failed: %s", exc)

            # Enable notifications
            await self._enable_notifications()
            
            # Authenticate
            if await self._authenticate():
                self._connected = True
                # Start connection monitoring for automatic reconnection
                await self._start_connection_monitor()
                return True
            else:
                await self.async_disconnect()
                return False

        except Exception as exc:
            _LOGGER.error("Connection failed: %s", exc)
            return False

    async def async_disconnect(self) -> None:
        """Disconnect from the charger."""
        _LOGGER.info("Disconnecting from charger...")
        self._should_reconnect = False
        
        # Stop reconnection tasks
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
        
        if self._connection_monitor_task and not self._connection_monitor_task.done():
            self._connection_monitor_task.cancel()
            try:
                await self._connection_monitor_task
            except asyncio.CancelledError:
                pass
        
        # Disconnect the client
        if self._client and self._client.is_connected:
            try:
                await self._client.disconnect()
            except Exception as exc:
                _LOGGER.warning("Error during disconnect: %s", exc)
        
        self._connected = False
        self._token = None
        self._client = None
        self._reconnect_attempts = 0
        log_connection("Disconnected from charger")

    async def _start_connection_monitor(self) -> None:
        """Start monitoring the connection and trigger reconnection if needed."""
        if self._connection_monitor_task and not self._connection_monitor_task.done():
            return
        
        self._connection_monitor_task = asyncio.create_task(self._connection_monitor_loop())
        if VERBOSE_LOGGING:
            _LOGGER.info("Started connection monitor")

    async def _connection_monitor_loop(self) -> None:
        """Monitor connection health and trigger reconnection if needed."""
        if VERBOSE_LOGGING:
            _LOGGER.info("Connection monitor started")
        
        while self._should_reconnect:
            try:
                # Check if we should be connected but aren't
                if not self.is_connected and self._should_reconnect:
                    log_connection("Connection lost, triggering reconnection...")
                    await self._trigger_reconnection()
                
                # Wait before next check
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except asyncio.CancelledError:
                _LOGGER.info("Connection monitor cancelled")
                break
            except Exception as exc:
                _LOGGER.warning("Connection monitor error: %s", exc)
                await asyncio.sleep(5)  # Wait before retrying
        
        _LOGGER.info("Connection monitor stopped")

    async def _trigger_reconnection(self) -> None:
        """Trigger reconnection if not already in progress."""
        if self._reconnect_task and not self._reconnect_task.done():
            _LOGGER.debug("Reconnection already in progress")
            return
        
        self._reconnect_task = asyncio.create_task(self._reconnection_loop())
        _LOGGER.info("Triggered reconnection")

    async def _reconnection_loop(self) -> None:
        """Handle reconnection with exponential backoff."""
        _LOGGER.info("Starting reconnection loop")
        
        while self._should_reconnect and self._reconnect_attempts < self._max_reconnect_attempts:
            try:
                self._reconnect_attempts += 1
                current_delay = min(self._reconnect_delay * (2 ** (self._reconnect_attempts - 1)), self._max_reconnect_delay)
                
                log_connection(f"Retrying connection (attempt {self._reconnect_attempts}/{self._max_reconnect_attempts}) in {current_delay:.1f}s")
                
                # Wait before attempting reconnection
                await asyncio.sleep(current_delay)
                
                if not self._should_reconnect:
                    break
                
                # Attempt to reconnect
                if await self._attempt_reconnection():
                    log_connection(f"Reconnection successful after {self._reconnect_attempts} attempts")
                    self._reconnect_attempts = 0  # Reset counter on success
                    return
                else:
                    _LOGGER.warning("Reconnection attempt %d failed", self._reconnect_attempts)
                    
            except asyncio.CancelledError:
                _LOGGER.info("Reconnection cancelled")
                break
            except Exception as exc:
                _LOGGER.error("Reconnection error: %s", exc)
        
        if self._reconnect_attempts >= self._max_reconnect_attempts:
            _LOGGER.error("Max reconnection attempts reached (%d), giving up", self._max_reconnect_attempts)
        else:
            _LOGGER.info("Reconnection stopped (should_reconnect=False)")

    async def _attempt_reconnection(self) -> bool:
        """Attempt to reconnect to the charger."""
        try:
            _LOGGER.info("Attempting to reconnect to charger...")
            
            # Clean up existing connection
            if self._client:
                try:
                    if self._client.is_connected:
                        await self._client.disconnect()
                except Exception:
                    pass
                self._client = None
            
            self._connected = False
            self._token = None
            
            # Use the previously discovered address if available
            device_address = self._discovered_address or await self._discover_device()
            if not device_address:
                _LOGGER.error("Could not discover device for reconnection")
                return False
            
            # Store the discovered address for future reconnections
            self._discovered_address = device_address
            
            # Try to reconnect
            ha_device = self._lookup_ble_device(device_address)
            if ha_device is not None:
                _LOGGER.info("Reconnecting using Home Assistant BLE device: %s", device_address)
                bleak_client = await establish_connection(
                    BleakClient,
                    ha_device,
                    f"zeekr_charger_{self.serial}",
                    max_attempts=3,
                )
            else:
                _LOGGER.info("Reconnecting directly to BLE address: %s", device_address)
                bleak_client = await establish_connection(
                    BleakClient,
                    device_address,
                    f"zeekr_charger_{self.serial}",
                    max_attempts=3,
                )
            
            if not bleak_client or not bleak_client.is_connected:
                _LOGGER.error("Failed to establish BLE connection during reconnection")
                return False
            
            _LOGGER.info("BLE connection re-established")
            self._client = bleak_client
            
            # Try to maximize MTU
            try:
                if hasattr(self._client, 'exchange_mtu'):
                    mtu = await self._client.exchange_mtu(517)
                    _LOGGER.debug("Negotiated MTU: %d", mtu)
            except Exception as exc:
                _LOGGER.warning("MTU exchange failed during reconnection: %s", exc)
            
            # Re-enable notifications
            await self._enable_notifications()
            
            # Re-authenticate
            if await self._authenticate():
                self._connected = True
                _LOGGER.info("Reconnection and re-authentication successful")
                return True
            else:
                _LOGGER.error("Re-authentication failed during reconnection")
                return False
                
        except Exception as exc:
            _LOGGER.error("Reconnection attempt failed: %s", exc)
            return False

    def _lookup_ble_device(self, device_address: str) -> Optional[BLEDevice]:
        """Return a BLEDevice for the given address if Home Assistant has one cached."""
        try:
            candidate = bluetooth.async_ble_device_from_address(self.hass, device_address)
        except Exception as exc:
            _LOGGER.debug("BLE device lookup failed for %s: %s", device_address, exc)
            return None

        if candidate is None:
            return None

        if isinstance(candidate, BLEDevice):
            return candidate

        device_attr = getattr(candidate, "device", None)
        if isinstance(device_attr, BLEDevice):
            return device_attr

        # Home Assistant returned something else (often a plain address string). Fallback.
        _LOGGER.debug(
            "BLE lookup returned unsupported type %s for %s; falling back to address",
            type(candidate).__name__,
            device_address,
        )
        return None

    async def _enable_notifications(self) -> None:
        """Enable notifications on all relevant characteristics."""
        characteristics = [GATT_CHAR_NOTIFY, GATT_CHAR_NOTIFY2]
        
        for char_uuid in characteristics:
            try:
                await self._client.start_notify(char_uuid, self._notification_handler)
                _LOGGER.debug("Enabled notifications on %s", char_uuid)
            except Exception as exc:
                _LOGGER.warning("Could not enable notify on %s: %s", char_uuid, exc)

    def _notification_handler(self, sender: int, data: bytearray) -> None:
        """Handle incoming notifications."""
        log_hex_rx(bytes(data))
        
        # Reassemble frames
        for frame in self._reassemble_frames(sender, bytes(data)):
            if VERBOSE_LOGGING:
                _LOGGER.debug("RX COMPLETE FRAME: %s", frame.hex().upper())
            self._process_frame(frame)

    def _reassemble_frames(self, sender: int, chunk: bytes) -> list[bytes]:
        """Reassemble complete frames from notification chunks."""
        buf = self._frame_buffer.setdefault(sender, bytearray())
        frames = []

        # Frames start with 0xAA; start a new buffer whenever we see that prefix
        if chunk.startswith(b"\xAA"):
            if buf:
                frames.append(bytes(buf))
                buf.clear()
        
        buf.extend(chunk)

        # FIXED: Improved frame reassembly logic matching working examples
        # Try to parse the current buffer as a complete frame
        try:
            candidate = parse_frame(bytes(buf))
            # If parsing succeeds, we have a complete frame
            frames.append(bytes(buf))
            buf.clear()
        except Exception:
            # Frame not complete yet, keep accumulating
            # For very long frames (like 0xC1 JSON responses), we need to wait
            # until we have enough data to parse the header and get the full payload
            # But don't accumulate indefinitely - limit buffer size
            if len(buf) > 1024:  # Reasonable limit for frame size
                _LOGGER.warning("Frame buffer too large, clearing: %d bytes", len(buf))
                buf.clear()

        return frames

    def _process_frame(self, frame_data: bytes) -> None:
        """Process a complete frame."""
        try:
            pf = parse_frame(frame_data)
            if VERBOSE_LOGGING:
                _LOGGER.info("=== PARSED FRAME ===")
                _LOGGER.info("Opcode: 0x%02X", pf.opcode)
                _LOGGER.debug("Token: %s", pf.token.hex().upper())
                _LOGGER.debug("Payload length: %d", len(pf.payload))
                _LOGGER.debug("Payload: %s", pf.payload.hex().upper())
                _LOGGER.debug("Tail: %s", pf.tail.hex().upper() if pf.tail else "None")
                _LOGGER.info("Status: 0x%02X", pf.status)
                _LOGGER.info("===================")

            # Handle authentication response
            if pf.opcode == 0xFE and pf.status == 0 and not self._token:
                self._token = extract_token_from_response(pf)
                if self._token:
                    log_connection("Authentication successful")
                    # Resolve any pending authentication
                    for future in self._pending_responses.values():
                        if not future.done():
                            future.set_result(self._token)

            # Handle heartbeat responses (0xB5) - track charging sessions
            if pf.opcode == 0xB5:
                self._heartbeat_count += 1
                if VERBOSE_LOGGING:
                    _LOGGER.info("Heartbeat #%d: payload=%s, tail=%s", self._heartbeat_count, pf.payload.hex(), pf.tail.hex() if pf.tail else "None")
                
                # Parse heartbeat state with timestamp tracking
                # The tail byte is frame-level metadata (ack/status), not part of heartbeat payload
                self._last_heartbeat_state = parse_heartbeat_state(pf.payload, self._last_heartbeat_time)
                self._last_heartbeat_time = self._last_heartbeat_state.timestamp
                
                
                # Track charging session state changes
                if self._last_heartbeat_state.charging and self._charging_session_start is None:
                    self._charging_session_start = self._last_heartbeat_state.timestamp
                    self._session_energy_offset_kwh = None
                    log_status("Charging session started")
                elif not self._last_heartbeat_state.charging and self._charging_session_start is not None:
                    session_duration = self._last_heartbeat_state.timestamp - self._charging_session_start
                    log_status(f"Charging session ended after {session_duration:.1f} seconds")
                    self._charging_session_start = None
                    self._session_energy_offset_kwh = None
                
                if VERBOSE_LOGGING:
                    _LOGGER.debug("Heartbeat state: %s (%.1fs ago, count=%d)", 
                           self._last_heartbeat_state, self._last_heartbeat_state.seconds_ago, self._heartbeat_count)
                
                # Check if this is a 21-byte telemetry frame
                if len(pf.payload) == 21:
                    telemetry = parse_b5_telemetry(pf.payload)
                    if telemetry:
                        self._last_telemetry = telemetry
                        if self._last_heartbeat_state.charging and self._session_energy_offset_kwh is None:
                            self._session_energy_offset_kwh = telemetry.session_energy_kwh
                        _LOGGER.debug("Telemetry received: session=%.2f kWh, lifetime=%.2f kWh, voltage=%.1f V, current=%.1f A", 
                                    telemetry.session_energy_kwh, telemetry.lifetime_energy_kwh, 
                                    telemetry.voltage_v, telemetry.current_a)
                
                if VERBOSE_LOGGING:
                    _LOGGER.debug("Received heartbeat response, state: %s", self._last_heartbeat_state)

            # Handle potential 0x8E opcode responses (unknown heartbeat type)
            elif pf.opcode == 0x8E:
                _LOGGER.warning("Received unexpected 0x8E opcode response (unknown heartbeat?): payload=%s, tail=%s", 
                               pf.payload.hex(), pf.tail.hex() if pf.tail else "None")
                _LOGGER.warning("0x8E response details: status=0x%02X, token=%s", 
                               pf.status, pf.token.hex())
                # Try to parse as heartbeat state for comparison
                try:
                    unknown_heartbeat_state = parse_heartbeat_state(pf.payload, self._last_heartbeat_time)
                    _LOGGER.warning("0x8E parsed as heartbeat state: %s", unknown_heartbeat_state)
                except Exception as e:
                    _LOGGER.warning("Failed to parse 0x8E as heartbeat state: %s", e)

            # Handle 0xE0 power status responses (like auth demo)
            elif pf.opcode == 0xE0:
                if VERBOSE_LOGGING:
                    _LOGGER.info("Processing 0xE0 power status response (like auth demo)")
                result = parse_power_status(pf.payload, pf.tail)
                self._last_power_status = result
                if VERBOSE_LOGGING:
                    _LOGGER.info("Stored power status: %s", result)
            
            # Handle other responses
            elif pf.opcode in self._pending_responses:
                if VERBOSE_LOGGING:
                    _LOGGER.info("Matched response for opcode 0x%02X", pf.opcode)
                future = self._pending_responses.pop(pf.opcode)
                if not future.done():
                    # For opcodes that need payload+tail (tail contains important data like closing JSON brace)
                    # C1-C9 are configuration JSON queries, E0 and A9 use tail for additional data
                    if pf.opcode in [0xE0, 0xA9, 0xC1, 0xC2, 0xC4, 0xC5, 0xC7, 0xC9]:
                        if VERBOSE_LOGGING:
                            _LOGGER.debug("Response for opcode 0x%02X: payload=%s, tail=%s", pf.opcode, pf.payload.hex(), pf.tail.hex() if pf.tail else "None")
                        future.set_result((pf.payload, pf.tail))
                    else:
                        if VERBOSE_LOGGING:
                            _LOGGER.debug("Response for opcode 0x%02X: payload=%s", pf.opcode, pf.payload.hex())
                        future.set_result(pf.payload)
            else:
                # Log unknown opcodes at warning level for better visibility
                _LOGGER.warning("Received unknown opcode 0x%02X (no pending response): payload=%s, tail=%s, status=0x%02X", 
                               pf.opcode, pf.payload.hex(), pf.tail.hex() if pf.tail else "None", pf.status)
                _LOGGER.debug("Unknown opcode 0x%02X details: token=%s, header=%s", 
                             pf.opcode, pf.token.hex(), pf.header.hex())

            # Call notification callbacks
            for callback in self._notification_callbacks:
                try:
                    callback(frame_data)
                except Exception as exc:
                    _LOGGER.warning("Notification callback error: %s", exc)

        except Exception as exc:
            _LOGGER.warning("Frame processing error: %s", exc)

    async def _authenticate(self) -> bool:
        """Authenticate with the charger."""
        try:
            # Build identity frame
            identity_frame = build_identity_frame(self.serial, self.station_id)
            
            # Send authentication request
            await self._send_frame(identity_frame)
            
            # Wait for authentication response (token will be set by notification handler)
            try:
                response = await asyncio.wait_for(
                    self._wait_for_response(0xFE), timeout=10.0
                )
                if response and self._token:
                    log_connection("Authentication successful")
                    
                    # Perform initial setup: time sync and heartbeat
                    await self._perform_initial_setup()
                    
                    return True
            except asyncio.TimeoutError:
                _LOGGER.error("Authentication timeout")
                return False

        except Exception as exc:
            _LOGGER.error("Authentication failed: %s", exc)
            return False

    async def _send_frame(self, frame: bytes) -> None:
        """Send a frame to the charger."""
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected to charger")
        
        log_hex_tx(frame)
        
        try:
            # Send in chunks
            chunk_size = 20
            for i in range(0, len(frame), chunk_size):
                chunk = frame[i : i + chunk_size]
                if VERBOSE_LOGGING:
                    _LOGGER.info("TX CHUNK %d: %s", i // chunk_size + 1, chunk.hex().upper())
                await self._client.write_gatt_char(GATT_CHAR_WNR, chunk, response=False)
                await asyncio.sleep(0.01)  # Small delay between chunks
        except Exception as exc:
            _LOGGER.error("Failed to send frame: %s", exc)
            # Mark connection as lost and trigger reconnection
            self._connected = False
            if self._should_reconnect:
                await self._trigger_reconnection()
            raise

    async def _wait_for_response(self, opcode: int, timeout: float = 5.0) -> bytes:
        """Wait for a response with the specified opcode."""
        future = asyncio.Future()
        self._pending_responses[opcode] = future
        
        if VERBOSE_LOGGING:
            _LOGGER.info("Waiting for response with opcode 0x%02X, timeout=%s", opcode, timeout)
        
        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            if VERBOSE_LOGGING:
                if isinstance(result, tuple):
                    _LOGGER.info("Received tuple response for opcode 0x%02X: payload=%s, tail=%s", opcode, result[0].hex(), result[1].hex())
                else:
                    _LOGGER.info("Received response for opcode 0x%02X: %s", opcode, result.hex() if result else "None")
            return result
        except asyncio.TimeoutError:
            _LOGGER.warning("Timeout waiting for response with opcode 0x%02X after %s seconds", opcode, timeout)
            return None
        finally:
            self._pending_responses.pop(opcode, None)

    # ============== Public API Methods ==============
    
    async def send_heartbeat(self) -> None:
        """Send a heartbeat to keep the session alive."""
        if self._token:
            frame = cmd_heartbeat(self._token)
            await self._send_frame(frame)
            _LOGGER.debug("Heartbeat sent")
        else:
            _LOGGER.warning("Cannot send heartbeat - no session token")

    async def query_power_status(self) -> Optional[PowerStatus]:
        """Query current power status - exactly like auth demo (fire and forget)."""
        if not self._token:
            _LOGGER.warning("Cannot query power status - no session token")
            return None
        
        try:
            # Exactly like auth demo: pack_frame_request(0xE0, token) and send
            if VERBOSE_LOGGING:
                _LOGGER.debug("Querying power status (like auth demo - fire and forget)...")
            frame = pack_frame_request(0xE0, self._token)
            if VERBOSE_LOGGING:
                _LOGGER.debug("Sending power status frame: %s", frame.hex())
            await self._send_frame(frame)
            
            # Wait like auth demo does (0.3 seconds) then return
            # The response will be processed by the notification handler
            await asyncio.sleep(0.3)
            if VERBOSE_LOGGING:
                _LOGGER.info("0xE0 query sent, response will be processed by notification handler")
            
            # Return None - the response is handled asynchronously by the notification handler
            # This matches the auth demo behavior
            return None
            
        except Exception as exc:
            _LOGGER.warning("Power status query failed: %s", exc)
            return None


    async def query_home_current_config(self) -> Optional[CurrentConfig]:
        """Query home current configuration using simple approach (like auth demo)."""
        if not self._token:
            _LOGGER.warning("Cannot query home current config - no session token")
            return None
        
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Querying home current config with simple approach...")
            
            # Try simple 0xA9 query first (like auth demo approach)
            frame = pack_frame_request(0xA9, self._token, b"")
            if VERBOSE_LOGGING:
                _LOGGER.debug("Sending home current config frame: %s", frame.hex())
                # Frame structure: SOF(1) + opcode(1) + header(5) + checksum(1) + token(8) + payload(variable)
                _LOGGER.debug("Home current config frame breakdown: SOF=%s, opcode=%s, header=%s, checksum=%s, token=%s, payload=%s", 
                            frame[:1].hex(), frame[1:2].hex(), frame[2:7].hex(), 
                            frame[7:8].hex(), frame[8:16].hex(), frame[16:].hex())
            await self._send_frame(frame)
            
            if VERBOSE_LOGGING:
                _LOGGER.debug("Waiting for home current config response...")
            response = await self._wait_for_response(0xA9, timeout=5.0)
            if VERBOSE_LOGGING:
                _LOGGER.info("Home current config response received: %s (type: %s)", response, type(response))
            if response:
                if isinstance(response, tuple):
                    payload, tail = response
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Home current config response received: payload=%s, tail=%s", payload.hex(), tail.hex())
                        _LOGGER.debug("Payload length: %d, Tail length: %d", len(payload), len(tail))
                    
                    # Parse the payload data like the dumper (0xA9 with 0xC0 selector)
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Parsing 0xA9 payload: length=%d, first_byte=0x%02X, payload=%s", 
                                   len(payload), payload[0] if len(payload) > 0 else 0, payload.hex())
                    if len(payload) >= 2 and payload[0] == 0xC0:
                        # Decode like zeekr_dumper_pro.py: grid_capacity_a = p[1]
                        _LOGGER.info("Taking 0xC0 parsing path")
                        grid_capacity_a = payload[1]
                        home_cfg_hex = payload.hex()
                        
                        configured_limit = tail[0] if tail else None
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Parsed home current config (0xA9): grid_capacity_a=%d, home_cfg_hex=%s, configured_limit=%s", 
                                        grid_capacity_a, home_cfg_hex, 
                                        f"{configured_limit}A" if configured_limit is not None else "None")
                        return CurrentConfig(
                            max_current_capacity_a=grid_capacity_a,
                            present_current_limit_a=configured_limit,
                            grid_capacity_a=grid_capacity_a,
                            home_cfg_hex=home_cfg_hex,
                        )
                    elif len(payload) >= 6:
                        # Handle direct format without 0xC0 selector: [grid_capacity][phase][earthing][solar_pv][solar_phase][extra]
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Taking direct format parsing path (no 0xC0 selector)")
                        grid_capacity_a = payload[0]  # First byte is grid capacity
                        grid_phase = payload[1]      # Second byte is grid phase
                        earthing_sys = payload[2]    # Third byte is earthing system
                        solar_pv = payload[3]        # Fourth byte is solar PV
                        solar_phase = payload[4]     # Fifth byte is solar phase
                        home_cfg_hex = payload.hex()
                        
                        configured_limit = tail[0] if tail else None
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Parsed home current config (direct format): grid_capacity=%d, grid_phase=%d, earthing_sys=%d, solar_pv=%d, solar_phase=%d, configured_limit=%s", 
                                    grid_capacity_a, grid_phase, earthing_sys, solar_pv, solar_phase,
                                    f"{configured_limit}A" if configured_limit is not None else "None")
                        return CurrentConfig(
                            max_current_capacity_a=grid_capacity_a,
                            present_current_limit_a=configured_limit,
                            grid_capacity_a=grid_capacity_a,
                            home_cfg_hex=home_cfg_hex,
                            grid_phase=grid_phase,
                            earthing_sys=earthing_sys,
                            solar_pv=solar_pv,
                            solar_phase=solar_phase,
                        )
                    elif len(payload) >= 2 and payload[0] == 0x8E:
                        # Handle 0x8E format (HA plugin specific): parse like Android app
                        # Skip status byte (0x8E), then parse 5 fields as per smali analysis
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Taking 0x8E parsing path")
                        if len(payload) >= 6:
                            grid_capacity_a = payload[1]  # gridCapacity
                            grid_phase = payload[2]      # gridPhase  
                            earthing_sys = payload[3]    # earthingSys
                            solar_pv = payload[4]        # solarPv
                            solar_phase = payload[5]     # solarPhase
                            home_cfg_hex = payload.hex()
                            
                            configured_limit = tail[0] if tail else None
                            _LOGGER.info("Parsed home current config (0xA9, 0x8E format): grid_capacity=%d, grid_phase=%d, earthing_sys=%d, solar_pv=%d, solar_phase=%d, configured_limit=%s", 
                                        grid_capacity_a, grid_phase, earthing_sys, solar_pv, solar_phase,
                                        f"{configured_limit}A" if configured_limit is not None else "None")
                            return CurrentConfig(
                                max_current_capacity_a=grid_capacity_a,
                                present_current_limit_a=configured_limit,
                                grid_capacity_a=grid_capacity_a,
                                home_cfg_hex=home_cfg_hex,
                                grid_phase=grid_phase,
                                earthing_sys=earthing_sys,
                                solar_pv=solar_pv,
                                solar_phase=solar_phase,
                            )
                        else:
                            # Fallback for shorter payloads
                            grid_capacity_a = payload[1]
                            home_cfg_hex = payload.hex()
                            configured_limit = tail[0] if tail else None
                            _LOGGER.info("Parsed home current config (0xA9, 0x8E format, short): grid_capacity=%d, configured_limit=%s", 
                                        grid_capacity_a, f"{configured_limit}A" if configured_limit is not None else "None")
                            return CurrentConfig(
                                max_current_capacity_a=grid_capacity_a,
                                present_current_limit_a=configured_limit,
                                grid_capacity_a=grid_capacity_a,
                                home_cfg_hex=home_cfg_hex,
                            )
                    elif len(payload) >= 6:
                        # Fallback to old parsing method for compatibility
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Taking fallback parsing path (old method)")
                        grid_capacity = (payload[0] << 8) | payload[1]
                        grid_phase = payload[2]
                        earthing = payload[3]
                        solar_pv = payload[4]
                        solar_phase = payload[5] if len(payload) > 5 else 0
                        
                        configured_limit = tail[0] if tail else None
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Parsed home current config (fallback): grid_capacity=%d, phase=%d, earthing=%d, solar_pv=%d, solar_phase=%d, configured_limit=%s", 
                                    grid_capacity, grid_phase, earthing, solar_pv, solar_phase, 
                                    f"{configured_limit}A" if configured_limit is not None else "None")
                        return CurrentConfig(
                            max_current_capacity_a=grid_capacity,
                            present_current_limit_a=configured_limit,
                        )
                    else:
                        _LOGGER.warning("Home current config payload too short: %s (expected >= 6 bytes)", payload.hex())
                        _LOGGER.warning("No parsing path matched - returning empty CurrentConfig")
                        return CurrentConfig()
                else:
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Home current config response received: %s", response.hex())
                    
                    # Parse the response data like the dumper (0xA9 with 0xC0 selector)
                    if len(response) >= 2 and response[0] == 0xC0:
                        # Decode like zeekr_dumper_pro.py: grid_capacity_a = p[1]
                        grid_capacity_a = response[1]
                        home_cfg_hex = response.hex()
                        
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Parsed home current config (0xA9): grid_capacity_a=%d, home_cfg_hex=%s", 
                                       grid_capacity_a, home_cfg_hex)
                        return CurrentConfig(
                            max_current_capacity_a=grid_capacity_a,
                            present_current_limit_a=None,
                            grid_capacity_a=grid_capacity_a,
                            home_cfg_hex=home_cfg_hex,
                        )
                    elif len(response) >= 2 and response[0] == 0x8E:
                        # Handle 0x8E format (HA plugin specific): parse like Android app
                        if len(response) >= 6:
                            grid_capacity_a = response[1]  # gridCapacity
                            grid_phase = response[2]      # gridPhase  
                            earthing_sys = response[3]    # earthingSys
                            solar_pv = response[4]        # solarPv
                            solar_phase = response[5]     # solarPhase
                            home_cfg_hex = response.hex()
                            
                            if VERBOSE_LOGGING:
                                _LOGGER.info("Parsed home current config (0xA9, 0x8E format): grid_capacity=%d, grid_phase=%d, earthing_sys=%d, solar_pv=%d, solar_phase=%d", 
                                       grid_capacity_a, grid_phase, earthing_sys, solar_pv, solar_phase)
                            return CurrentConfig(
                                max_current_capacity_a=grid_capacity_a,
                                present_current_limit_a=None,
                                grid_capacity_a=grid_capacity_a,
                                home_cfg_hex=home_cfg_hex,
                                grid_phase=grid_phase,
                                earthing_sys=earthing_sys,
                                solar_pv=solar_pv,
                                solar_phase=solar_phase,
                            )
                        else:
                            # Fallback for shorter payloads
                            grid_capacity_a = response[1]
                            home_cfg_hex = response.hex()
                            if VERBOSE_LOGGING:
                                _LOGGER.info("Parsed home current config (0xA9, 0x8E format, short): grid_capacity=%d", grid_capacity_a)
                            return CurrentConfig(
                                max_current_capacity_a=grid_capacity_a,
                                present_current_limit_a=None,
                                grid_capacity_a=grid_capacity_a,
                                home_cfg_hex=home_cfg_hex,
                            )
                    elif len(response) >= 6:
                        # Fallback to old parsing method for compatibility
                        grid_capacity = (response[0] << 8) | response[1]
                        grid_phase = response[2]
                        earthing = response[3]
                        solar_pv = response[4]
                        # response[5] might be solar_phase or other data
                        
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Parsed home current config (fallback): grid_capacity=%d, phase=%d, earthing=%d, solar_pv=%d", 
                                   grid_capacity, grid_phase, earthing, solar_pv)
                        return CurrentConfig(max_current_capacity_a=grid_capacity, present_current_limit_a=None)
                    else:
                        _LOGGER.warning("Home current config payload too short: %s (expected >= 2 bytes)", response.hex())
                        return CurrentConfig()
            else:
                _LOGGER.warning("No home current config response received (timeout or no response)")
                _LOGGER.warning("Response was: %s (type: %s)", response, type(response))
                return None
        except Exception as exc:
            _LOGGER.error("Home current config query failed: %s", exc)
            import traceback
            _LOGGER.error("Full traceback: %s", traceback.format_exc())
            return None

    async def query_charger_basic_info(self) -> Optional[dict[str, Any]]:
        """Query charger basic information (0xC1) with 1-byte 0x01 payload."""
        if not self._token:
            _LOGGER.warning("Cannot query charger basic info - no session token")
            return None
        
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Querying charger basic info (0xC1) with 0x01 payload...")
            
            # Send C1 query with 1-byte 0x01 payload (configuration read - Android app style)
            frame = pack_frame_request(0xC1, self._token, b"\x01")
            await self._send_frame(frame)
            
            response = await self._wait_for_response(0xC1, timeout=5.0)
            if VERBOSE_LOGGING:
                _LOGGER.info("Basic info query response: %s", response)
            if response:
                # Response is a tuple (payload, tail)
                if isinstance(response, tuple):
                    payload, tail = response
                    # Combine payload and tail for complete JSON
                    full_response = payload + (tail if tail else b"")
                else:
                    full_response = response
                
                if VERBOSE_LOGGING:
                    _LOGGER.info("Charger basic info response received: %d bytes", len(full_response))
                
                # Response format: First 1-2 bytes are status/type, then JSON
                try:
                    # Try to find JSON start by looking for '{' character
                    json_start = -1
                    for i, byte in enumerate(full_response):
                        if byte == ord('{'):
                            json_start = i
                            break
                    
                    if json_start == -1:
                        _LOGGER.warning("No JSON start found in basic info response: %s", full_response.hex())
                        return {"raw_hex": full_response.hex()}
                    
                    json_bytes = full_response[json_start:]
                    json_str = json_bytes.decode('utf-8')
                    import json
                    json_data = json.loads(json_str)
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Successfully parsed basic info JSON (started at byte %d): %s", json_start, json_data)
                    
                    # Convert from Android format [type_code, value] to just value
                    normalized = {}
                    for key, val in json_data.items():
                        if isinstance(val, list) and len(val) == 2:
                            # Extract value from [type_code, value] tuple
                            normalized[key] = val[1]
                        else:
                            normalized[key] = val
                    
                    # Map field names to match expected format (similar to zeekr_dumper_pro.py)
                    field_mappings = {
                        "rated_power": "rated_power_w",
                        "rate_charging_current": "rated_charging_current_a",
                        "number_of_socket_outlets": "num_socket_outlets",
                    }
                    
                    # Apply field mappings
                    mapped_data = {}
                    for key, value in normalized.items():
                        mapped_key = field_mappings.get(key, key)
                        mapped_data[mapped_key] = value
                    
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Basic info mapped data: %s", mapped_data)
                    return mapped_data
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    _LOGGER.warning("Failed to parse basic info as JSON: %s", e)
                    if VERBOSE_LOGGING:
                        _LOGGER.debug("Raw response: %s", full_response.hex())
                    return {"raw_hex": full_response.hex()}
            else:
                _LOGGER.warning("No charger basic info response received (response was None)")
        except Exception as exc:
            _LOGGER.warning("Charger basic info query failed: %s", exc)
        
        return None

    async def query_charger_protection_info(self) -> Optional[dict[str, Any]]:
        """Query charger protection information (0xC4) with 1-byte 0x01 payload."""
        return await self._query_config_json(0xC4, "protection info")
    
    
    async def query_charger_wifi_config(self) -> Optional[dict[str, Any]]:
        """Query charger WiFi configuration (0xC7) with 1-byte 0x01 payload."""
        return await self._query_config_json(0xC7, "wifi config")
    
    
    async def _query_config_json(self, opcode: int, description: str) -> Optional[dict[str, Any]]:
        """Generic method to query configuration JSON responses (C1-C9)."""
        if not self._token:
            _LOGGER.warning("Cannot query %s - no session token", description)
            return None
        
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Querying charger %s (0x%02X) with 0x01 payload...", description, opcode)
            
            # Send query with 1-byte 0x01 payload (configuration read - Android app style)
            frame = pack_frame_request(opcode, self._token, b"\x01")
            await self._send_frame(frame)
            
            response = await self._wait_for_response(opcode, timeout=5.0)
            if response:
                # Response is a tuple (payload, tail)
                if isinstance(response, tuple):
                    payload, tail = response
                    # Combine payload and tail for complete JSON
                    full_response = payload + (tail if tail else b"")
                else:
                    full_response = response
                
                if VERBOSE_LOGGING:
                    _LOGGER.debug("Charger %s response received: %d bytes", description, len(full_response))
                
                # Response format: First 1-2 bytes are status/type, then JSON
                try:
                    # Try to find JSON start by looking for '{' character
                    json_start = -1
                    for i, byte in enumerate(full_response):
                        if byte == ord('{'):
                            json_start = i
                            break
                    
                    if json_start == -1:
                        _LOGGER.warning("No JSON start found in %s response: %s", description, full_response.hex())
                        return {"raw_hex": full_response.hex()}
                    
                    json_bytes = full_response[json_start:]
                    json_str = json_bytes.decode('utf-8')
                    import json
                    json_data = json.loads(json_str)
                    _LOGGER.debug("Successfully parsed %s JSON (started at byte %d)", description, json_start)
                    
                    # Convert from Android format [type_code, value] to just value
                    normalized = {}
                    for key, val in json_data.items():
                        if isinstance(val, list) and len(val) == 2:
                            # Extract value from [type_code, value] tuple
                            normalized[key] = val[1]
                        else:
                            normalized[key] = val
                    
                    # Map field names to match expected format (similar to zeekr_dumper_pro.py)
                    field_mappings = {}
                    if opcode == 0xC1:  # Basic info
                        field_mappings = {
                            "rated_power": "rated_power_w",
                            "rate_charging_current": "rated_charging_current_a",
                            "number_of_socket_outlets": "num_socket_outlets",
                        }
                    elif opcode == 0xC2:  # Employ info
                        field_mappings = {
                            "rate_charging_current": "rated_charging_current_a",
                            "number_of_socket_outlets": "num_socket_outlets",
                        }
                    elif opcode == 0xC4:  # Protection info
                        # No field mappings needed for protection info
                        pass
                    elif opcode == 0xC5:  # Socket config
                        field_mappings = {
                            "server_a_ip_address": "server_a_ip_address",
                            "server_a_port": "server_a_port",
                            "server_a_protocol": "server_a_protocol",
                            "protocol_a_version": "protocol_a_version",
                        }
                    elif opcode == 0xC7:  # WiFi config
                        field_mappings = {
                            "wifi_function_enable": "wifi_function_enable",
                            "wifi_mac_address": "wifi_mac_address",
                            "wifi_module_firmware_version": "wifi_module_firmware_version",
                        }
                    
                    # Apply field mappings
                    mapped_data = {}
                    for key, value in normalized.items():
                        mapped_key = field_mappings.get(key, key)
                        mapped_data[mapped_key] = value
                    
                    return mapped_data
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    _LOGGER.warning("Failed to parse %s as JSON: %s", description, e)
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Raw response: %s", full_response.hex())
                        _LOGGER.info("Raw response as string: %s", full_response.decode('utf-8', errors='ignore'))
                    return {"raw_hex": full_response.hex()}
            else:
                _LOGGER.warning("No %s response received", description)
        except Exception as exc:
            _LOGGER.warning("%s query failed: %s", description, exc)
        
        return None

    async def query_wifi_config(self) -> Optional[dict[str, Any]]:
        """Query WiFi configuration (0xC7)."""
        return await self._query_config_json(0xC7, "WiFi config")

    async def query_wifi_status(self) -> Optional[dict[str, Any]]:
        """Query WiFi status (0xE4) - binary format, not JSON."""
        if not self._token:
            _LOGGER.warning("Cannot query WiFi status - no session token")
            return None
        
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Querying WiFi status (0xE4)...")
            
            # Send query with 1-byte 0x01 payload
            frame = pack_frame_request(0xE4, self._token, b"\x01")
            await self._send_frame(frame)
            
            response = await self._wait_for_response(0xE4, timeout=5.0)
            if response:
                # Response is a tuple (payload, tail)
                if isinstance(response, tuple):
                    payload, tail = response
                    full_response = payload + (tail if tail else b"")
                else:
                    full_response = response
                
                if VERBOSE_LOGGING:
                    _LOGGER.info("WiFi status response received: %d bytes", len(full_response))
                    _LOGGER.info("WiFi status raw response: %s", full_response.hex())
                    _LOGGER.info("WiFi status response bytes: %s", [hex(b) for b in full_response])
                
                # Log the decoded content for debugging
                if len(full_response) > 2:
                    try:
                        decoded_content = full_response[2:].decode('utf-8', errors='ignore')
                        if VERBOSE_LOGGING:
                            _LOGGER.info("WiFi status decoded content: %s", repr(decoded_content))
                    except Exception:
                        pass
                
                # Parse 0xE4 response like the dumper does
                # Structure: [response_type][format][ssid_data][newline][password_data]
                # Example: C0 02 68 61 0A 77 75 74 61 6E 67 6C 61 6E
                #          C0=response_type, 02=format, 68 61="ha", 0A=newline, 77 75...="wutanglan"
                result = {}
                if len(full_response) >= 2:
                    result["wifi_flag_hex"] = full_response[:2].hex()
                    if len(full_response) > 2:
                        result["wifi_extra_hex"] = full_response[2:].hex()
                    
                    # Map WiFi status codes to English descriptions
                    wifi_status_codes = {
                        0: "WiFi hardware switch not opened, startup failed",
                        1: "WiFi module not supported, WiFi startup failed", 
                        2: "WiFi module not found",
                        3: "Invalid password, startup failed",
                        4: "Invalid SSID, startup failed",
                        5: "Unknown WiFi error, startup failed",
                        6: "IP setting failed",
                        7: "DHCP startup failed, WiFi startup failed",
                        8: "Server problem",
                        9: "Client problem"
                    }
                    
                    # The first byte (0x8E/0xC0) is a response type identifier
                    # The second byte (0x02) indicates successful data format
                    # For now, we'll interpret 0x02 as "successful" since it contains SSID/password
                    first_byte = full_response[0]
                    second_byte = full_response[1] if len(full_response) > 1 else 0
                    
                    if VERBOSE_LOGGING:
                        _LOGGER.info("WiFi status parsing: first_byte=0x%02X, second_byte=0x%02X", first_byte, second_byte)
                    
                    result["wifi_response_type"] = f"0x{first_byte:02X}"
                    result["wifi_data_format"] = second_byte
                    
                    # If we have SSID/password data, consider it successful
                    # Accept 0x01, 0x02, and 0x68 as valid format indicators
                    # 0x68 appears to be a newer firmware format
                    if second_byte in (0x01, 0x02, 0x68):
                        result["wifi_status"] = "Connected"
                        result["wifi_status_code"] = 0  # Success
                    else:
                        result["wifi_status"] = f"Unknown data format: 0x{second_byte:02X} (expected 0x01, 0x02, or 0x68)"
                        result["wifi_status_code"] = second_byte
                        _LOGGER.warning("WiFi status received unknown data format: 0x%02X (response: %s)", 
                                       second_byte, full_response.hex())
                
                # Parse SSID and password if present
                # Handle C0 02, 8E 02, and 0x68 formats
                if VERBOSE_LOGGING:
                    _LOGGER.info("WiFi status parsing: full_response=%s, length=%d", full_response.hex(), len(full_response))
                if len(full_response) >= 2:
                    if VERBOSE_LOGGING:
                        _LOGGER.info("WiFi status: first_byte=0x%02X, second_byte=0x%02X", full_response[0], full_response[1])
                    body = full_response[1:]
                    try:
                        s = body.decode('utf-8', errors='ignore')
                        if VERBOSE_LOGGING:
                            _LOGGER.info("WiFi status: decoded body as UTF-8: '%s'", s)
                            _LOGGER.info("WiFi status: decoded body length: %d", len(s))
                        if '\n' in s:
                            ssid, pwd = s.split('\n', 1)
                            # Clean up the password (remove control characters)
                            pwd = pwd.rstrip('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')
                            if VERBOSE_LOGGING:
                                _LOGGER.info("WiFi status: split result - ssid='%s', password='%s'", ssid, pwd)
                            # Only set SSID if we haven't already set it with the corrected value
                            if "ssid" not in result and ssid:
                                result["ssid"] = ssid
                            # Only set password if we haven't already set it with the corrected value
                            if "password" not in result and pwd:
                                result["password"] = pwd
                        else:
                            if s:
                                result["ssid_or_value"] = s
                    except Exception as e:
                        _LOGGER.warning("Failed to parse WiFi status ASCII: %s", e)
                else:
                    _LOGGER.warning("WiFi status: second byte 0x%02X not in expected formats (0x01, 0x02, 0x68)", 
                                   full_response[1] if len(full_response) >= 2 else 0)
                
                if VERBOSE_LOGGING:
                    _LOGGER.info("Parsed WiFi status: %s", result)
                return result
            else:
                _LOGGER.warning("No WiFi status response received")
        except Exception as exc:
            _LOGGER.error("WiFi status query failed: %s", exc)
        
        return None

    async def query_network_status(self) -> Optional[dict[str, Any]]:
        """Query network status (0xD3) - CheckNetworkStatusResponse with error codes."""
        if not self._token:
            _LOGGER.warning("Cannot query network status - no session token")
            return None
        
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Querying network status (0xD3)...")
            
            # Send query with 1-byte 0x01 payload
            frame = pack_frame_request(0xD3, self._token, b"\x01")
            await self._send_frame(frame)
            
            response = await self._wait_for_response(0xD3, timeout=5.0)
            if response:
                # Response is a tuple (payload, tail)
                if isinstance(response, tuple):
                    payload, tail = response
                    full_response = payload + (tail if tail else b"")
                else:
                    full_response = response
                
                if VERBOSE_LOGGING:
                    _LOGGER.info("Network status response received: %d bytes", len(full_response))
                    _LOGGER.info("Network status raw response: %s", full_response.hex())
                
                # Parse 0xD3 response based on CheckNetworkStatusResponse.smali
                result = {}
                if len(full_response) >= 2:
                    # First 2 bytes: network result
                    result["network_result"] = int.from_bytes(full_response[0:2], "little")
                
                if len(full_response) >= 4:
                    # Next 2 bytes: networking mode
                    result["networking_mode"] = int.from_bytes(full_response[2:4], "little")
                
                if len(full_response) >= 8:
                    # Next 4 bytes: result detail (the error code we want)
                    result["result_detail"] = int.from_bytes(full_response[4:8], "little")
                    
                    # Map error codes to descriptions based on smali analysis
                    error_descriptions = {
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
                        0x1003: "WiFi Hardware Switch Not On, Startup Failed",
                    }
                    
                    result["result_detail_desc"] = error_descriptions.get(
                        result["result_detail"], 
                        f"Unknown Error (0x{result['result_detail']:04X})"
                    )
                
                if VERBOSE_LOGGING:
                    _LOGGER.info("Parsed network status: %s", result)
                return result
            else:
                _LOGGER.warning("No network status response received")
        except Exception as exc:
            _LOGGER.error("Network status query failed: %s", exc)
        
        return None


    async def _perform_initial_setup(self) -> None:
        """Perform initial setup after authentication (exactly like auth demo)."""
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Performing initial setup following auth demo sequence...")
                _LOGGER.info("Sending time sync...")
            
            # Send time sync first (like auth demo) - it's important for session validity
            time_sync_success = await self.sync_time()
            if not time_sync_success:
                _LOGGER.warning("Time sync failed - this may cause subsequent commands to fail")
            
            # Wait a little for the acknowledgement to arrive before heartbeats (like auth demo)
            if VERBOSE_LOGGING:
                _LOGGER.info("Waiting for time sync acknowledgement...")
            await asyncio.sleep(1.0)
            
            # Send heartbeat (like auth demo) - don't wait for response
            if VERBOSE_LOGGING:
                _LOGGER.info("Sending heartbeat...")
            heartbeat_frame = cmd_heartbeat(self._token)
            await self._send_frame(heartbeat_frame)
            if VERBOSE_LOGGING:
                _LOGGER.info("Heartbeat sent")
            await asyncio.sleep(0.5)
            
            _LOGGER.info("Initial setup completed")
        except Exception as exc:
            _LOGGER.warning("Initial setup failed: %s", exc)

    async def authorize_charge(self) -> bool:
        """Authorize a charge session (0xB4)."""
        if not self._token:
            _LOGGER.warning("Cannot authorize charge - no session token")
            return False
        
        try:
            _LOGGER.info("Authorizing charge session...")
            frame = cmd_auth_charge(self._token)
            if VERBOSE_LOGGING:
                _LOGGER.info("Sending authorize charge frame: %s", frame.hex())
            await self._send_frame(frame)
            
            _LOGGER.info("Waiting for authorize charge response...")
            response = await self._wait_for_response(0xB4, timeout=5.0)
            if response:
                if VERBOSE_LOGGING:
                    _LOGGER.info("Charge authorization response received: %s", response.hex())
                return True
            else:
                _LOGGER.warning("No charge authorization response received")
                return False
        except Exception as exc:
            _LOGGER.warning("Charge authorization failed: %s", exc)
            return False

    async def stop_charge(self) -> bool:
        """Stop charging session (0xB6)."""
        if not self._token:
            _LOGGER.warning("Cannot stop charge - no session token")
            return False
        
        try:
            _LOGGER.info("Stopping charge session...")
            frame = cmd_stop_charge(self._token)
            if VERBOSE_LOGGING:
                _LOGGER.info("Sending stop charge frame: %s", frame.hex())
            await self._send_frame(frame)
            
            _LOGGER.info("Waiting for stop charge response...")
            response = await self._wait_for_response(0xB6, timeout=5.0)
            if response:
                if VERBOSE_LOGGING:
                    _LOGGER.info("Stop charge response received: %s", response.hex())
                return True
            else:
                _LOGGER.warning("No stop charge response received")
                return False
        except Exception as exc:
            _LOGGER.warning("Stop charge failed: %s", exc)
            return False


    async def set_charge_model(self, mode: int) -> bool:
        """Set charge model (0xB3): 0x00 = auto, 0x01 = authorized."""
        if not self._token:
            _LOGGER.warning("Cannot set charge model - no session token")
            return False
        
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Setting charge model to %s", "auto" if mode == 0x00 else "authorized")
            frame = pack_frame_request(0xB3, self._token, bytes([mode]))
            if VERBOSE_LOGGING:
                _LOGGER.info("Sending charge model frame: %s", frame.hex())
            await self._send_frame(frame)
            
            if VERBOSE_LOGGING:
                _LOGGER.info("Waiting for charge model response...")
            response = await self._wait_for_response(0xB3, timeout=5.0)
            if response:
                if VERBOSE_LOGGING:
                    _LOGGER.info("Charge model response received: %s", response.hex())
                return True
            else:
                _LOGGER.warning("No charge model response received")
                return False
        except Exception as exc:
            _LOGGER.warning("Set charge model failed: %s", exc)
            return False

    async def query_charge_mode(self) -> Optional[int]:
        """Query current charge mode (0xE6): returns 0x00 = auto, 0x01 = authorized."""
        if not self._token:
            _LOGGER.warning("Cannot query charge mode - no session token")
            return None
        
        try:
            if VERBOSE_LOGGING:
                _LOGGER.info("Querying charge mode (0xE6)...")
            frame = pack_frame_request(0xE6, self._token, b"")
            if VERBOSE_LOGGING:
                _LOGGER.info("Sending charge mode query frame: %s", frame.hex())
            await self._send_frame(frame)
            
            if VERBOSE_LOGGING:
                _LOGGER.info("Waiting for charge mode query response...")
            response = await self._wait_for_response(0xE6, timeout=5.0)
            if response:
                if VERBOSE_LOGGING:
                    _LOGGER.info("Charge mode query response received: %s (length: %d)", response.hex(), len(response))
                # Parse the response - handle optional selector byte 0x26 like other queries
                if len(response) >= 1:
                    # Check for optional selector byte 0x26 (like in zeekr_dumper_pro.py)
                    if response[0] == 0x26 and len(response) >= 2:
                        mode = response[1]
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Found selector byte 0x26, using second byte as mode: 0x%02X", mode)
                    else:
                        mode = response[0]
                        if VERBOSE_LOGGING:
                            _LOGGER.info("Using first byte as mode: 0x%02X", mode)
                    
                    # Log all bytes for debugging
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Full response bytes: %s", [hex(b) for b in response])
                    
                    mode_name = self._get_charge_mode_name(mode)
                    if VERBOSE_LOGGING:
                        _LOGGER.info("Current charge mode: 0x%02X (%s)", mode, mode_name)
                    return mode
                else:
                    _LOGGER.warning("Charge mode response too short: %s", response.hex())
                    return None
            else:
                _LOGGER.warning("No charge mode query response received")
                return None
        except Exception as exc:
            _LOGGER.warning("Query charge mode failed: %s", exc)
            return None

    def _get_charge_mode_name(self, mode: int) -> str:
        """Get human-readable name for charge mode value."""
        mode_map = {
            0x00: "Plug & Charge (Auto)",
            0x01: "Auth (Requires Auth)", 
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





    async def sync_time(self) -> bool:
        """Sync time with charger (0xB0)."""
        if not self._token:
            _LOGGER.warning("Cannot sync time - no session token")
            return False
        
        try:
            import time
            _LOGGER.info("Syncing time with charger...")
            
            # Use the same timezone calculation as the auth demo
            tz_minutes = -time.timezone // 60  # Calculate like auth demo
            if VERBOSE_LOGGING:
                _LOGGER.info("Timezone offset minutes: %d (calculated like auth demo)", tz_minutes)
            
            # Use current time 
            epoch = int(time.time())
            if VERBOSE_LOGGING:
                _LOGGER.info("Epoch time: %d (current time like auth demo)", epoch)
                _LOGGER.info("Epoch hex: %08x", epoch)
                _LOGGER.info("Tz_minutes hex: %04x", tz_minutes)
            
            # Use the epoch parameter 
            frame = cmd_sync_time(self._token, tz_minutes=tz_minutes)
            if VERBOSE_LOGGING:
                _LOGGER.info("Sending time sync frame: %s", frame.hex())
                # Frame structure: SOF(1) + opcode(1) + header(5) + checksum(1) + token(8) + payload(variable)
                _LOGGER.info("Time sync frame breakdown: SOF=%s, opcode=%s, header=%s, checksum=%s, token=%s, payload=%s", 
                            frame[:1].hex(), frame[1:2].hex(), frame[2:7].hex(), 
                            frame[7:8].hex(), frame[8:16].hex(), frame[16:].hex())
            await self._send_frame(frame)
            
            if VERBOSE_LOGGING:
                _LOGGER.info("Waiting for time sync response...")
            response = await self._wait_for_response(0xB0, timeout=5.0)
            if response:
                if VERBOSE_LOGGING:
                    _LOGGER.info("Time sync response received: %s", response.hex())
                _LOGGER.info("Time sync completed successfully")
                return True  # Time sync response received successfully
            else:
                _LOGGER.warning("No time sync response received")
                return False
        except Exception as exc:
            _LOGGER.warning("Time sync failed: %s", exc)
            return False

    async def set_current_limit(self, port: int, amps: int) -> bool:
        """Set current limit for a port."""
        if not self._token:
            return False
        
        try:
            frame = cmd_set_current_limit(self._token, port, amps)
            await self._send_frame(frame)
            return True
        except Exception as exc:
            _LOGGER.warning("Set current limit failed: %s", exc)
            return False



    def get_car_connection_state(self) -> HeartbeatState:
        """Get the last known car connection state from heartbeat data."""
        return self._last_heartbeat_state


    def get_last_telemetry(self) -> Optional[B5Telemetry]:
        """Get the last received telemetry data."""
        return self._last_telemetry

    def get_session_energy_offset(self) -> Optional[float]:
        """Return the baseline session energy captured at session start."""
        return self._session_energy_offset_kwh

    def get_last_power_status(self) -> Optional[PowerStatus]:
        """Get the last received power status data."""
        return self._last_power_status
    
    
    def get_heartbeat_stats(self) -> dict[str, Any]:
        """Get comprehensive heartbeat statistics for charging session tracking."""
        import time
        current_time = time.time()
        
        stats = {
            "total_heartbeats": self._heartbeat_count,
            "last_heartbeat_time": self._last_heartbeat_time,
            "seconds_since_last_heartbeat": current_time - self._last_heartbeat_time if self._last_heartbeat_time > 0 else 0,
            "charging_session_active": self._charging_session_start is not None,
            "charging_session_start": self._charging_session_start,
            "charging_session_duration": (current_time - self._charging_session_start) if self._charging_session_start else 0,
            "last_heartbeat_state": self._last_heartbeat_state.__dict__,
        }
        
        return stats


    @property
    def is_connected(self) -> bool:
        """Return connection status."""
        return self._connected and self._client and self._client.is_connected

    @property
    def session_token(self) -> Optional[bytes]:
        """Return the current session token."""
        return self._token

    def get_connection_status(self) -> dict[str, Any]:
        """Get detailed connection status information."""
        return {
            "connected": self.is_connected,
            "should_reconnect": self._should_reconnect,
            "reconnect_attempts": self._reconnect_attempts,
            "max_reconnect_attempts": self._max_reconnect_attempts,
            "discovered_address": self._discovered_address,
            "has_token": self._token is not None,
            "last_heartbeat_time": self._last_heartbeat_time,
            "heartbeat_count": self._heartbeat_count,
        }

    async def force_reconnect(self) -> bool:
        """Force an immediate reconnection attempt."""
        _LOGGER.info("Force reconnection requested")
        self._reconnect_attempts = 0  # Reset attempts for forced reconnection
        return await self._attempt_reconnection()

    def set_reconnection_config(self, max_attempts: int = None, initial_delay: float = None, max_delay: float = None) -> None:
        """Configure reconnection behavior."""
        if max_attempts is not None:
            self._max_reconnect_attempts = max_attempts
        if initial_delay is not None:
            self._reconnect_delay = initial_delay
        if max_delay is not None:
            self._max_reconnect_delay = max_delay
        _LOGGER.info("Reconnection config updated: max_attempts=%d, initial_delay=%.1f, max_delay=%.1f", 
                    self._max_reconnect_attempts, self._reconnect_delay, self._max_reconnect_delay)
