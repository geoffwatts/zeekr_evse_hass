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
    parse_config_json,
    parse_home_current_config,
    parse_network_status,
    parse_wifi_status,
    parse_power_status,
    parse_tlv_response,
    parse_b5_telemetry,
    pack_frame_request,
    TELEMETRY_LENGTHS,
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
        self._last_telemetry_time: Optional[float] = None  # time.monotonic() of the last telemetry frame
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

    async def _open_session(self, device_address: str) -> bool:
        """Connect over BLE, enable notifications and authenticate.

        Shared by the initial connect and by reconnection. On failure the BLE
        link is left for the caller to clean up.
        """
        # Prefer the BLEDevice from HA's BLE stack (works through ESPHome proxies)
        target = self._lookup_ble_device(device_address) or device_address
        bleak_client = await establish_connection(
            BleakClient,
            target,
            f"zeekr_charger_{self.serial}",
            max_attempts=3,
        )
        # establish_connection returns a connected client or raises
        if not bleak_client or not bleak_client.is_connected:
            _LOGGER.error("Failed to connect to BLE device")
            return False

        log_connection(f"Connected to charger at {device_address}")
        self._client = bleak_client

        if hasattr(bleak_client, "exchange_mtu"):
            try:
                _LOGGER.debug("Negotiated MTU: %d", await bleak_client.exchange_mtu(517))
            except Exception as exc:
                _LOGGER.warning("MTU exchange failed: %s", exc)

        await self._enable_notifications()
        return await self._authenticate()

    async def async_connect(self) -> bool:
        """Connect to the charger."""
        try:
            device_address = await self._discover_device()
            if not device_address:
                _LOGGER.error("Could not discover Zeekr charger device")
                return False

            self._discovered_address = device_address  # Reused by reconnection

            if await self._open_session(device_address):
                self._connected = True
                await self._start_connection_monitor()
                return True

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

        while self._should_reconnect:
            try:
                self._reconnect_attempts += 1
                current_delay = min(
                    self._reconnect_delay * (2 ** (self._reconnect_attempts - 1)),
                    self._max_reconnect_delay,
                )

                if self._reconnect_attempts <= self._max_reconnect_attempts:
                    log_connection(
                        f"Retrying connection (attempt {self._reconnect_attempts}/{self._max_reconnect_attempts}) in {current_delay:.1f}s"
                    )
                else:
                    # After max attempts switch to fixed interval retries every 5 minutes
                    current_delay = max(current_delay, 300)
                    log_connection(
                        f"Max attempts reached; continuing retries every {current_delay:.0f}s"
                    )

                await asyncio.sleep(current_delay)

                if not self._should_reconnect:
                    break

                if await self._attempt_reconnection():
                    log_connection(
                        f"Reconnection successful after {self._reconnect_attempts} attempts"
                    )
                    self._reconnect_attempts = 0
                    return
                _LOGGER.warning("Reconnection attempt %d failed", self._reconnect_attempts)

            except asyncio.CancelledError:
                _LOGGER.info("Reconnection cancelled")
                break
            except Exception as exc:
                _LOGGER.error("Reconnection error: %s", exc)

        if not self._should_reconnect:
            _LOGGER.info("Reconnection stopped (should_reconnect=False)")

    async def _attempt_reconnection(self) -> bool:
        """Attempt to reconnect to the charger."""
        try:
            _LOGGER.info("Attempting to reconnect to charger...")

            # Drop the stale connection and session
            if self._client:
                try:
                    if self._client.is_connected:
                        await self._client.disconnect()
                except Exception:
                    pass
                self._client = None
            self._connected = False
            self._token = None

            device_address = self._discovered_address or await self._discover_device()
            if not device_address:
                _LOGGER.error("Could not discover device for reconnection")
                return False
            self._discovered_address = device_address

            if await self._open_session(device_address):
                self._connected = True
                _LOGGER.info("Reconnection and re-authentication successful")
                return True

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
                heartbeat_temperature = self._last_heartbeat_state.temperature_c
                
                
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
                
                # Check if this is a telemetry frame (21-byte Zeekr or 33-byte Raedian)
                if len(pf.payload) in TELEMETRY_LENGTHS:
                    telemetry = parse_b5_telemetry(pf.payload)
                    if telemetry:
                        if heartbeat_temperature is not None and telemetry.temperature_c is None:
                            telemetry.temperature_c = heartbeat_temperature
                        self._last_telemetry = telemetry
                        self._last_telemetry_time = time.monotonic()
                        # Raedian energy already counts from 0 per session, so an
                        # offset taken mid-session (e.g. after a reconnect) would be wrong
                        if (
                            telemetry.layout != "raedian33"
                            and self._last_heartbeat_state.charging
                            and self._session_energy_offset_kwh is None
                        ):
                            self._session_energy_offset_kwh = telemetry.session_energy_kwh
                        _LOGGER.debug(
                            "Telemetry received: session=%.2f kWh, voltage=%.1f V, current=%.1f A",
                            telemetry.session_energy_kwh,
                            telemetry.voltage_v,
                            telemetry.current_a,
                        )
                
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
                _LOGGER.error("Authentication failed: no token in response")
                return False
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
        """Query the installation config (0xA9): grid capacity, phase, earthing, solar."""
        if not self._token:
            _LOGGER.warning("Cannot query home current config - no session token")
            return None

        try:
            await self._send_frame(pack_frame_request(0xA9, self._token, b""))
            response = await self._wait_for_response(0xA9, timeout=5.0)
        except Exception as exc:
            _LOGGER.error("Home current config query failed: %s", exc)
            return None

        if not response:
            _LOGGER.warning("No home current config response received")
            return None

        # _process_frame resolves 0xA9 futures with (payload, tail)
        payload, tail = response
        config = parse_home_current_config(payload, tail)
        if config.grid_capacity_a is None:
            _LOGGER.warning("Unrecognised home current config payload: %s", payload.hex())
        return config

    async def _query_raw(self, opcode: int, description: str, payload: bytes = b"\x01") -> Optional[bytes]:
        """Send a query and return the response body (payload + tail), or None."""
        if not self._token:
            _LOGGER.warning("Cannot query %s - no session token", description)
            return None

        try:
            await self._send_frame(pack_frame_request(opcode, self._token, payload))
            response = await self._wait_for_response(opcode, timeout=5.0)
        except Exception as exc:
            _LOGGER.warning("%s query failed: %s", description, exc)
            return None

        if not response:
            _LOGGER.warning("No %s response received", description)
            return None

        # Some opcodes resolve with (payload, tail), the rest with plain payload
        if isinstance(response, tuple):
            payload, tail = response
            return payload + (tail or b"")
        return response

    async def _query_config_json(self, opcode: int, description: str) -> Optional[dict[str, Any]]:
        """Query a configuration JSON response (0xC1-0xC9)."""
        data = await self._query_raw(opcode, description)
        if data is None:
            return None
        result = parse_config_json(opcode, data)
        if "raw_hex" in result:
            _LOGGER.warning("Could not parse %s response as JSON", description)
        return result

    async def query_charger_basic_info(self) -> Optional[dict[str, Any]]:
        """Query charger basic information (0xC1)."""
        return await self._query_config_json(0xC1, "basic info")

    async def query_charger_protection_info(self) -> Optional[dict[str, Any]]:
        """Query charger protection information (0xC4)."""
        return await self._query_config_json(0xC4, "protection info")

    async def query_wifi_config(self) -> Optional[dict[str, Any]]:
        """Query WiFi configuration (0xC7)."""
        return await self._query_config_json(0xC7, "WiFi config")

    async def query_wifi_status(self) -> Optional[dict[str, Any]]:
        """Query WiFi status (0xE4) - binary format, not JSON."""
        data = await self._query_raw(0xE4, "WiFi status")
        if data is None:
            return None
        result = parse_wifi_status(data)
        if result.get("wifi_status", "").startswith("Unknown"):
            # Log lengths only: the response contains the WiFi password
            _LOGGER.warning("WiFi status received unknown data format (response length: %d)", len(data))
        return result

    async def query_network_status(self) -> Optional[dict[str, Any]]:
        """Query network status (0xD3) - error codes and networking mode."""
        data = await self._query_raw(0xD3, "network status")
        if data is None:
            return None
        return parse_network_status(data)


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

    def get_last_telemetry_age(self) -> Optional[float]:
        """Seconds since the last telemetry frame arrived, or None if none arrived yet."""
        if self._last_telemetry_time is None:
            return None
        return time.monotonic() - self._last_telemetry_time

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
