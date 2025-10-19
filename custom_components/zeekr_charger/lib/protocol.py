"""
Clean Zeekr BLE Protocol Library for Home Assistant Integration
Only includes the methods and definitions actually needed.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

from Crypto.Cipher import DES


# ============== BLE Characteristics ==============
GATT_CHAR_NOTIFY = "0000ff02-0000-1000-8000-00805f9b34fb"
GATT_CHAR_NOTIFY2 = "0000abf2-0000-1000-8000-00805f9b34fb"
GATT_CHAR_WNR = "0000abf1-0000-1000-8000-00805f9b34fb"


# ============== Opcodes ==============
class OPC(IntEnum):
    # Authentication
    IDENTITY_AUTH = 0xFE
    
    # Session management
    SYNC_TIME_CMD = 0xB0
    HEARTBEAT = 0xB5
    AUTH_CHARGE_CMD = 0xB4
    STOP_CHARGE_CMD = 0xB6
    
    # Power control
    POWER_CONTROL = 0xC0
    QUERY_POWER_PERCENT = 0xE0
    QUERY_HOME_CURRENT = 0xA9
    
    # Information queries
    CHARGE_POINT_BASIC_INFORMATION = 0xC1
    CHARGE_POINT_EMPLOY_INFORMATION = 0xC2
    BLUETOOTH_DEVICE_INFORMATION = 0xC8


# ============== Response Status Codes ==============
RESPONSE_STATUS_TEXT = {
    0x00: "SUCCESS",
    0x11: "PARSE_ERROR",
    0x12: "NO_PERMISSION",
    0x13: "REJECTED",
    0x14: "CMD_NOT_EXIST",
    0x15: "CMD_NOT_SUPPORTED",
    0x16: "TOKEN_TIMEOUT",
    0x50: "DEVICE_ERROR",
    0x51: "CMD_EXECUTE_FAILURE",
}


# ============== Heartbeat State Mapping ==============
@dataclass
class StateMapping:
    """Heartbeat state mapping for status codes."""
    car_connected: bool
    charging: bool
    state: str


HEARTBEAT_STATE_MAPPING = {
    0x00: StateMapping(car_connected=False, charging=False, state="available"),
    0x01: StateMapping(car_connected=True, charging=False, state="preparing"),
    0x02: StateMapping(car_connected=True, charging=False, state="suspended_ev"),
    0x03: StateMapping(car_connected=True, charging=False, state="reserved"),
    0x04: StateMapping(car_connected=True, charging=False, state="suspended_evse"),
    0x05: StateMapping(car_connected=True, charging=False, state="charging_break_off"),
    0x06: StateMapping(car_connected=True, charging=True, state="charging"),
    0x07: StateMapping(car_connected=True, charging=False, state="pausing"),
    0x08: StateMapping(car_connected=True, charging=False, state="finishing"),
    0x0E: StateMapping(car_connected=False, charging=False, state="unavailable"),
    0x0F: StateMapping(car_connected=False, charging=False, state="faulted"),
    0xC0: StateMapping(car_connected=False, charging=False, state="available"),  # Alternative format
}


def map_heartbeat_status_code(status_code: int) -> Optional[StateMapping]:
    """Map a heartbeat status code to its state information."""
    return HEARTBEAT_STATE_MAPPING.get(status_code)


# ============== Data Models ==============
@dataclass
class HeartbeatState:
    """Parsed heartbeat state information."""
    car_connected: bool = False
    charging: bool = False
    state: str = "unknown"
    port: int = 0
    timestamp: float = 0.0  # Unix timestamp when heartbeat was received
    seconds_ago: float = 0.0  # Seconds since last heartbeat
    telemetry: Optional[B5Telemetry] = None  # Detailed telemetry data for 21-byte payloads
    temperature_c: Optional[int] = None  # Charger temperature when present


@dataclass
class PowerStatus:
    """Power status information from 0xE0 query."""
    limit_amps: int = 0  # Current limit setting (byte 2)
    max_current_capacity: int = 0  # Maximum current capacity of device (byte 1)
    configured_limit_amps: int = 0  # Configured limit from tail (if present)


@dataclass
class CurrentConfig:
    """Current configuration information."""
    max_current_capacity_a: Optional[int] = None
    present_current_limit_a: Optional[int] = None
    grid_capacity_a: Optional[int] = None
    home_cfg_hex: Optional[str] = None
    grid_phase: Optional[int] = None
    earthing_sys: Optional[int] = None
    solar_pv: Optional[int] = None
    solar_phase: Optional[int] = None


@dataclass
class B5Telemetry:
    """Full heartbeat telemetry during active charging.

    Empirically confirmed layout on current Zeekr firmware (single and multi-phase):
    - Byte 0: state (0x06 = charging)
    - Byte 1: port hint (often zero; port index is repeated at byte 19)
    - Bytes 2-5: session sequence number (little-endian)
    - Bytes 6-7: phase/line flags (bitmask, 0 = single phase)
    - Bytes 8-9: line voltage (little-endian centivolts)
    - Bytes 10-11: reserved (observed as 0 on single-phase units)
    - Byte 12: charge current (deci-amps)
    - Bytes 13-14: session energy (little-endian; some firmwares append a third
      byte which we interpret using the extended-energy logic)
    - Bytes 15-16: session runtime (big-endian seconds)
    - Byte 18: state repeat / status echo
    - Byte 19: port index (when in range) and, on single-phase units, the
      internal temperature in °C
    - Byte 20: checksum / rolling counter
    - Byte 31 (when present): internal temperature for multi-phase payloads
    """
    state: int
    port: int
    charge_order_seq: int  # 4-byte sequence number
    charge_electricity_centikwh: int  # Energy in 0.01 kWh units
    charge_voltage_centi_v: int  # Voltage in 0.01 V units
    charge_current_centi_a: int  # Current in 0.01 A units
    charge_duration_seconds: int  # Duration in seconds (session runtime)
    phase_flags: int = 0  # Phase bitmask (0 = single phase)
    state_repeat: int = 0  # State byte echoed later in payload
    port_hint: int = 0  # Raw byte 1 value for reference/debugging
    checksum: int = 0  # Trailer byte captured from payload
    session_energy_kwh_exact: float = 0.0
    temperature_c: Optional[int] = None  # Charger temperature derived from heartbeat

    @property
    def voltage_v(self) -> float:
        return self.charge_voltage_centi_v / 100.0

    @property
    def current_a(self) -> float:
        return self.charge_current_centi_a / 100.0

    @property
    def session_energy_kwh(self) -> float:
        if self.session_energy_kwh_exact:
            return self.session_energy_kwh_exact
        return self.charge_electricity_centikwh / 100.0

    @property
    def session_runtime_seconds(self) -> int:
        return self.charge_duration_seconds

    @property
    def sequence_number(self) -> int:
        return self.charge_order_seq


# ============== Frame Building ==============
def build_header(payload_len: int) -> bytes:
    """Build a 5-byte header for frames."""
    if payload_len < 0:
        payload_len = 0
    lo = payload_len & 0xFF
    hi = (payload_len >> 8) & 0xFF
    return bytes([0x00, 0x00, lo, hi, 0x00])


def _compute_checksum(prefix: bytes, token: bytes, payload: bytes) -> int:
    """Compute XOR checksum for frame."""
    checksum = 0
    for b in prefix:
        checksum ^= b
    for b in token:
        checksum ^= b
    for b in payload:
        checksum ^= b
    return checksum & 0xFF


def pack_frame_request(op: int, token: bytes, payload: bytes = b"", header: Optional[bytes] = None) -> bytes:
    """Pack a request frame (0xFE format)."""
    assert len(token) == 8, "token must be 8 bytes"
    h = header if header is not None else build_header(len(payload))
    if len(h) != 5:
        raise ValueError("header must be 5 bytes")

    frame = bytearray()
    frame.append(0xFE)  # SOF
    frame.append(op & 0xFF)  # Opcode
    frame.extend(h)  # Header
    
    # Placeholder checksum
    frame.append(0x00)
    frame.extend(token)  # Token
    frame.extend(payload)  # Payload
    
    # Compute and set checksum
    checksum = _compute_checksum(frame[:7], token, payload)
    frame[7] = checksum
    
    return bytes(frame)


# ============== Frame Parsing ==============
def parse_frame(data: bytes) -> Any:
    """Parse AA/FE framed packets."""
    if not data or len(data) < 2:
        raise ValueError("frame too short")

    sof = data[0]
    op = data[1]

    if sof == 0xAA:  # Response frame
        # Frame structure: AA | OPC | H0 H1 H2 H3 H4 | CHK | T0..T7 | PAYLOAD | TAIL
        if len(data) < 1 + 1 + 5 + 1 + 8:
            raise ValueError("AA frame too short")

        header = data[2:7]
        payload_len = header[2] | (header[3] << 8)
        checksum_byte = data[7]  # Checksum at position 7

        # Token starts after the checksum (position 8)
        token_start = 8
        token_end = token_start + 8
        token = data[token_start:token_end]

        # Payload starts after the token
        payload_start = token_end
        payload_end = payload_start + payload_len
        if payload_end > len(data):
            raise ValueError("AA frame payload incomplete")

        payload = data[payload_start:payload_end]
        
        # FIXED: Only take 1 byte as tail if it's not the start of a new frame (0xAA)
        # This matches the working protocol implementation
        tail = b""
        if payload_end < len(data):
            nxt = data[payload_end]
            if nxt != 0xAA:
                tail = data[payload_end:payload_end+1]

        class ParsedFrame:
            def __init__(self):
                self.sof = sof
                self.opcode = op
                self.header = header
                self.status = header[0] if len(header) > 0 else 0
                self.checksum = checksum_byte
                self.token = token
                self.payload = payload
                self.tail = tail

        return ParsedFrame()

    elif sof == 0xFE:  # Request frame
        if len(data) < 10:
            raise ValueError("FE frame too short")
        header = data[2:8]
        token = data[-8:]
        payload = data[8:-8] if len(data) > 16 else b""

        class ParsedFrame:
            def __init__(self):
                self.sof = sof
                self.opcode = op
                self.header = header
                self.status = None
                self.token = token
                self.payload = payload
                self.tail = b""

        return ParsedFrame()

    else:
        raise ValueError("unknown SOF")


# ============== Authentication ==============
def _pkcs5_pad(data: bytes, block_size: int = 8) -> bytes:
    """PKCS5 padding for DES encryption."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def build_identity_frame(serial: str, station_id: int) -> bytes:
    """Build the identity authentication frame."""
    # Build identity payload
    block = bytearray(0x30)
    
    serial_clean = serial.replace("-", "").upper()
    if len(serial_clean) < 8:
        raise ValueError("Serial must be at least 8 characters")
    block[0:8] = serial_clean.encode("ascii")[:8]
    
    block[0x14] = 0x02  # auth level
    block[0x15] = 0x01  # client type
    
    station_ascii = str(station_id).encode("ascii")
    if len(station_ascii) > 0x0f:
        raise ValueError("Station ID too long")
    block[0x16 : 0x16 + len(station_ascii)] = station_ascii
    
    # Encrypt with DES
    padded = _pkcs5_pad(bytes(block), 8)
    cipher = DES.new(b"ucserver", DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded)
    
    # Build frame
    body = bytearray(0x82)
    body[0:2] = b"\x80\x00"
    body[2 : 2 + len(ciphertext)] = ciphertext
    
    token_zero = b"\x00" * 8
    header = build_header(len(body))
    return pack_frame_request(OPC.IDENTITY_AUTH, token_zero, bytes(body), header=header)




def extract_token_from_response(pf) -> Optional[bytes]:
    """Extract session token from authentication response (V1)."""
    if pf.payload:
        extra = getattr(pf, "tail", b"") or b""
        if len(extra) == 1 and len(pf.payload) >= 7:
            return pf.payload[-7:] + extra
        elif len(pf.payload) >= 8:
            return pf.payload[-8:]
    return pf.token


# ============== Command Builders ==============
def cmd_sync_time(token: bytes, tz_minutes: Optional[int] = None) -> bytes:
    """Build a time sync command."""
    if tz_minutes is None:
        tz_minutes = 0
    epoch = int(time.time())
    payload = struct.pack("<IH", epoch & 0xFFFFFFFF, tz_minutes & 0xFFFF)
    return pack_frame_request(OPC.SYNC_TIME_CMD, token, payload)


def cmd_heartbeat(token: bytes) -> bytes:
    """Build a heartbeat command."""
    return pack_frame_request(OPC.HEARTBEAT, token, b"")


def cmd_query_power_percent(token: bytes) -> bytes:
    """Build a power status query command."""
    return pack_frame_request(OPC.QUERY_POWER_PERCENT, token, b"")


def cmd_query_home_current(token: bytes) -> bytes:
    """Build a home current configuration query command."""
    return pack_frame_request(OPC.QUERY_HOME_CURRENT, token, b"")


def cmd_set_current_limit(token: bytes, port: int, amps: int) -> bytes:
    """Build a current limit set command."""
    payload = bytes([port & 0xFF, amps & 0xFF])
    return pack_frame_request(OPC.POWER_CONTROL, token, payload)


def cmd_auth_charge(token: bytes) -> bytes:
    """Build an authorize charge command."""
    return pack_frame_request(OPC.AUTH_CHARGE_CMD, token, b"")


def cmd_stop_charge(token: bytes) -> bytes:
    """Build a stop charge command."""
    return pack_frame_request(OPC.STOP_CHARGE_CMD, token, b"")


def cmd_get_basic_info(token: bytes) -> bytes:
    """Build a basic information query command."""
    return pack_frame_request(OPC.CHARGE_POINT_BASIC_INFORMATION, token, b"")


def cmd_get_employ_info(token: bytes) -> bytes:
    """Build an employment information query command."""
    return pack_frame_request(OPC.CHARGE_POINT_EMPLOY_INFORMATION, token, b"")


def cmd_get_ble_info(token: bytes) -> bytes:
    """Build a BLE device information query command."""
    return pack_frame_request(OPC.BLUETOOTH_DEVICE_INFORMATION, token, b"")


# ============== Response Parsers ==============
def parse_b5_telemetry(payload: bytes) -> Optional[B5Telemetry]:
    """Parse B5 telemetry payload with empirically determined structure."""
    if len(payload) < 21:
        return None
    
    try:
        # Parse with empirically determined byte positions (see B5Telemetry docstring)
        state = payload[0]
        port_hint = payload[1]

        # 4-byte sequence number (not energy!)
        charge_order_seq = int.from_bytes(payload[2:6], "little")
        phase_flags = int.from_bytes(payload[6:8], "little")

        # 2-byte voltage - divided by 100.0
        charge_voltage_centi_v = int.from_bytes(payload[8:10], "little")

        # Current (firmware now uses two-byte little-endian 0.01A units; older
        # builds only populate the low byte with 0.1A steps).
        raw_current = int.from_bytes(payload[12:14], "little")
        if (raw_current >> 8) > 0:
            charge_current_centi_a = raw_current
        else:
            charge_current_centi_a = payload[12] * 10

        # Session energy: 2 bytes at bytes 14-15, in centi-kWh units (0.01 kWh)
        # This matches the Android app parsing and working Python implementation
        session_energy_centikwh = int.from_bytes(payload[14:16], "little")
        energy_kwh = session_energy_centikwh / 100.0
        charge_electricity_centikwh = session_energy_centikwh

        # Session runtime appears as big-endian seconds (two-byte counter)
        charge_duration_seconds = (payload[15] << 8) | payload[16]

        state_repeat = payload[18]

        temperature_c: Optional[int] = None
        port = port_hint

        if len(payload) > 19:
            port_candidate = payload[19]
            if phase_flags == 0:
                temperature_c = port_candidate
            # Use candidate as port when it is within sensible range (1..2)
            if 0 < port_candidate <= 2:
                port = port_candidate

        if phase_flags != 0 and len(payload) > 31:
            temperature_c = payload[31]

        checksum = payload[20]

        return B5Telemetry(
            state=state,
            port=port,
            charge_order_seq=charge_order_seq,
            charge_electricity_centikwh=int(charge_electricity_centikwh),
            charge_voltage_centi_v=charge_voltage_centi_v,
            charge_current_centi_a=charge_current_centi_a,
            charge_duration_seconds=charge_duration_seconds,
            phase_flags=phase_flags,
            state_repeat=state_repeat,
            port_hint=port_hint,
            checksum=checksum,
            session_energy_kwh_exact=energy_kwh,
            temperature_c=temperature_c,
        )
    except Exception as e:
        return None


def parse_heartbeat_state(payload: bytes, last_heartbeat_time: float = 0.0) -> HeartbeatState:
    """Parse heartbeat payload to extract car connection and charging state."""
    import time
    current_time = time.time()
    state_info = HeartbeatState(timestamp=current_time)
    
    # Calculate seconds since last heartbeat
    if last_heartbeat_time > 0:
        state_info.seconds_ago = current_time - last_heartbeat_time
    
    # Log heartbeat state changes (not every heartbeat)
    
    if len(payload) == 2:
        # Two-byte heartbeat format: [status_code][port]
        # Android app (ReadStatusResponse.smali) parses first byte as status code
        status_code = payload[0]
        port = payload[1]
        state_info.port = port
        
        # High-value status codes (0x80+) are NOT standard heartbeat states
        # The Android app does not handle these - they fall through without processing
        # These appear to be data format indicators or query response types
        # We ignore them like the Android app does - no state change
        if status_code >= 0x80:
            # Ignore non-standard formats like the Android app does
            # Don't update any state fields - leave them as default values
            # (Android app also ignores these)
            return state_info
        
        # Use centralized state mapping
        state_mapping = map_heartbeat_status_code(status_code)
        if state_mapping:
            state_info.car_connected = state_mapping.car_connected
            state_info.charging = state_mapping.charging
            state_info.state = state_mapping.state
        else:
            # Other unrecognized low-value codes
            state_info.car_connected = False
            state_info.charging = False
            state_info.state = f"unknown_{status_code:02X}"
            
    elif len(payload) == 3 and payload == b"\x01\x01\x01":
        # Keep-alive pattern
        pass  # Keep-alive received
        
    elif len(payload) == 8:
        # B5LimitSnapshot - 8-byte current limit advertisement
        record_type = payload[0]
        port = payload[1]
        state_flag = payload[2]
        limit_amps = int.from_bytes(payload[4:6], "little")
        state_info.port = port
        
        # Use centralized state mapping
        state_mapping = map_heartbeat_status_code(state_flag)
        if state_mapping:
            state_info.car_connected = state_mapping.car_connected
            state_info.charging = state_mapping.charging
            state_info.state = state_mapping.state
        else:
            state_info.car_connected = True
            state_info.charging = False
            state_info.state = f"limit_snapshot_{state_flag:02X}"
        
        # Limit snapshot parsed
        
    elif len(payload) == 21:
        # Full telemetry frame - parse detailed charging data
        telemetry = parse_b5_telemetry(payload)
        if telemetry:
            state_info.port = telemetry.port
            state_info.car_connected = True
            state_info.charging = telemetry.state == 0x06
            state_info.state = "charging" if telemetry.state == 0x06 else f"state_{telemetry.state:02X}"

            # Store telemetry data for detailed charging information
            state_info.telemetry = telemetry
            state_info.temperature_c = telemetry.temperature_c
            # Telemetry data parsed
        else:
            # Fallback to basic parsing if telemetry parsing fails
            state = payload[0]
            port = payload[1]
            state_info.port = port
            state_info.car_connected = True
            state_info.charging = state == 0x06
            state_info.state = "charging" if state == 0x06 else f"state_{state:02X}"
    
    # Handle single byte responses (like 0x45)
    elif len(payload) == 1:
        state = payload[0]
        state_info.state = f"single_byte_{state:02X}"
        # For single byte responses, we can't determine car connection status
        state_info.car_connected = False
        state_info.charging = False
    
    # Handle other payload lengths
    else:
        state_info.state = f"unknown_len_{len(payload)}"
        # Unknown heartbeat pattern - log for analysis

        # Try to extract basic state info from first byte if possible
        if len(payload) >= 1:
            state = payload[0]
            # Use centralized state mapping with unknown prefix
            state_mapping = map_heartbeat_status_code(state)
            if state_mapping:
                state_info.car_connected = state_mapping.car_connected
                state_info.charging = state_mapping.charging
                state_info.state = f"unknown_{state_mapping.state}_{state:02X}"
            else:
                state_info.state = f"unknown_{state:02X}"

        if len(payload) >= 2:
            state_info.port = payload[1]

    if state_info.temperature_c is None:
        if len(payload) > 31:
            state_info.temperature_c = payload[31]
        elif len(payload) > 19:
            state_info.temperature_c = payload[19]

    return state_info


def parse_power_status(payload: bytes, tail: bytes = b"") -> PowerStatus:
    """Parse power status response (0xE0)."""
    # E0 response structure (from zeekr_dumper_pro.py):
    # - Optional 0x26 selector byte (we skip it in preprocessing)
    # - payload[0] = power_status_code (sequence/status)
    # - payload[1] = max_current_a (if len >= 3)
    # - payload[2] = set_current_a (if len >= 3)
    # - tail[0] = set_current_a (if present, overrides payload[2])
    
    # Combine payload and tail for processing
    full_data = payload + (tail if tail else b"")
    
    if len(full_data) < 1:
        return PowerStatus()
    
    # Skip optional 0x26 selector byte
    if full_data[0] == 0x26:
        full_data = full_data[1:]
    
    if len(full_data) < 1:
        return PowerStatus()
    
    status_code = full_data[0]
    max_current_a = 0
    set_current_a = 0
    
    if len(full_data) >= 3:
        max_current_a = full_data[1]
        # If more than 3 bytes, use the last byte as set_current
        if len(full_data) > 3:
            set_current_a = full_data[-1]
        else:
            set_current_a = full_data[2]
    elif len(full_data) == 2:
        set_current_a = full_data[1]
    
    # Log the raw data for debugging
    # Raw data logged for debugging
    
    return PowerStatus(limit_amps=set_current_a, max_current_capacity=max_current_a, configured_limit_amps=set_current_a)


def parse_tlv_response(payload: bytes) -> Dict[str, Any]:
    """Parse TLV (Type-Length-Value) response."""
    result = {}
    i = 0
    
    # Log the raw payload for debugging
    
    # Handle single-byte responses (might be status codes)
    if len(payload) == 1:
        result["status_byte"] = payload[0]
        return result
    
    # First, try to parse as JSON if it looks like JSON
    try:
        if payload.startswith(b'{') or b'"' in payload:
            # Use robust JSON extraction similar to zeekr_dumper_pro.py
            json_str = _extract_json_from_payload(payload)
            if json_str:
                import json
                parsed_json = json.loads(json_str)
                result.update(parsed_json)
                return result
    except Exception as e:
        pass
    
    # Fall back to TLV parsing
    while i < len(payload):
        if i + 2 > len(payload):
            break
            
        tag = payload[i]
        length = payload[i + 1]
        i += 2
        
        if i + length > len(payload):
            break
            
        value = payload[i:i + length]
        i += length
        
        # Try to decode as ASCII if all bytes are printable
        if all(32 <= b <= 126 for b in value):
            ascii_value = value.decode("ascii", errors="ignore")
            
            # Map known field tags to meaningful names
            field_name = _get_field_name(tag, ascii_value)
            result[field_name] = ascii_value
        else:
            # Try to decode as integer for known numeric fields
            if tag == 0x88 and len(value) <= 4:  # max current capacity
                int_value = int.from_bytes(value, "little")
                result["max_current_capacity_a"] = int_value
            elif tag == 0xDD and len(value) <= 4:  # present current limit
                int_value = int.from_bytes(value, "little")
                result["present_current_limit_a"] = int_value
            else:
                result[f"field_{tag:02X}_hex"] = value.hex()
    
    return result


def _extract_json_from_payload(payload: bytes) -> str | None:
    """
    Robust JSON slicer from payload.
    - Decodes payload as UTF-8 (ignore errors).
    - Finds the first '{' and then walks forward to the last balanced '}'.
    - If braces are unbalanced, falls back to slicing up to the last '}' present.
    """
    try:
        s = payload.decode('utf-8', errors='ignore')
    except Exception:
        s = ''.join(chr(x) if 32 <= x <= 126 else ' ' for x in payload)
    
    # Quick exit
    if '{' not in s or '}' not in s:
        return None
    
    # Find first '{'
    start = s.find('{')
    if start == -1:
        return None
    
    # Walk to balanced end
    depth = 0
    end_idx = -1
    for i in range(start, len(s)):
        ch = s[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end_idx = i
                break
    
    if end_idx == -1:
        # Fallback: use last '}' if any
        last = s.rfind('}')
        if last > start:
            candidate = s[start:last+1]
        else:
            return None
    else:
        candidate = s[start:end_idx+1]
    
    # Sanity-check JSON
    candidate_stripped = candidate.strip()
    if candidate_stripped:
        try:
            import json
            json.loads(candidate_stripped)
            return candidate_stripped
        except Exception:
            # Return raw slice anyway; caller may want partials
            return candidate_stripped
    
    return None


def _get_field_name(tag: int, value: str) -> str:
    """Map TLV tag to meaningful field name based on known patterns."""
    # Common field mappings based on your data
    field_mappings = {
        0x01: "serial_number",
        0x02: "model",
        0x03: "manufacturer", 
        0x04: "firmware_version",
        0x05: "hardware_version",
        0x06: "production_date",
        0x07: "rated_charging_current_a",
        0x08: "rated_power_w",
        0x09: "c_board_software_version",
        0x0A: "device_type",
        0x0B: "mac_address",
        0x0C: "ip_address",
    }
    
    # Check if the value matches known patterns
    if "V" in value and "." in value and len(value) < 20:
        return "software_version"
    elif "20" in value and "-" in value and len(value) > 8:
        return "production_date"
    elif value.isdigit() and int(value) > 10 and int(value) < 100:
        return "rated_charging_current_a"
    elif value.isdigit() and int(value) > 1000:
        return "rated_power_w"
    elif tag in field_mappings:
        return field_mappings[tag]
    else:
        return f"field_{tag:02X}"


def cmd_get_protection_info(token: bytes) -> bytes:
    """C4 protection info query V1 plaintext."""
    return pack_frame_request(0xC4, token)
