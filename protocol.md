# Zeekr / Brioess Charger BLE Protocol

This document summarizes the application-layer BLE protocol used by the Zeekr wallbox, based on traffic captures

## 1. BLE Transport Basics
- **Services & Characteristics**
  - Primary service `0000FFFF-0000-1000-8000-00805F9B34FB`
    - `FF01-...` Write (some firmwares accept Write With Response; most use WNR)
    - `FF02-...` Notify / Read (primary notification path)
  - Secondary service `0000ABF0-0000-1000-8000-00805F9B34FB`
    - `ABF1-...` Write Without Response (commonly used for requests)
    - `ABF2-...` Notify (secondary notification path)
- **Connection routine**
  1. Connect and request high MTU (firmware accepts 517 bytes).
  2. Enable notifications on `FF02` and `ABF2` (use `ABF4` too if exposed).
  3. Send requests via `ABF1` (fallback to `FF01` if required).
  4. Charger accepts only one central connection at a time.

## 2. Framing & Checksums
Every packet is a framed message containing a single opcode.

```
Request:  FE | OPC | H0 H1 H2 H3 H4 | CHK | TOKEN[8] | PAYLOAD...
Response: AA | OPC | H0 H1 H2 H3 H4 | CHK | TOKEN[8] | PAYLOAD... | [TAIL]
```

- **SOF**: `0xFE` for requests, `0xAA` for responses.
- **Opcode**: 1 byte.
- **Header**: 5 bytes. `H2|H3` (little endian) is the payload length. `H0` doubles as status for replies.
- **Checksum** (`CHK`): XOR of header (SOF excluded), token, and payload: `CHK = xor(H0..H4, TOKEN[0..7], PAYLOAD)`.
- **Token**: 8-byte session token provided by the authentication step. All commands must echo it.
- **Payload**: Command-specific data; empty for many requests.
- **Tail**: Optional single byte on responses (examples: `0x7D` closing brace, current limit mirror). Always inspect trailing bytes past the declared payload length.

Notifications may split frames across BLE packets. Reassemble chunks until the next `0xAA` start byte is seen.

## 3. Authentication & Session Bootstrap
1. **Identity request (`0xFE` opcode, `IDENTITY_AUTH`)**
   - Build a 0x30-byte block:
     - Bytes 0x00–0x07: Charger serial (ASCII, uppercase, hyphen removed).
     - Bytes 0x08–0x13: `0x00` padding.
     - Byte 0x14: `0x02` (auth level).
     - Byte 0x15: `0x01` (client type).
     - Bytes 0x16–0x24: Station/account identifier as ASCII digits, padded with zeros.
     - Remaining bytes: zero.
   - Apply PKCS#5 padding to 56 bytes and encrypt with DES/ECB using key `"ucserver"`.
   - Wrap ciphertext in an 0x82-byte payload: `80 00 || ciphertext || zero padding`.
   - Send frame with `token = 00...00`.
2. **Identity response**
   - Reply is `AA FE ...` carrying status, hardware/software strings, and an 8-byte session token (last bytes of payload/tail). Extract and persist this token.
3. **Immediate follow-ups**
   - `0xB0 SYNC_TIME_CMD`: payload `<epoch (uint32 LE)><timezone_minutes (uint16 LE)>`.
   - Optional info pulls (e.g., `0xC1` basic info) to confirm the token.
4. **Token Lifetime**
   - Token persists until idle timeout or charger reset. A `TOKEN_TIMEOUT` status requires re-auth.

## 4. Response Status Codes
These map header byte `H0` in responses:

| Code | Meaning             |
|------|---------------------|
| 0x00 | SUCCESS             |
| 0x11 | PARSE_ERROR         |
| 0x12 | NO_PERMISSION       |
| 0x13 | REJECTED            |
| 0x14 | CMD_NOT_EXIST       |
| 0x15 | CMD_NOT_SUPPORTED   |
| 0x16 | TOKEN_TIMEOUT       |
| 0x50 | DEVICE_ERROR        |
| 0x51 | CMD_EXECUTE_FAILURE |

## 5. Command Reference
Only opcodes observed on production firmware are listed. All requests echo the session token and typically carry empty payloads unless specified.

### 5.1 Session & Control
| Opcode | Request Payload                      | Response Highlights |
|--------|--------------------------------------|---------------------|
| 0xFE (`IDENTITY_AUTH`) | DES-encrypted block (see §3) | Returns auth level, firmware strings, session token |
| 0xB0 (`SYNC_TIME_CMD`) | `<epoch><tz_minutes>`        | Echoes the time values |
| 0xB3 (`SET_CHARGE_MODEL`) | `00` = auto-start, `01` = authorised-start | Ack only |
| 0xB4 (`AUTH_CHARGE_CMD`) | none | Ack (`AA B4`) with success status |
| 0xB5 (`HEARTBEAT`) | none | Heartbeat payload (see §6) |
| 0xB6 (`STOP_CHARGE_CMD`) | none | Ack; includes cumulative energy counter |

### 5.2 Power & Current
| Opcode | Request Payload             | Response Highlights |
|--------|-----------------------------|---------------------|
| 0xC0 (`POWER_CONTROL`) | `[port, amps]` | Optional ack; charger adopts requested limit if within installation caps |
| 0xE0 (`QUERY_POWER_PERCENT`) | none | Payload: status byte, device max current, set current; tail mirrors configured limit |
| 0xA9 (`QUERY_HOME_CURRENT`) | none | Returns installation configuration (grid capacity, earthing, solar flags) with tail repeating current limit |

### 5.3 Information Queries
| Opcode | Description |
|--------|-------------|
| 0xC1 (`CHARGE_POINT_BASIC_INFORMATION`) | Static device metadata (serial, power, firmware revisions). Payload may include JSON or TLV strings. |
| 0xC2 (`CHARGE_POINT_EMPLOY_INFORMATION`) | Site/installation info (connector type, rated current, number of outlets). |
| 0xC8 (`BLUETOOTH_DEVICE_INFORMATION`) | BLE board firmware and MAC address. |
| 0xC4 (`PROTECTION_CONFIGURATION`) | Residual current, relay checks, RFID flags. |

### 5.4 Networking & Services
| Opcode | Description |
|--------|-------------|
| 0xD2 (`CONFIGURATION_WIFI_NETWORK`) | TLV payload configuring SSID, credentials, DHCP/static IP, DNS. |
| 0xD3 (`CHECK_NETWORK_STATUS`) | Bitfields for link status, IP acquisition, backend reachability. |
| 0xD4 (`CHANGE_NET_MODE`) | Switches between Wi-Fi/LAN/4G priority modes. |
| 0xC6 / 0xBF / 0xCF | LAN, grid-network, and 4G module configuration (TLV encoded). |
| 0x86 / 0xD6–0xDA | OCPP server profile management (host, port, scheme, path, heartbeat). |

### 5.5 RFID & Metering
| Opcode | Description |
|--------|-------------|
| 0xD0 (`ACTIVE_ADD_CARD`) | Arms RFID reader to learn a new token; async notification informs success. |
| 0xF1 / 0xF2 (`CONFIGURE_ELECTRIC_METER`, `QUERY_ELECTRIC_METER_CONFIGURATION`) | Meter binding, Modbus parameters, CT/phase setup. |

## 6. Heartbeat Payloads (`0xB5` Responses)
Heartbeats appear multiple times per minute and vary by length:

- **Keep-alive**: `01 01 01` — simple acknowledgement.
- **State packets**: `[state, port]` — map state codes via table below.
- **Limit snapshot**: `08-byte` structure `[type, port, state, reserved, amps_le, 0x00, 0x00, 0x00]` announcing configured current.
- **Telemetry block (21 bytes)**
  - Byte 0: state (`0x06` = charging)
  - Byte 1: port
  - Bytes 2–5: session sequence number (little endian)
  - Bytes 6–7: status/flags (phase bitfield, etc.)
  - Bytes 8–9: line voltage (0.01 V units)
  - Byte 12: current (0.1 A units)
  - Bytes 13–14: session energy (0.01 kWh)
  - Bytes 16–19: session runtime (seconds)
  - Byte 20: checksum / rolling counter

### State Code Map
| Value | Description        | Car Connected | Charging |
|-------|--------------------|---------------|----------|
| 0x00  | available          | No            | No       |
| 0x01  | preparing          | Yes           | No       |
| 0x02  | suspended (EV)     | Yes           | No       |
| 0x03  | reserved           | Yes           | No       |
| 0x04  | suspended (EVSE)   | Yes           | No       |
| 0x05  | charging break-off | Yes           | No       |
| 0x06  | charging           | Yes           | Yes      |
| 0x07  | pausing            | Yes           | No       |
| 0x08  | finishing          | Yes           | No       |
| 0x0E  | unavailable        | No            | No       |
| 0x0F  | faulted            | No            | No       |
| 0xC0  | available (alt)    | No            | No       |

## 7. TLV and JSON Handling
Many responses blend TLV data with embedded JSON:
- If payload starts with `{` or contains printable braces, extract the JSON substring (balanced braces) before parsing TLVs.
- TLV convention: `[Type (1B)] [Length (1B)] [Value ...]`, with `0xFF` length meaning the next two bytes encode the actual length (little endian).
- Known tag hints:
  - `0x01`: serial number
  - `0x02`: model name
  - `0x04`: firmware version
  - `0x07`: rated charging current (A)
  - `0x08`: rated power (W)
  - `0x88`: maximum current capacity (little endian integer)
  - `0xDD`: present current limit (little endian integer)

## 8. Implementation Notes & Tips
- Always check the trailing byte after the declared payload length—`0xE0` and `0xA9` rely on it for the active current limit.
- Charger may drop acknowledgements for `0xC0`; trust subsequent heartbeat or query responses to confirm the new setting.
- If `NO_PERMISSION` (`0x12`) appears, ensure the session token is valid and that the charger is in an idle state for the requested operation.
- For automation, a safe cycle is: `HEARTBEAT` → `QUERY_POWER_PERCENT` → `POWER_CONTROL` → monitor `HEARTBEAT` telemetry until stable.
- BLE connection loss resets the session; repeat the identity handshake to recover.
