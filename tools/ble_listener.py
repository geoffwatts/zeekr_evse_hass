#!/usr/bin/env python3
"""Dump the charger's BLE frames through an ESPHome Bluetooth proxy.

Connects to the proxy over its native API, connects to the charger through it,
authenticates exactly like the integration does, then sends a heartbeat every
few seconds and logs every notification and decoded frame. Start a charge while
it runs to capture the B5 telemetry frames (payload length, temperature, ...).

    pip install aioesphomeapi pycryptodome
    export ESPHOME_NOISE_PSK=<api encryption key from the proxy's ESPHome config>
    python tools/ble_listener.py --serial EB1C03JA

IMPORTANT: only one BLE client can talk to the charger. Close the vendor app and
disable the Zeekr Charger config entry in Home Assistant while this runs.

Output: a readable log on stdout and a JSON-lines file (default
captures/ble_<timestamp>.jsonl) with every raw notification chunk and frame.
0xE4 (WiFi status) payloads contain the WiFi password and are redacted.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_PROTOCOL = ROOT / "custom_components" / "zeekr_charger" / "lib" / "protocol.py"
_spec = importlib.util.spec_from_file_location("zeekr_protocol", _PROTOCOL)
protocol = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = protocol
_spec.loader.exec_module(protocol)

CHUNK_SIZE = 20  # same as the integration's _send_frame
REDACT_OPCODES = {0xE4}


class FrameDumper:
    """Reassembles notification chunks into frames and records everything."""

    def __init__(self, out, echo=print):
        self.out = out
        self.echo = echo
        self.buffers: dict[str, bytearray] = {}
        self.redacting: dict[str, bool] = {}
        self.token: bytes | None = None
        self.b5_lengths: collections.Counter = collections.Counter()
        self.t0 = time.monotonic()

    def _write(self, record: dict) -> None:
        record["t"] = round(time.monotonic() - self.t0, 3)
        self.out.write(json.dumps(record) + "\n")
        self.out.flush()

    def on_chunk(self, source: str, data: bytes) -> None:
        buf = self.buffers.setdefault(source, bytearray())
        if data[:1] == b"\xaa":
            if buf:
                self._emit(bytes(buf))
                buf.clear()
            # a new frame starts: redact its raw chunks if it is a sensitive opcode
            self.redacting[source] = len(data) > 1 and data[1] in REDACT_OPCODES
        raw = "<redacted>" if self.redacting.get(source) else bytes(data).hex()
        self._write({"kind": "chunk", "char": source, "hex": raw})
        buf.extend(data)
        try:
            protocol.parse_frame(bytes(buf))
        except Exception:
            if len(buf) > 1024:
                buf.clear()
            return
        self._emit(bytes(buf))
        buf.clear()

    def _emit(self, frame: bytes) -> None:
        try:
            pf = protocol.parse_frame(frame)
        except Exception as exc:
            self._write({"kind": "bad_frame", "hex": frame.hex(), "error": str(exc)})
            return

        payload = pf.payload
        redacted = pf.opcode in REDACT_OPCODES
        record = {
            "kind": "frame",
            "opcode": f"0x{pf.opcode:02X}",
            "status": pf.status,
            "payload_len": len(payload),
            "payload": f"<redacted {len(payload)} bytes>" if redacted else payload.hex(),
            "tail": pf.tail.hex() if pf.tail else "",
        }
        line = f"RX 0x{pf.opcode:02X} len={len(payload)} payload={record['payload']} tail={record['tail']}"

        if pf.opcode == 0xFE and pf.status == 0 and self.token is None:
            self.token = protocol.extract_token_from_response(pf)
            line += "  <- auth token received"
        elif pf.opcode == 0xB5:
            self.b5_lengths[len(payload)] += 1
            record["b5_payload_len"] = len(payload)
            if len(payload) in protocol.TELEMETRY_LENGTHS:
                t = protocol.parse_b5_telemetry(payload)
                if t:
                    record["telemetry"] = {
                        "layout": t.layout,
                        "state": t.state,
                        "voltage_v": t.voltage_v,
                        "current_a": t.current_a,
                        "energy_kwh": t.session_energy_kwh,
                        "runtime_s": t.session_runtime_seconds,
                        "temperature_c": t.temperature_c,
                        "phase_flags": t.phase_flags,
                    }
                    line += (
                        f"\n     telemetry[{t.layout}]: {t.voltage_v:.1f} V, {t.current_a:.2f} A, "
                        f"{t.session_energy_kwh:.2f} kWh, runtime {t.session_runtime_seconds}s, "
                        f"temp={t.temperature_c}"
                    )
        self._write(record)
        self.echo(line)


def mac_to_int(mac: str) -> int:
    return int(mac.replace(":", "").replace("-", ""), 16)


def chunks(frame: bytes):
    for i in range(0, len(frame), CHUNK_SIZE):
        yield frame[i : i + CHUNK_SIZE]


async def find_address_type(client, address: int, timeout: float) -> int:
    """Listen for the charger's advertisement to learn its BLE address type."""
    found: asyncio.Future = asyncio.get_running_loop().create_future()

    def on_adv(resp):
        for adv in resp.advertisements:
            if adv.address == address and not found.done():
                found.set_result(adv.address_type)

    unsub = client.subscribe_bluetooth_le_raw_advertisements(on_adv)
    try:
        return await asyncio.wait_for(found, timeout)
    finally:
        unsub()


def find_char(services, uuid: str):
    for service in services.services:
        for char in service.characteristics:
            if char.uuid.lower() == uuid.lower():
                return char
    raise SystemExit(f"Characteristic {uuid} not found on the charger")


async def run(args) -> None:
    import aioesphomeapi  # imported here so the module can be imported for tests

    psk = args.noise_psk or os.environ.get("ESPHOME_NOISE_PSK")
    client = aioesphomeapi.APIClient(args.host, args.port, args.password, noise_psk=psk)
    await client.connect(login=True)
    info = await client.device_info()
    print(f"Connected to ESPHome '{info.name}' (ESPHome {info.esphome_version})")
    flags = info.bluetooth_proxy_feature_flags_compat(client.api_version)

    address = mac_to_int(args.mac)
    # The proxy only forwards advertisements to one API client and Home Assistant
    # normally holds that, so the scan may see nothing; fall back to --address-type.
    print(f"Looking for {args.mac} advertising (up to {args.scan_timeout:.0f}s)...")
    try:
        address_type = await find_address_type(client, address, args.scan_timeout)
        print(f"Seen advertising, address type {address_type}")
    except asyncio.TimeoutError:
        address_type = args.address_type
        print(f"Not seen (Home Assistant likely owns the advert subscription); assuming address type {address_type}")

    connected: asyncio.Future = asyncio.get_running_loop().create_future()

    def on_state(is_connected: bool, mtu: int, error: int) -> None:
        if connected.done():
            return
        if is_connected:
            connected.set_result(mtu)
        else:
            connected.set_exception(RuntimeError(f"BLE connect failed (error {error})"))

    print("Connecting to charger via proxy...")
    await client.bluetooth_device_connect(
        address, on_state, timeout=30.0, feature_flags=flags, has_cache=False, address_type=address_type
    )
    mtu = await asyncio.wait_for(connected, 40)
    print(f"Connected, MTU {mtu}")

    out_path = Path(args.out or f"captures/ble_{time.strftime('%Y%m%d_%H%M%S')}.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out = out_path.open("w")
    dumper = FrameDumper(out)
    print(f"Writing {out_path}")

    try:
        services = await client.bluetooth_gatt_get_services(address)
        write_char = find_char(services, protocol.GATT_CHAR_WNR)
        for uuid in (protocol.GATT_CHAR_NOTIFY, protocol.GATT_CHAR_NOTIFY2):
            char = find_char(services, uuid)
            short = uuid[4:8]
            await client.bluetooth_gatt_start_notify(
                address, char.handle, lambda h, d, s=short: dumper.on_chunk(s, bytes(d))
            )

        async def send(frame: bytes, label: str) -> None:
            print(f"TX {label}")
            for part in chunks(frame):
                await client.bluetooth_gatt_write(address, write_char.handle, part, False)
                await asyncio.sleep(0.01)

        await send(protocol.build_identity_frame(args.serial, args.station_id), "identity")
        for _ in range(100):
            if dumper.token:
                break
            await asyncio.sleep(0.1)
        if not dumper.token:
            raise SystemExit("No auth token - wrong --serial, or another client is connected?")

        await send(protocol.cmd_sync_time(dumper.token), "time sync")
        await asyncio.sleep(1.0)
        if args.authorize:
            await send(protocol.cmd_auth_charge(dumper.token), "authorize charge")

        print(f"Listening - start a charge now. Heartbeat every {args.interval}s. Ctrl-C to stop.")
        deadline = time.monotonic() + args.duration if args.duration else None
        while deadline is None or time.monotonic() < deadline:
            await send(protocol.cmd_heartbeat(dumper.token), "heartbeat")
            await asyncio.sleep(args.interval)
    finally:
        out.close()
        print("\nB5 payload lengths seen:", dict(dumper.b5_lengths))
        try:
            await client.bluetooth_device_disconnect(address)
        except Exception:
            pass
        await client.disconnect()


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="192.168.1.103", help="ESPHome BLE proxy address")
    p.add_argument("--port", type=int, default=6053)
    p.add_argument("--noise-psk", help="API encryption key (or set ESPHOME_NOISE_PSK)")
    p.add_argument("--password", default=None, help="legacy API password, if the proxy uses one")
    p.add_argument("--mac", default="E8:06:90:D2:06:A2", help="charger BLE MAC address")
    p.add_argument("--serial", default="EB1C03JA", help="charger serial, as entered in the integration")
    p.add_argument("--station-id", type=int, default=88888)
    p.add_argument("--interval", type=float, default=3.0, help="seconds between heartbeats")
    p.add_argument("--scan-timeout", type=float, default=8.0)
    p.add_argument("--address-type", type=int, default=0, help="BLE address type if not seen advertising: 0 public, 1 random")
    p.add_argument("--duration", type=float, default=0, help="stop after this many seconds (default: run until Ctrl-C)")
    p.add_argument("--authorize", action="store_true", help="also send the authorize-charge command once")
    p.add_argument("--out", help="JSONL output path")
    return p.parse_args(argv)


if __name__ == "__main__":
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        pass
