"""Offline test of the BLE listener's frame dumping (no proxy or charger needed)."""

import importlib.util
import io
import json
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "tools" / "ble_listener.py"
_spec = importlib.util.spec_from_file_location("ble_listener", _PATH)
listener = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(listener)

TOKEN = bytes.fromhex("38a61017afac26c0")
RAEDIAN = bytes.fromhex("0601552700005c0054560000a0050a00000000000a0000000000b9040000200121")


def make_frame(opcode: int, payload: bytes, tail: bytes = b"") -> bytes:
    header = bytes([0, 0, len(payload) & 0xFF, len(payload) >> 8, 0])
    return bytes([0xAA, opcode]) + header + b"\x60" + TOKEN + payload + tail


def feed(dumper, frame):
    for chunk in listener.chunks(frame):
        dumper.on_chunk("ff02", chunk)


def records(out):
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_chunked_raedian_telemetry_is_reassembled_and_decoded():
    out, echoed = io.StringIO(), []
    dumper = listener.FrameDumper(out, echo=echoed.append)
    feed(dumper, make_frame(0xB5, RAEDIAN))

    frames = [r for r in records(out) if r["kind"] == "frame"]
    assert len(frames) == 1
    assert frames[0]["b5_payload_len"] == 33
    assert frames[0]["telemetry"]["layout"] == "raedian33"
    assert frames[0]["telemetry"]["temperature_c"] == 33
    assert dumper.b5_lengths == {33: 1}
    # every raw chunk is recorded too
    assert sum(r["kind"] == "chunk" for r in records(out)) == 3


def test_idle_heartbeat_has_no_telemetry():
    out = io.StringIO()
    dumper = listener.FrameDumper(out, echo=lambda _: None)
    feed(dumper, make_frame(0xB5, b"\x00\x01"))
    frame = [r for r in records(out) if r["kind"] == "frame"][0]
    assert frame["b5_payload_len"] == 2 and "telemetry" not in frame


def test_wifi_status_payload_is_redacted():
    out = io.StringIO()
    dumper = listener.FrameDumper(out, echo=lambda _: None)
    feed(dumper, make_frame(0xE4, b"\x02MyNet\x0apassword\x03"))
    frame = [r for r in records(out) if r["kind"] == "frame"][0]
    assert "password" not in frame["payload"]
    assert frame["payload"].startswith("<redacted")
    # raw chunks must not leak it either
    assert "password".encode().hex() not in out.getvalue()
