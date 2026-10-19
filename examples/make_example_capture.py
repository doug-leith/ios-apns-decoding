#!/usr/bin/env python3
"""Build ``examples/example.mitm``, a small capture used by the README quick start.

It holds one APNs courier connection as mitmdump with ``apns_mitm.py`` records it: the TLS
plaintext of both directions, in the serial encoding, for the messages an iPhone exchanges when
it connects (Connect, ConnectResponse, Filter, PresenceTracking, KeepAlive and the replies).

Everything is SYNTHETIC.  The messages use the real wire format, command numbers and field
numbers, so the decoder output shows the genuine field names, but no value comes from a real
device: the push token is a byte pattern, the certificate, nonce, signature and salt are
placeholders, the client IP address is in the range reserved for documentation (RFC 5737,
192.0.2.0/24), and the topic hashes are SHA-1 hashes of public Apple topic names.

Rebuild both files with::

    python examples/make_example_capture.py

which rewrites ``examples/example.mitm`` and ``examples/example_output.txt`` (the output of
``python apns_mitm.py examples/example.mitm``).
"""
import contextlib
import hashlib
import io
import os
import struct
import sys

from mitmproxy import io as mio, tcp
from mitmproxy.test import tflow

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import apns_mitm  # noqa: E402

T0 = 1767225600.0                       # 2026-01-01 00:00:00 UTC
TOKEN = bytes(range(0x10, 0x30))        # 32-byte placeholder push token


def msg(cmd: int, fields: list[tuple[int, bytes]]) -> bytes:
    """One serial-encoded message: [cmd][len u32 BE] then [field u8][len u16 BE][value]."""
    body = b"".join(bytes([n]) + struct.pack(">H", len(v)) + v for n, v in fields)
    return bytes([cmd]) + struct.pack(">I", len(body)) + body


def u8(v): return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)
def sha1(s): return hashlib.sha1(s.encode()).digest()


ms = int(T0 * 1000)
connect = msg(0x07, [
    (1, TOKEN), (2, u8(1)), (5, u32(0x26A)), (6, u8(1)), (7, u32(5)),
    (8, b"WiFi"), (9, b"16.7.11"), (10, b"20H360"), (11, b"iPhone10,1"),
    (12, b"placeholder for the device certificate (DER)"),
    (13, b"\x00" + u64(ms) + bytes(8)),                  # nonce: 00, time in ms, 8 random bytes
    (14, b"\x01\x01" + bytes(128)),                      # signature: 01 01 + RSA-1024 signature
    (16, u16(10)), (17, u16(0)),
])
connect_response = msg(0x08, [
    (1, u8(0)), (4, u16(5120)), (6, u32(3)), (8, u16(51200)), (10, u64(ms + 150)),
    (11, b"US"), (19, bytes([192, 0, 2, 1])),
])
filter_ = msg(0x09, [(1, TOKEN)]
              + [(2, sha1(t)) for t in ("com.apple.passd", "com.apple.mobileme.fmip", "com.apple.aa.idms")]
              + [(4, sha1("com.apple.icloud-container.com.apple.willowd"))])
presence = msg(0x20, [(1, u32(1)), (2, TOKEN), (3, u64(0x0123456789ABCDEF)), (4, u32(0)), (5, u64(ms + 200))])
keep_alive = msg(0x0C, [(1, b"WiFi"), (2, b"16.7.11"), (3, b"20H360"), (4, b"iPhone10,1"),
                        (5, b"10"), (6, b"600"), (9, u8(4)), (10, u8(4))])
presence_reply = msg(0x20, [(1, u32(1)), (2, TOKEN), (3, u8(0))])
keep_alive_ack = msg(0x16, [])

# (from_client, bytes, seconds after T0): chunks as mitmproxy would record them
CHUNKS = [
    (True, connect, 0.100),
    (False, connect_response, 0.150),
    (True, filter_ + presence + keep_alive, 0.180),
    (False, presence_reply + keep_alive_ack, 0.200),
]


def build_flow() -> tcp.TCPFlow:
    f = tflow.ttcpflow()
    f.id = "00000000-0000-4000-8000-000000000001"
    f.client_conn.sni = f.server_conn.sni = "courier2.push.apple.com"
    f.client_conn.alpn = f.server_conn.alpn = b""        # no ALPN selected, as through the addon
    f.client_conn.peername = ("192.168.1.10", 49152)
    f.server_conn.address = f.server_conn.peername = ("17.57.146.13", 5223)
    f.client_conn.timestamp_start = T0
    f.messages = [tcp.TCPMessage(fc, data, T0 + dt) for fc, data, dt in CHUNKS]
    return f


def main():
    capture = os.path.join(HERE, "example.mitm")
    with open(capture, "wb") as fo:
        mio.FlowWriter(fo).add(build_flow())
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        apns_mitm.main([capture])
    with open(os.path.join(HERE, "example_output.txt"), "w") as fo:
        fo.write(out.getvalue())
    print(f"wrote {capture} and example_output.txt")


if __name__ == "__main__":
    main()
