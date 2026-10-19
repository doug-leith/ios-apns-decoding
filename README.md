# Decoding Apple Push Notification Service (APNs) Traffic

Every iPhone keeps a long-lived connection to the Apple Push Notification service (APNs), over which Apple's servers deliver notifications to the handset's apps and services. The connection, to `courier.push.apple.com` on TCP port 5223, carries an undocumented binary protocol inside TLS, and it is usually missing from the decrypted traffic captures used in privacy measurements: either port 5223 is not intercepted at all, or, if it is, the TLS handshake fails in `mitmproxy`, so the connection is never decrypted. This repository contains:

- **[`apns_mitm.py`](apns_mitm.py)**, a single self-contained file that is both a [mitmproxy](https://mitmproxy.org) addon and an offline decoder. Loaded into `mitmdump`, it makes the APNs connection work through the proxy and decodes its messages alongside the ordinary HTTPS traffic. Run as a script, it decodes saved captures. It needs only the Python standard library (plus `mitmproxy` for the addon).
- **[A report](report/apns_report.pdf)** describing the interception setup, the message format, and what the messages contain: the handset's push token and device certificate, the handset's public IP address echoed back by the server, and hashes of the topics (services and apps) for which the handset wants notifications.

Related repositories:

- [ios-protobuf-decoding](https://github.com/doug-leith/ios-protobuf-decoding) decodes the rest of an iPhone's traffic to Apple (binary protobufs, Siri, tiles and more). Its `ios_decoder` includes the same `apns_mitm.py` and decodes APNs connections in a capture together with everything else.
- [poor-privacy-practices-of-the-apple-app-store](https://github.com/doug-leith/poor-privacy-practices-of-the-apple-app-store) has the SSL Kill Switch tweak used to bypass certificate checks on the handset, in a version fixed so that it no longer breaks APNs (`ssl-kill-switch3-DL`), and the report [Device And User Identifiers In iPhone Network Traffic](https://github.com/doug-leith/poor-privacy-practices-of-the-apple-app-store/blob/main/iphone_identifiers.pdf), which describes how the push token and device certificate relate to the handset's other identifiers.

## Quick start

Clone this repository and install into a virtual environment (Python 3.12 or later):

```sh
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

To test the installation, decode the example capture:

```sh
./venv/bin/python3 apns_mitm.py examples/example.mitm | diff - examples/example_output.txt
```

No output from `diff` means the decoded output matches `examples/example_output.txt`. The capture holds one APNs connection as `mitmdump` records it with the addon, with the messages an iPhone exchanges when it connects. It is synthetic: the messages use the real wire format and field numbers, but the values are made up (see [`examples/make_example_capture.py`](examples/make_example_capture.py), which rebuilds both files).

## What is in this repository

| Path | Contents |
|---|---|
| [`apns_mitm.py`](apns_mitm.py) | The `mitmproxy` addon and the decoder. `python apns_mitm.py --help` describes both. |
| `tests/` | Tests, on synthetic data. |
| `examples/` | The example capture, its expected output, and the script that builds them. |
| [`report/`](report/apns_report.pdf) | The report (`apns_report.pdf`), its source (`apns_report.md`, figures and LaTeX build). |

## Capturing APNs traffic

The handset must route its traffic through `mitmdump` running as a transparent proxy, and the handset's system processes must accept `mitmproxy`'s certificate. In our measurements an iPhone 8 (iOS 16.7.11) was jailbroken with [palera1n](https://palera.in), the `mitmproxy` CA certificate was installed as trusted on the handset, certificate pinning was bypassed with the fixed SSL Kill Switch tweak from the repository above, and a Raspberry Pi acting as the Wi-Fi access point redirected the handset's traffic to `mitmdump`. The unmodified SSL Kill Switch 3 prevents the APNs connection from working at all, with or without a proxy (report, Section 2.3).

Besides the usual redirect of ports 80 and 443, the APNs port must be redirected too, e.g. on a Linux access point with the handset at 192.168.4.54:

```sh
sudo iptables -t nat -A PREROUTING -i wlan0 -s 192.168.4.54 -p tcp --dport 5223 -j REDIRECT --to-ports 8080
```

Then capture as usual, with the addon loaded:

```sh
mitmdump --mode transparent --showhost --ssl-insecure -w capture.mitm -s apns_mitm.py
```

Stop `mitmdump` with Ctrl-C (not `kill -9`), so that the still-open APNs connection is written to the capture. The addon:

- offers Apple only the `apns-security-v3` protocol in the TLS handshake. Apple's servers otherwise answer the handset's other offer, `apns-pack-v1`, with a value the handset never offered, which `mitmproxy` rejects. With this change both ends use the simpler serial encoding.
- decodes each APNs message as it arrives, prints it in the console (byte values shortened), and stores the decoded messages with the connection in `capture.mitm`, where `mitmproxy` can read them without the addon.
- appends the decoded messages and the raw decrypted bytes to `apns_decoded.jsonl` as they arrive. `mitmdump` writes a connection to `capture.mitm` only when it closes, and the APNs connection stays open for hours, so this file is the copy that survives if `mitmdump` stops abruptly. `--set apns_log=FILE` changes its name and `--set apns_log=` turns it off.
- raises `mitmproxy`'s idle timeout from 600 seconds to one hour, unless set explicitly with `--set tcp_timeout=N`. The handset sends its first keep-alive after 10 minutes, so with the default `mitmproxy` closes the connection just before it, every 10 minutes.

`--ssl-insecure` stops `mitmproxy` checking Apple's certificates. Some APNs servers have certificates issued under Apple Root CA, which is not in `mitmproxy`'s default list of trusted roots; to keep the check, use `--set ssl_verify_upstream_trusted_ca=BUNDLE.pem` with a file holding [certifi](https://pypi.org/project/certifi/)'s roots plus [Apple Root CA](https://www.apple.com/certificateauthority/) instead.

## Reading a capture

```sh
# The APNs connections in a capture, values shortened
./venv/bin/python3 apns_mitm.py capture.mitm

# The same, with values in full
./venv/bin/python3 apns_mitm.py capture.mitm --full

# From the addon's log (e.g. if mitmdump was killed); needs no mitmproxy
./venv/bin/python3 apns_mitm.py --jsonl apns_decoded.jsonl

# Through mitmdump itself, which replays the capture through the addon
mitmdump -n --set flow_detail=0 -r capture.mitm -s apns_mitm.py
```

In Python, the decoded messages are in the metadata of each APNs connection:

```python
from mitmproxy import io, tcp
for f in io.FlowReader(open("capture.mitm", "rb")).stream():
    if isinstance(f, tcp.TCPFlow) and "apns" in f.metadata:
        for m in f.metadata["apns"]["messages"]:
            print(m["dir"], m["name"], [(x["name"], x["value"]) for x in m["fields"]])
```

## Decoded examples

### The example capture

```sh
./venv/bin/python3 apns_mitm.py examples/example.mitm
```

prints one line per message, `->` from the handset and `<-` from the server, with the time stamp of the TCP data that completed it:

```
== flow 00000000-0000-4000-8000-000000000001 ('17.57.146.13', 5223) sni=courier2.push.apple.com alpn=b'' -> serial
   1767225600.100 -> Connect(0x07) Token=1011...2e2f (32B), State=1, Flags=618, Interface=1, ActiveInterval=5, Carrier=WiFi, SoftwareVersion=16.7.11, SoftwareBuild=20H360, HardwareVersion=iPhone10,1, Certificate=706c...5229 (44B), Nonce=0000...0000 (17B), Signature=0101...0000 (130B), ProtocolVersion=10, RedirectCount=0
   1767225600.150 <- ConnectResponse(0x08) ConnectedResponse=0, MessageSize=5120, Capabilities=3, LargeMessageSize=51200, ServerTime=1767225600150, GeoRegion=US, ClientIPAddress=c0...01 (4B)
   1767225600.180 -> Filter(0x09) Token=1011...2e2f (32B), EnabledTopicHash=3c92...4cd2 (20B), EnabledTopicHash=79af...8f1a (20B), EnabledTopicHash=4137...886d (20B), OpportunisticTopicHash=2038...88d0 (20B)
   1767225600.180 -> PresenceTracking(0x20) MessageID=1, PushToken=1011...2e2f (32B), Salt=81...95, TrackingFlag=0, Timestamp=1767225600200
   1767225600.180 -> KeepAlive(0x0c) Carrier=WiFi, SoftwareVersion=16.7.11, SoftwareBuild=20H360, HardwareVersion=iPhone10,1, KeepAliveInterval=10, DelayedResponseInterval=600, State=4, SubState=4
   1767225600.200 <- PresenceTracking(0x20) PresenceActivityMessageID=1, PresenceActivityPushToken=1011...2e2f (32B), PresenceActivityStatus=0
   1767225600.200 <- KeepAliveAck(0x16)
```

The Connect message identifies the handset by its push token and authenticates it with the device certificate that Apple issued at activation, a nonce and a signature of the nonce. The ConnectResponse echoes the handset's public IP address (`ClientIPAddress`, here 192.0.2.1) and a region code. The Filter message lists SHA-1 hashes of the push topics; here, for example, `3c92...4cd2` is the hash of `com.apple.passd` (Wallet). With `--full` every value is printed in full.

### A real session

The start of a session from our iPhone 8 through `mitmdump` (from the report, Figure 2; identifier values shortened):

```
-> Connect(0x07) Token=e30e...45f8 (32B), State=1, Flags=618, Interface=1, ActiveInterval=5, Carrier=WiFi, SoftwareVersion=16.7.11, SoftwareBuild=20H360, HardwareVersion=iPhone10,1, Certificate=3082...33fe (759B), Nonce=0000...d050 (17B), Signature=0101...0c2a (130B), ProtocolVersion=10, RedirectCount=0, TCPHandshakeTimeMs=2, DNSResolveTimeMs=28, TLSHandshakeTimeMs=147, ...
<- ConnectResponse(0x08) ConnectedResponse=0, MessageSize=5120, attr5=000a (2B), Capabilities=3, LargeMessageSize=51200, ServerTime=1792242105031, GeoRegion=IE, attr12=0000...3ac7 (8B), ClientIPAddress=c1...92 (4B)
-> Filter(0x09) Token=e30e...45f8 (32B), EnabledTopicHash=3e86...bde9 (20B), EnabledTopicHash=7429...423f (20B), ... (92 topic hashes)
-> PubSub(0x1d) PubSubMessageID=2, ChannelListPayload=0801...1801 (997B), BaseToken=e30e...45f8 (32B)
-> PresenceTracking(0x20) MessageID=10695208, PushToken=e30e...45f8 (32B), Salt=61...52, TrackingFlag=0, Timestamp=1792242105042
-> KeepAlive(0x0c) Carrier=WiFi, SoftwareVersion=16.7.11, SoftwareBuild=20H360, HardwareVersion=iPhone10,1, KeepAliveInterval=10, DelayedResponseInterval=600, State=4, SubState=4
<- PubSub(0x1d) PubSubMessageID=2, PubSubToken=e30e...45f8 (32B), PubSubStatus=0
<- PresenceTracking(0x20) PresenceActivityMessageID=10695208, PresenceActivityPushToken=e30e...45f8 (32B), PresenceActivityStatus=0
<- KeepAliveAck(0x16)
```

Fields that `apsd`, the iOS daemon that manages the connection, has no name for are shown by number (`attr5`, `attr12`). The report describes each message and field, and Appendix B lists every field number.

### The addon's log

`apns_decoded.jsonl` has one JSON object per line. A `flow` record starts each connection, a `raw` record holds each chunk of decrypted bytes (shortened here), and a `message` record holds each decoded message:

```json
{"kind": "flow", "flow": "00000000-0000-4000-8000-000000000001", "t": 1767225600.0, "server": ["17.57.146.13", 5223], "sni": "courier2.push.apple.com", "alpn": "", "framing": "serial", "tables": [0, 0]}
{"kind": "raw", "flow": "00000000-0000-4000-8000-000000000001", "dir": "s2c", "t": 1767225600.15, "hex": "080000002c010001000400021400060004000000..."}
{"kind": "message", "flow": "00000000-0000-4000-8000-000000000001", "server": ["17.57.146.13", 5223], "dir": "s2c", "cmd": 8, "name": "ConnectResponse", "len": 49, "t": 1767225600.15, "fields": [{"attr": 1, "name": "ConnectedResponse", "type": "uint", "how": "literal", "value": 0}, {"attr": 4, "name": "MessageSize", "type": "uint", "how": "literal", "value": 5120}, ...]}
```

The log holds values in full; only the console output is shortened.

## Tests

```sh
./venv/bin/python3 -m pytest
```

The tests use synthetic data only. They cover the decoder (both encodings, the packed encoding's tables, field names, shortening), the addon (its records, the protocol and timeout changes) and the command line. Two tests of the `ios_decoder` integration are skipped here; they run in the [ios-protobuf-decoding](https://github.com/doug-leith/ios-protobuf-decoding) repository.

## The report

[`report/apns_report.pdf`](report/apns_report.pdf) is built from `report/apns_report.md` with pandoc and LaTeX (the ACM `acmart` class):

```sh
cd report/latex && ./build.sh
```

The field-number table in Appendix B is generated from `apns_mitm.py` during the build, so it always matches the decoder.

## Limitations

The decoder and the report are based on one handset, an iPhone 8 with iOS 16.7.11. No push notification arrived during our captures, so the fields of the PushNotification message come from `apsd`'s code rather than from observed messages. Through `mitmdump` the connection uses the serial encoding; the packed encoding, used on direct connections, is decoded too but was checked only against messages recorded inside `apsd` and against `apsd`'s own encoder.

## Provenance

This repository was created as a snapshot of files from a larger private research repository, and starts with no history. `apns_mitm.py` is also maintained as `ios_decoder/apns_mitm.py` in [ios-protobuf-decoding](https://github.com/doug-leith/ios-protobuf-decoding). As the report's "Use Of AI" section describes, the code and the report were drafted by Claude (Anthropic), working in Claude Code under the author's direction.
