# Ethernet Packet Lab — HTTP API reference

All endpoints are served by `server.js` on `:8080`. Request/response bodies
are JSON unless stated otherwise. Endpoints that drive the local raw socket
agent require the server to have been started under `sudo` (which
`run-lab.sh` does for you).

## Inventory

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/interfaces`        | List local NICs (name, MAC, MTU, link state, IPv4 addresses). |
| GET  | `/api/examples`          | The 27 example profile JSONs from `examples/`. |
| GET  | `/api/test-profiles`     | Standard test suites from `testprofiles/` (Packet-List ready). |
| GET  | `/api/test-cases`        | User-saved Packet-List test cases from `testcases/`. |
| POST | `/api/test-case/save`    | Persist a Packet-List test case. |
| POST | `/api/test-case/delete`  | Delete a saved test case. |
| POST | `/api/build`             | Build (and decode) a frame without sending. |
| POST | `/api/send`              | Transmit a frame on a local interface. |
| POST | `/api/capture`           | Blocking capture (returns all frames at the end). |
| POST | `/api/capture-stream`    | **NDJSON streaming** capture. One JSON event per line. |
| POST | `/api/probe-node`        | Fetch `/api/interfaces` from a peer URL. |
| POST | `/api/e2e-test`          | One-profile send + match on peer. |
| POST | `/api/run-report`        | Offline (build-only) validation across all 27 example profiles. |
| POST | `/api/wire-validation`   | On-wire validation of the standard suite. |
| POST | `/api/run-test-case`     | Run a saved Packet-List test case. |
| POST | `/api/benchmark`         | Timestamped UDP stream benchmark. |
| POST | `/api/sweep`             | Run benchmark across 64..1514 frame sizes. |
| POST | `/api/rfc2544`           | RFC 2544 §26 binary-search throughput per frame size. |
| GET  | `/api/tty/list`          | List `/dev/tty(USB|ACM|AMA|mxc|THS)*` with USB metadata. |
| POST | `/api/tty/open`          | Open a TTY session, returns `sessionId`. |
| GET  | `/api/tty/stream?session=ID` | Long-lived NDJSON stream of RX events. |
| POST | `/api/tty/write`         | Write hex bytes to a TTY session. |
| POST | `/api/tty/control`       | Send `break` / `setRts` / `setDtr`. |
| POST | `/api/tty/close`         | Close a TTY session. |

## Common shapes

### Profile

```json
{
  "interface": "enxXXX",
  "protocol": "udp" | "tcp" | "icmp" | "arp" | "raw",
  "srcMac": "aa:bb:cc:dd:ee:01",
  "dstMac": "aa:bb:cc:dd:ee:02",
  "ipv4":   { "src": "10.0.0.1", "dst": "10.0.0.2", "ttl": 64 },
  "ipv6":   { "src": "2001:db8::1", "dst": "2001:db8::2", "hopLimit": 64 },
  "udp":    { "srcPort": 40000, "dstPort": 50000 },
  "tcp":    { "srcPort": 50000, "dstPort": 80,
              "flags": ["SYN","ACK"], "seq": 0, "ack": 0, "window": 65535 },
  "icmp":   { "type": 8, "code": 0, "id": 1, "seq": 1 },
  "arp":    { "operation": 1, "senderIp": "10.0.0.1", "targetIp": "10.0.0.2" },
  "vlan":   { "enabled": true, "id": 10, "priority": 7, "dei": false },
  "etherType": "0x88b5",
  "payload": {
    "mode": "text" | "hex" | "counter" | "repeat" | "random" | "sequence" | "benchmark" | "prbs",
    "data": "...",         "size": 64,
    "byte": "0xaa",        "template": "SEQ={seq:06d}",
    "start": 1,            "order": 7|15|23|31, "seed": 0x7fffff
  },
  "targetFrameLength": 1514,
  "count": 1,
  "intervalMs": 1000,
  "recordTimestamps": true
}
```

Provide `ipv6` instead of `ipv4` to switch the L3 stack; `protocol` selects
the L4. Only `srcMac`, `dstMac`, `protocol`, and the L3/L4 block matching
that protocol are required.

### Decoded frame

```json
{
  "length": 1514,
  "ethernet": { "dstMac": "...", "srcMac": "...", "etherType": "0x0800" },
  "vlan":     { "tpid": "0x8100", "id": 10, "priority": 7, "dei": false, "etherType": "0x0800" },
  "vlanInner":{ ... },             // present for Q-in-Q (0x88a8 + 0x8100)
  "ipv4":     { "src": "...", "dst": "...", "ttl": 64, "protocol": 17, "totalLength": 1500, "checksumValid": true },
  "ipv6":     { "src": "...", "dst": "...", "hopLimit": 64, "nextHeader": 17, "payloadLength": ..., "trafficClass": 0, "flowLabel": 0 },
  "udp":      { "srcPort": 40000, "dstPort": 50000, "length": ..., "checksum": "0x..." },
  "tcp":      { "srcPort": ..., "dstPort": ..., "seq": ..., "ack": ..., "flags": ["SYN","ACK"], "window": ..., "dataOffset": 20, "checksum": "0x..." },
  "icmp":     { "type": 8, "code": 0, "id": ..., "seq": ..., "checksum": "0x..." },
  "icmpv6":   { "type": ..., "code": ..., "typeName": "Echo Request", "checksum": "0x..." },
  "arp":      { "operation": 1, "senderMac": "...", "senderIp": "...", "targetMac": "...", "targetIp": "..." },
  "lldp":     { "tlvCount": 4, "tlvs": [...] },
  "ptp":      { "messageType": 0, "messageName": "Sync", "version": 2, "domain": 0, "sequenceId": 0, "flags": "0x0000", ... },
  "lacp":     { "raw": "..." },
  "benchmark":{ "seq": 42, "txTimestampNs": 1778053777586316695 } // present when payload.mode=benchmark
}
```

## Streaming endpoints

### `POST /api/capture-stream`

Body: same as `/api/capture` (`interface`, optional `srcMac`/`dstMac`/`etherType` filters, `timeoutSec=0` for run-until-disconnect, `maxFrames=0` for unbounded).

Response: `Content-Type: application/x-ndjson` with one JSON object per line.

```json
{"type":"start","interface":"enxXXX","timestampNs":...}
{"type":"frame","n":1,"timestamp":1778053777.586316,"rxTimestampNs":1778053777586316695,"length":74,"frameHex":"...","hexdump":"...","decoded":{...}}
{"type":"frame","n":2, ...}
{"type":"end","count":N}
```

Closing the HTTP request from the client side SIGTERMs the agent immediately
(no zombie capture). The browser can use `fetch()` + `body.getReader()` to
consume frames live.

### `POST /api/tty/open` + `GET /api/tty/stream?session=ID`

`open` body:

```json
{ "path": "/dev/ttyUSB0", "baudRate": 115200,
  "dataBits": 8, "parity": "N", "stopBits": 1, "hwFlow": false }
```

Returns `{ ok: true, sessionId: "1" }`.

The stream NDJSON emits:

```json
{"type":"open","path":"/dev/ttyUSB0","baudRate":115200}
{"type":"rx","hex":"6f6b0d0a","len":4}
{"type":"error","message":"..."}
{"type":"closed"}
```

Multiple browsers can subscribe to the same `sessionId`; all subscribers
receive the same RX events. Write back via `POST /api/tty/write`:

```json
{ "sessionId": "1", "hex": "0a" }
```

## Reports

The benchmark / sweep / RFC 2544 / wire-validation endpoints all persist both
JSON and HTML to `reports/<name>-latest.{json,html}`. The HTML reports are
self-contained (Chart.js loaded from CDN). See [`samples/`](samples/) for
checked-in examples.
