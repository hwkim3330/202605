# Ethernet Packet Lab

KETI two-node Ethernet packet lab for direct cable, FPGA, PHY, or isolated switch tests.

A functional packet generator + receiver + analyser. Use it to prove packet fields, forwarding, filtering, VLAN/PCP handling, payload integrity, and basic periodic / TSN traffic before moving to dedicated line-rate equipment.

---

## Prerequisites

| | Required |
|---|---|
| OS | Linux (any modern distribution). Uses `AF_PACKET` raw sockets — macOS / Windows are not supported. |
| Node.js | **18 or newer** (server uses native `fetch` + `ReadableStream` for the live capture stream). |
| Python | **3.10 or newer** (agent uses PEP 604 union types and `time.time_ns`). |
| iproute2 | `ip(8)` is used by the agent to enumerate interfaces. |
| Privileges | The runner uses `sudo` because raw Ethernet send/capture needs `CAP_NET_RAW`. |
| Browser | Any modern Chromium / Firefox / Safari (uses `fetch` + `ReadableStream` reader). |

Install on Ubuntu / Debian:

```bash
# Node.js 22 (or 18+):
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs python3 iproute2
```

`./install-lab.sh` checks every prerequisite explicitly and refuses to continue if anything is below the minimum.

---

## Install

On **both PCs** (the lab is two-PC by design):

```bash
git clone https://github.com/hwkim3330/202605.git
cd 202605
./install-lab.sh
```

The installer:

1. Verifies Linux + Node 18+ + Python 3.10+ + iproute2.
2. Runs `npm install` (no native modules — pure JS).
3. Marks the helper scripts executable.
4. Runs `npm run check` to syntax-check `server.js` and `public/app.js`.

---

## Run

On both PCs:

```bash
./run-lab.sh
```

Open locally in the browser:

```
http://localhost:8080
```

`run-lab.sh` re-execs itself with `sudo` because raw socket operations require root. It also:

- Refuses to start if port `8080` is already in use (avoids zombie servers).
- Honours `PORT=...` env var if you need a different port.
- Forwards Node's `node` binary path through `sudo` so it works under nvm.

---

## Two-PC topology

```
┌──────────────┐                                    ┌──────────────┐
│   PC A       │   direct cable / lab switch        │   PC B       │
│              │    (raw Ethernet, link-local       │              │
│  enxXXXX     ├──────────  169.254.x.x  ───────────┤  enxYYYY     │
│              │                                    │              │
└──────┬───────┘                                    └──────┬───────┘
       │ ./run-lab.sh                                      │ ./run-lab.sh
       │ http://localhost:8080  ←  controls PC A           │ http://localhost:8080  ←  controls PC B
       │                                                   │
       │  Pin Peer URL: http://<PC_B_IP>:8080  ─ ─ ─ ─ ─→ │  (or vice versa)
       └───────────────────────────────────────────────────┘
                       (peer probe / E2E)
```

Each browser controls **only the PC running its own server**. Cross-control happens through the pinned Peer URL — the local server uses HTTP to ask the peer's server to capture or send. The data plane (the actual frames) goes over the direct Ethernet link, not over HTTP.

Both PCs must allow TCP `8080` from the link-local network. If the peer probe times out, check cable / link state, the `169.254.x.x/16` address, firewall policy, and whether `./run-lab.sh` is still running on the peer.

---

## Update

```bash
cd 202605
./update-lab.sh
./run-lab.sh   # restart
```

`update-lab.sh` does `git pull --ff-only` + `npm install` + `npm run check`.

---

## Tabs at a glance

| Tab | What it does |
|---|---|
| **Sender** | Build any frame (Ethernet II / ARP / IPv4·UDP / IPv4·ICMP / Raw EtherType / 802.1Q) and transmit it. Auto-rebuilds the Frame Details + Frame Bytes preview on every edit (no need to click Refresh). The bottom `Packet List` is a sequence builder: click rows to load, edit inline, save as JSON, replay with `Send List` / `Send Selected`. |
| **Capture** | Wireshark-style live packet list streamed from the agent over NDJSON. Start / Stop / Clear, auto-scroll, `pkts / pps / bytes / capturing-elapsed` chips, protocol-tinted rows. Click any row → decoded JSON + hex panes split below. Display filter accepts `tcp / udp / icmp / icmpv6 / arp / vlan / ipv4 / ipv6 / lldp / ptp / lacp / dns / dhcp / ntp / mdns` plus `mac:<substr> / ip:<substr> / port:<n>` and free-text. |
| **Control** | Four action cards driven by the pinned peer pair: <br>• **Wire Validation** — run the standard suite (ARP / ICMP / UDP / payload patterns / frame-size 64..1514 / VLAN+PCP) on the wire and prove every step round-trips. <br>• **E2E** — burst the currently selected Sender profile across the link (default 5 packets at 200 ms). <br>• **Benchmark** — timestamped UDP stream → throughput, p50/p95/p99 latency (clock-skew adjusted), jitter, loss. <br>• **Frame-size sweep** — same benchmark across 64..1514 B with a 4-chart Chart.js report (under 10 s for 7 sizes at count=200). |
| **Serial** | TeraTerm-style USB / TTY console. Lists `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyAMA*`, `/dev/ttymxc*`, `/dev/ttyTHS*` with USB vendor / product / serial when available. Pick a port, baud (300..3 000 000), data bits, parity, stop bits, optional RTS/CTS hardware flow control, and Connect. Live RX is streamed back over NDJSON; `Hex view` toggle shows raw byte dump. Type and press Enter (or paste `\xNN` escapes) — line ending selectable (None / LF / CR / CRLF). Local echo, BRK button, RX/TX byte counters. Pure stdlib termios on the agent side, no `pyserial` dependency. |

---

## Reports

Every Control action persists both JSON and HTML to `reports/`:

- `reports/testcase-latest.{html,json}` — Wire Validation, Packet List runs.
- `reports/e2e-latest.{html,json}` — single-profile E2E.
- `reports/benchmark-latest.{html,json}` — latency CDF + per-packet line + inter-arrival timeline + histogram.
- `reports/sweep-latest.{html,json}` — Tx/Rx Mbps, Loss %, Latency p95, Jitter vs frame size.

The HTML reports are self-contained (Chart.js loaded from CDN) and safe to copy off the lab PC for sharing.

---

## Manual CLI usage

The Python agent works on its own:

```bash
# Build one example frame, no root needed:
python3 tools/packet_agent.py build < examples/03_udp_unicast_basic.json

# Capture (root):
sudo python3 tools/packet_agent.py capture <<'JSON'
{"interface":"eth0","timeoutSec":10,"maxFrames":10}
JSON

# Send:
sudo python3 tools/packet_agent.py send < examples/03_udp_unicast_basic.json
```

---

## Built-in profiles

`examples/` ships 27 profiles, grouped:

1. **Basic** — ARP, ICMP, UDP unicast.
2. **Integrity** — UDP sequence, AA55 pattern, counter.
3. **Size Sweep** — 64 / 128 / 256 / 512 / 1024 / 1514 / MTU edge.
4. **VLAN / PCP** — VLAN 10 PCP 0, VLAN 10 PCP 7, VLAN 20 isolation.
5. **Switching** — unknown unicast, L2 multicast, broadcast storm guard.
6. **ACL Policy** — ACL UDP block candidate.
7. **TSN Prep** — periodic UDP 1 ms.
8. **TSN** — PSFP Stream A/B, sub-ms periodic jitter.
9. **Performance** — latency benchmark, mixed-PCP burst.

`testprofiles/` ships 5 standard suites for the Packet List sequence builder (RFC core, payload integrity, IEEE 802.1Q, switching/policy, TSN-prep).

See [docs/packet-test-plan.md](docs/packet-test-plan.md) for the recommended end-to-end order.

---

## Standards coverage

| Standard | Coverage |
|---|---|
| **RFC 2544** §26 Throughput | Binary-search throughput discovery per frame size (64 / 128 / 256 / 512 / 1024 / 1280 / 1518) — Control card "RFC 2544 throughput". Configurable trial duration, tolerance, and link-rate baseline. Quick-mode (1–2 s trials) for feedback; raise to 60 s for the formal RFC numbers. |
| **RFC 2544** §26.2 Latency | Per-iteration latency p50 / p95 / p99 + jitter (mean \|Δlatency\|), clock-skew adjusted. Recorded inside the RFC 2544 report as well as the standalone Benchmark card. |
| **RFC 2544** §26.3 Frame loss rate | Recorded per binary-search iteration (the loss column in the per-size detail tables). |
| **RFC 4814** payload patterns | Constant byte (`repeat` mode), counter (`counter` mode), pseudorandom (`random` mode), KETI benchmark marker (`benchmark` mode), and **PRBS-7 / 15 / 23 / 31** (`prbs` mode) generated from a polynomial LFSR — receiver can re-generate the same sequence from `seed` + `order` to do a cleartext BERT comparison. |
| **RFC 5180** IPv6 benchmarking | IPv6 + UDP / TCP / ICMPv6 frame **build and decode**. Set `protocol:"udp"` (or `"tcp"`) plus `ipv6:{src,dst,hopLimit}` instead of `ipv4`. |
| **RFC 793 / 9293** TCP | TCP frame build with full flag bits (NS / CWR / ECE / URG / ACK / PSH / RST / SYN / FIN), seq, ack, window, checksum (over IPv4 or IPv6 pseudo-header). |
| **IEEE 802.1Q** | 802.1Q tagging (TPID / PCP / DEI / VID), and **Q-in-Q** (`0x88a8` outer + `0x8100` inner) decoded into `vlan` + `vlanInner`. |
| **IEEE 802.3** clauses | Frame-size sweep plus the RFC 2544 1518 B size; minimum-frame padding to 60 B; configurable target frame length. AF_PACKET frames omit the 4-byte FCS, so a wire-side 1518 B frame appears as 1514 B in our buffers. |
| **IEEE 1588 / PTP** | EtherType 0x88f7 message-type decode (Sync / Follow_Up / Delay_Req·Resp / Pdelay_Req·Resp(_FU) / Announce / Signaling / Management). Generation of arbitrary 0x88f7 frames via raw-EtherType profile. |
| **LLDP** (IEEE 802.1AB) | Decoder walks every TLV (Chassis ID / Port ID / TTL / Port·System Name·Description / Org-specific). |
| **LACP** (IEEE 802.1AX) | Top-level decode marker. |

Not covered (out of scope for usermode AF_PACKET):

- RFC 2544 §26.4 back-to-back (needs hardware-precise IFG).
- ITU-T Y.1564 Service Activation (needs CIR/EIR shaping).
- Hardware-timestamped one-way latency (needs PTP-disciplined NIC). The benchmark uses NTP-disciplined wall-clock with `latencyAdjustedUs` (min normalised to 0) for meaningful skew-free distribution.

## Architecture

```
                ┌────────────────────────────────────┐
   browser  ←→  │ server.js  (Node 18+)              │
   (this PC)    │  • static UI + JSON API            │
                │  • /api/build /send /capture       │
                │  • /api/capture-stream  (NDJSON)   │
                │  • /api/benchmark /sweep           │
                │  • /api/wire-validation            │
                │  • /api/run-test-case              │
                │  • /api/probe-node  (peer pair)    │
                └─────────────┬──────────────────────┘
                              │  spawn python3
                              ▼
                ┌────────────────────────────────────┐
                │ tools/packet_agent.py              │
                │  • AF_PACKET SOCK_RAW              │
                │  • build_frame / decode_frame      │
                │    Ethernet, 802.1Q, Q-in-Q,       │
                │    IPv4, IPv6, ARP,                │
                │    UDP, TCP, ICMP, ICMPv6,         │
                │    LLDP, PTP, LACP                 │
                └────────────────────────────────────┘
```

Node owns the UI and orchestration. Python owns the privileged raw-socket work. This avoids fragile Node native packet addons while using standard Linux raw sockets and the kernel's IPv4/IPv6 stack.

When the Control page asks for an on-the-wire test, the local Node calls the peer's `/api/capture` over HTTP and its own `/api/send` in parallel. Frames travel on the Ethernet link; only orchestration uses HTTP.

---

## Troubleshooting

**`raw socket permission denied`** → not running with sudo. `./run-lab.sh` does this automatically; if you're testing the agent manually, prefix with `sudo`.

**`Port 8080 already in use`** → an old run-lab is still alive. `sudo pkill -f 'node .*server.js'` then restart.

**Capture starts but `pkts=0`** → traffic is reaching the wire but the Capture display filter is non-empty. Click `Clear`, blank the display filter, and the auto-fill of advanced pre-decode filters in `Capture filters` should also be empty (we no longer auto-write them).

**`Wire Validation` fails on VLAN tests only** → the receiver NIC's `rxvlan` offload is stripping the 4-byte 802.1Q tag from the captured buffer. The matcher already accepts the stripped variant, but if your driver mangles it differently, disable offload:

```bash
sudo ethtool -K <iface> rxvlan off txvlan off
```

**Peer probe fails** → check both PCs have `./run-lab.sh` running, the peer URL is reachable (`curl http://PEER:8080/api/interfaces`), and the firewall allows TCP 8080 inbound.

**Two PCs see no traffic from each other** → confirm the link is up (`ip -br link`), addresses are in the same `/16` (typically `169.254.x.x/16` for link-local), and you've picked the right NIC in the Interface dropdown of both browsers.

**Long benchmark takes too long** → the receiver capture used to wait the full safety timeout. As of recent commits, `maxFrames=count` makes it exit immediately when all expected frames arrive (~1.2 s + count·interval_ms per slot).

**`./install-lab.sh` says python is too old** → install Python 3.10+. On Ubuntu 22.04 it's the default; on older distros use `sudo apt install python3.11` and either symlink or set `PY=python3.11` and re-run.

**Browser shows old UI after update** → hard refresh (Ctrl+F5). The static handler serves the latest files; only the browser cache is stale.

---

## Notes

- Use an isolated lab interface. Broadcast ARP, unknown unicast, multicast, and VLAN-tagged frames *will* affect other devices on the same segment.
- `AF_PACKET` frames do not include the Ethernet FCS. A 1514-byte untagged frame here corresponds to 1518 bytes on the wire including FCS.
- The benchmark's absolute one-way latency depends on NTP sync between the two PCs (typically only ms-accurate). For meaningful comparisons we always show `latencyAdjustedUs` — the raw distribution shifted so its minimum is 0. Jitter and loss are unaffected.
- Headless Chrome / Selenium friendly: `?#capture`, `?#sender`, `?#control` URL hashes activate the right tab on first paint, and `?autoStart=1#capture` auto-clicks Start for live tests.
