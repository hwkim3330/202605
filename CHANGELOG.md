# CHANGELOG

All notable changes to this project, newest first. The format is loosely
inspired by [Keep a Changelog](https://keepachangelog.com/) but groups
by capability rather than strict semver because this is a lab tool, not
a library.

## Unreleased

### Added
- **PCAP-NG export** with full nanosecond timestamp resolution (Section
  Header + Interface Description with `if_tsresol = 9` + Enhanced Packet
  Blocks). The Capture toolbar now offers `↓ .pcap` (legacy, µs) and
  `↓ .pcapng` (modern, ns) side by side. Verified by `file(1)` →
  `pcapng capture file - version 1.0` and `capinfos` →
  `File timestamp precision: nanoseconds (9)`.
- This `CHANGELOG.md`.

## 2026-05 — Major version

### New tabs and surfaces
- **Sender** with auto-rebuilding Frame Details / Bytes preview, profile
  picker, payload modes (text / hex / counter / repeat / sequence /
  random / benchmark / **PRBS-7/15/23/31**), 802.1Q VLAN, frame-length
  targeting, and a bottom **Packet List sequence builder** (save / load
  / replay JSON test cases, two-way bound to the form).
- **Capture** — Wireshark-style live packet list streamed from the agent
  over NDJSON. Sniff-all by default, click-to-decode, layered hex byte
  colouring, display filter (`tcp / udp / icmp[v6] / arp / vlan / ipv6 /
  lldp / ptp / lacp / dns / dhcp / ntp / mdns / tls / vxlan` plus
  `mac:.. / ip:.. / port:..` and free-text), live `pkts / pps / bytes /
  kdrops / capturing-elapsed` chips. Capture file export to **PCAP** and
  **PCAP-NG**.
- **Control** — five action cards driven by the pinned peer pair:
  - Wire Validation (30/30 round-trip on the standard Ethernet suite)
  - E2E single profile burst
  - Benchmark (latency / jitter / loss with KETI marker)
  - Frame-size sweep (4-chart Chart.js report)
  - **RFC 2544 §26 binary-search throughput** (64..1518 wire sizes)
- **Serial** — TeraTerm-style USB-serial console. `/dev/ttyUSB*`,
  `ttyACM*`, `ttyAMA*`, `ttymxc*`, `ttyTHS*` discovered with USB vendor
  metadata. NDJSON RX stream + raw stdin TX, configurable baud (300 –
  3 000 000) / data / parity / stop / RTS-CTS.

### Decoders (build + decode unless noted)
- Ethernet II, 802.1Q, **Q-in-Q** (`0x88a8` outer + `0x8100` inner),
  ARP, LLDP, PTP (over Ethernet 0x88f7), LACP (decode only).
- IPv4 + ICMP (with **inner-packet decode** for ICMP error types).
- **IPv6** + ICMPv6.
- **TCP** with full 9-bit flag set, seq, ack, window, IPv4/IPv6
  pseudo-header checksum.
- UDP, plus port-based heuristics that decode **DNS, DHCP, NTP, mDNS,
  PTP-over-UDP, VXLAN**.
- **TLS ClientHello** sniff over TCP with **SNI extraction**.
- KETI benchmark marker (`KETI` magic + uint32 seq + uint64 ns tx ts) —
  payload mode that lets the receiver match by sequence and compute
  per-packet latency.

### Standards
- **RFC 2544 §26** binary-search throughput per frame size, with
  configurable trial duration and tolerance, results plotted vs
  theoretical line rate.
- **RFC 4814** payloads — constant byte / counter / random / **PRBS**.
- **RFC 5180** IPv6 benchmarking — IPv6 frames build / decode end to
  end.
- **RFC 793 / 9293** TCP frames build / decode end to end.
- **IEEE 802.1Q + Q-in-Q + 1588 PTP + 802.1AB LLDP** — see Standards
  table in README.

### Capture quality
- AF_PACKET via `recvmsg()` with **PACKET_AUXDATA** so VLAN tags
  stripped by the NIC are spliced back into the visible buffer (frame
  hex stays byte-identical to wire).
- Periodic kernel-side **`PACKET_STATISTICS`** events surface drops in
  the UI's `kdrops` chip.
- Streaming endpoint cleans up the python child on every disconnect
  path (`req.close`, `req.aborted`, child exit) — no zombie capture.

### Two-PC orchestration
- Pinned **link strip** at the top of every tab — local NIC ↔ peer NIC,
  click `⇄` to swap roles, `🔒 Locked to peer` auto-binds Sender and
  Capture MAC / IP fields to the active pair.
- `/api/probe-node` walks peer interfaces in one round trip; pair card
  on the Control tab outlines amber when peer is not yet probed so a
  Run click never silently fails.

### Reports
- Self-contained Chart.js HTML reports for every Control action saved
  to `reports/`.
- Six **sample reports** (HTML + JSON + sample .pcap) checked into
  `docs/samples/` so reviewers can see the output without running the
  lab.

### UX polish
- Apple-style transitions on tab change, action cards, hover lift.
- **Toast notifications** with severity bands replace every blocking
  `alert()`.
- **Keyboard shortcuts**: `1/2/3/4` jump tabs; in Capture `S`
  start / stop, `C` clear, `P` save .pcap, `/` focus filter, `Esc`
  stop; in Sender `Ctrl+Enter` send, `Ctrl+S` save list.
- `?` opens a help overlay listing all shortcuts and filter tokens.
- `↻ Refresh preview` button demoted: Sender Frame Details now
  auto-rebuilds (250 ms debounce) on any field change.
- Progress bars with realistic ETAs on every Control action.
- Skew-adjusted latency (min normalised to 0) used in headline metrics
  so unsynchronised wall clocks don't show negative one-way times.

### Robustness / safety
- Server wrapped in last-line `uncaughtException` / `unhandledRejection`
  net; the `createServer` callback is in a try/catch so a single bad
  request can't take the lab down.
- Static handler validates that the resolved path is a regular file
  (no `EISDIR` on directory pipes) and recovers from `new URL()`
  failures on malformed inputs like `//`.
- 32 MB body cap in `readRequestJson()` (DOS protection).
- `/api/send` clamps `count` to [1..1 000 000] and `intervalMs` to
  [0..60 000].
- Browser capture buffer ringed at 50 000 packets (FIFO drop, single
  warn toast) so an overnight capture cannot OOM the tab.
- Run buttons mutex on click + `finally` unlock so a double-click can't
  spawn two concurrent agent pipelines on the same NIC.
- TTY sessions auto-close after 60 s with no subscribers — no zombie
  python serial agents if the browser tab closes mid-session.

### Performance
- Sweep wall-time dropped 60 s → 9 s by setting `maxFrames = count` on
  the receiver agent (the strict `srcMac` filter already isolates our
  flow, so the receiver exits the moment all frames arrive instead of
  riding the full safety timeout).
- RFC 2544 sub-millisecond inter-frame intervals: Python's
  `time.sleep(<1 ms)` rounds up to the scheduler tick, so we use a
  monotonic-time spin/yield wait below 1 ms.

### Tests + CI
- `tools/test_packet_agent.py` — 13 synthetic-frame unit tests covering
  Ethernet basics, 802.1Q + Q-in-Q, IPv4 UDP / TCP-SYN / DNS /
  ICMP-error inner, IPv6 UDP, ARP, LLDP TLVs, PTP Announce, PRBS
  determinism, KETI benchmark marker.
- `docs/ci-template.yml` — three-job GitHub Actions CI (Node + Python
  syntax check, decoder unit tests, every example builds). Move to
  `.github/workflows/ci.yml` to enable on push / PR.

### Documentation
- `README.md` — prerequisites, two-PC topology diagram, per-tab feature
  table, standards-coverage table, troubleshooting section, license,
  documentation index.
- `docs/API.md` — every HTTP endpoint with request / response shapes
  for the Profile and Decoded-frame JSON dialect the agent speaks.
- `docs/samples/README.md` — index of sample reports + headline numbers.
- `LICENSE` — MIT.

### Initial scaffold
- Two-PC Ethernet packet lab. Linux AF_PACKET raw-socket send / capture
  engine. Node.js HTTP server + Python privileged agent, IPC over
  stdio JSON.
- 27 example profiles (ARP / ICMP / UDP / payload patterns / 64..1514
  size sweep / VLAN+PCP / switching / ACL / TSN / performance) plus
  five standard test suites.
