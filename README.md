# Ethernet Packet Lab

KETI two-node Ethernet packet lab for direct cable, FPGA, PHY, or isolated switch tests.

This tool is a functional packet generator and receiver. It is not a line-rate traffic generator. Use it to prove packet fields, forwarding, filtering, VLAN/PCP handling, payload integrity, and basic periodic traffic before moving to dedicated TSN/performance equipment.

## Important Model

Install and run this repository on **both PCs**.

Each browser controls only the machine where its local Node/Python server is running:

```text
PC A: ./run-lab.sh -> open http://localhost:8080 on PC A -> Sender
PC B: ./run-lab.sh -> open http://localhost:8080 on PC B -> Capture
```

If PC B opens `http://PC_A_IP:8080`, it controls PC A's NICs, not PC B's NICs.

## Features

- Sender, Capture, and Control views.
- One-click local profile validation with HTML/JSON report generation.
- Linux `AF_PACKET` raw-socket send/capture engine.
- Ethernet II, 802.1Q VLAN, IPv4, UDP, ICMP Echo, and ARP.
- Wireshark-style packet list, decode panel, and hex panel.
- 27 built-in test profiles:
  - ARP, ICMP, UDP
  - sequence payload
  - AA55 and counter payload patterns
  - 64/128/256/512/1024/1514-byte frame-size tests
  - VLAN 10 PCP 0/7 and VLAN 20 isolation
  - unknown unicast, multicast, ACL candidate
  - periodic UDP and PSFP Stream A/B candidates
  - latency benchmark, sub-ms periodic jitter, mixed-PCP burst, MTU edge, broadcast storm guard
- Performance benchmark mode: embedded sequence + tx timestamp in the UDP payload, capture records ns-precision rx timestamps, and the server computes per-packet latency, inter-arrival, jitter, loss, and throughput.
- Frame-size sweep that runs the benchmark across 64..1514 B and produces a Chart.js report (throughput, loss, latency p95, jitter vs frame size).
- HTML benchmark report with latency CDF, latency-per-packet line, inter-arrival timeline, and latency histogram (Chart.js).

## Install

On both PCs:

```bash
git clone https://github.com/hwkim3330/202605.git
cd 202605
./install-lab.sh
```

## Run

On both PCs:

```bash
./run-lab.sh
```

Open locally on each PC:

```text
http://localhost:8080
```

`run-lab.sh` uses `sudo` because raw Ethernet send/capture requires `CAP_NET_RAW`.

## Update

On both PCs:

```bash
cd 202605
./update-lab.sh
```

Then restart:

```bash
./run-lab.sh
```

## Two-PC Flow

1. Start `./run-lab.sh` on PC A and PC B.
2. On PC B, open `http://localhost:8080`, select the test interface, open `Capture`, and press `Start Capture`.
3. On PC A, open `http://localhost:8080`, select the test interface, open `Sender`, choose a test profile, and press `Send Packet`.
4. Start with ARP, ICMP, and UDP. Then move to payload pattern, size sweep, VLAN/PCP, switching, policy, and TSN-prep profiles.

`Preview Frame` only builds and decodes locally. It does not transmit.

## One-screen Two-node Control

For a direct link or link-local test, run this app on both PCs, then control both nodes from one browser:

```text
Sender PC   http://169.254.5.7:8080
Receiver PC http://169.254.148.199:8080
```

1. Open either PC's UI.
2. Open `Control`.
3. Enter the sender node URL and receiver node URL.
4. Press `Probe Nodes`.
5. Select the sender and receiver test interfaces.
6. Choose the test profile and packet fields in `Sender`.
7. Return to `Control` and press `Run E2E Test`.

The E2E test starts capture on the receiver node, sends the selected profile from the sender node, matches the captured Ethernet frame by source MAC, destination, protocol, VLAN, IP, and UDP/ICMP/ARP fields, then writes:

```text
reports/e2e-latest.html
reports/e2e-latest.json
```

Both PCs must allow TCP `8080` from the link-local network. If a node does not probe, check cable/link state, the `169.254.x.x/16` address, firewall policy, and whether `./run-lab.sh` is still running on that node.

## Wire Validation

Open `Control` and run `Wire Validation`.

This is an on-the-wire standard packet validation. The sender node transmits ARP, ICMP, UDP, payload-pattern, frame-size, VLAN, and PCP test frames while the receiver node captures and matches them. It writes:

```text
reports/testcase-latest.html
reports/testcase-latest.json
```

The older local build/decode check still exists as an internal API, but the Control page validation is now the real link validation.

## Packet List

The Sender screen has a bottom `Packet List`, modeled after `EthernetPacketGenerator_v1.zip`.

A packet list is a JSON test case stored in `testcases/`. It can contain:

- `packet` steps: a complete packet profile plus repeat `count` and `intervalMs`
- `delay` steps: a wait between packet groups
- checked rows for `Send Selected`
- full-list sending with optional repeat loops and cycle period

Typical flow:

1. Configure one packet in `Sender`.
2. Press `+` in `Packet List`.
3. Add delay events where needed.
4. Adjust count/interval in the sequence table.
5. Save the packet list.
6. Probe the peer in the top link strip.
7. Press `Send Selected` or `Send List`.

The runner opens capture on the receiver node, sends each packet step from the sender node in order, then writes:

```text
reports/testcase-latest.html
reports/testcase-latest.json
```

The built-in `testcases/basic-link-bringup.json` covers ARP, UDP sequence payload, and VLAN PCP burst smoke tests.

## Recommended Test Order

See [docs/packet-test-plan.md](docs/packet-test-plan.md).

Short version:

1. Basic: ARP, ICMP, UDP
2. Integrity: sequence, AA55, counter
3. Size sweep: 64, 128, 256, 512, 1024, 1514 bytes without FCS
4. VLAN/PCP: VLAN 10 PCP 0/7 and VLAN 20 isolation
5. Switching/policy/TSN-prep candidates

## Commands

Run checks:

```bash
npm run check
```

Build one example frame without root:

```bash
python3 tools/packet_agent.py build < examples/03_udp_unicast_basic.json
```

Manual capture:

```bash
sudo python3 tools/packet_agent.py capture <<'JSON'
{"interface":"eth0","timeoutSec":10,"maxFrames":10}
JSON
```

Manual send:

```bash
sudo python3 tools/packet_agent.py send < examples/03_udp_unicast_basic.json
```

## Architecture

- `server.js`: Node.js web server and JSON API.
- `tools/packet_agent.py`: Python raw-socket packet engine.
- `public/`: browser UI and KETI logo.
- `examples/`: test profiles.
- `testcases/`: reusable packet-list test cases.
- `docs/`: operating and test-plan documentation.

Node handles UI/API. Python handles privileged packet work. This avoids fragile Node native packet addons while using standard Linux raw sockets.

## Notes

- Use an isolated lab interface.
- Broadcast ARP, unknown unicast, multicast, and VLAN traffic can affect other devices on the same segment.
- `AF_PACKET` frames do not include Ethernet FCS. A 1514-byte untagged frame here corresponds to 1518 bytes on the wire including FCS.
