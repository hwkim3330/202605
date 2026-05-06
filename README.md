# Ethernet Packet Lab

KETI two-node Ethernet packet lab for direct cable or isolated switch tests.

The app provides a browser UI for packet transmit, receive capture, frame decode, and hex view. It is designed for Linux lab PCs where crafted Ethernet II frames need to be sent and observed between two machines.

## What it does

- Sends Ethernet II frames from a selected NIC.
- Captures received frames on a selected NIC.
- Builds and decodes Ethernet, 802.1Q VLAN, IPv4, UDP, ICMP Echo, and ARP.
- Shows packet list, protocol details, and hex bytes in a Wireshark-style layout.
- Provides ready-to-run profiles for ARP, ICMP, UDP, payload patterns, size sweep, VLAN/PCP, switching, ACL, and TSN-prep traffic.
- Works over normal LAN IPs or link-local addresses such as `169.254.x.x`.

## Architecture

- `server.js`: Node.js web server and JSON API.
- `tools/packet_agent.py`: Linux `AF_PACKET` raw-socket engine.
- `public/`: browser UI and KETI logo.
- `examples/`: editable packet profiles.
- `docs/two-node-test.md`: two-PC test procedure.
- `docs/packet-test-plan.md`: recommended validation order.

Node handles the UI and API. Python handles the privileged packet work. This avoids fragile Node native packet addons while still using Linux standard raw sockets.

## Install

```bash
git clone https://github.com/hwkim3330/202605.git
cd 202605
npm install
```

## Run

One-command lab start:

```bash
./run-lab.sh
```

Frame preview also works as a normal user:

```bash
npm start
```

Actual send, capture, and discovery need raw-socket permission:

```bash
sudo env PATH="$PATH" npm start
```

If Node was installed with `nvm`, use the full PATH:

```bash
sudo env PATH="$HOME/.nvm/versions/node/v22.19.0/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" npm start
```

Open the UI:

```text
http://localhost:8080
```

From the second PC, open this PC's interface address:

```text
http://<this-pc-ip>:8080
```

For the current link-local setup, the address may look like:

```text
http://169.254.5.7:8080
```

## Lab Flow

The UI is split into two work modes:

- `Sender`: choose UDP, ICMP, ARP, or raw EtherType, then press `Send Packet`.
- `Capture`: set optional MAC/EtherType filters, then press `Start Capture`.

Typical two-PC flow:

1. Select the test interface on both PCs.
2. On the receiver PC, open `Capture` and press `Start Capture`.
3. On the sender PC, open `Sender`, set destination MAC/IP and payload, then press `Send Packet`.
4. Use ARP/ICMP/UDP profiles first, then move to payload, size, VLAN, PCP, and TSN-prep profiles.

`Preview Frame` only generates and decodes the frame locally in the `Sender` view. It does not transmit anything.

The built-in profiles follow this order:

1. Basic: ARP, ICMP, UDP
2. Integrity: sequence, AA55, counter
3. Size sweep: 64, 128, 256, 512, 1024, 1514 bytes without FCS
4. VLAN/PCP: VLAN 10 PCP 0/7 and VLAN 20 isolation
5. Switching/policy/TSN-prep candidates

## Verification

```bash
npm run check
python3 tools/packet_agent.py build < examples/03_udp_unicast_basic.json
```

API checks:

```bash
curl http://127.0.0.1:8080/api/interfaces
curl -X POST http://127.0.0.1:8080/api/build \
  -H 'content-type: application/json' \
  --data-binary @examples/03_udp_unicast_basic.json
```

## Notes

- Use this on an isolated lab interface.
- Broadcast ARP and crafted VLAN traffic can affect other devices on the same segment.
- AF_PACKET frames do not include Ethernet FCS. A `targetFrameLength` of 1514 corresponds to a 1518-byte untagged Ethernet frame on the wire including FCS.
