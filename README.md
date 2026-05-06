# Ethernet Packet Lab

KETI two-node Ethernet packet lab for direct cable or isolated switch tests.

The app provides a browser UI for packet transmit, receive capture, frame decode, hex view, and ARP discovery. It is designed for Linux lab PCs where crafted Ethernet II frames need to be sent and observed between two machines.

## What it does

- Sends Ethernet II frames from a selected NIC.
- Captures received frames on a selected NIC.
- Builds and decodes Ethernet, 802.1Q VLAN, IPv4, UDP, ICMP Echo, and ARP.
- Shows packet list, protocol details, and hex bytes in a Wireshark-style layout.
- Runs ARP discovery and renders discovered hosts with D3.
- Works over normal LAN IPs or link-local addresses such as `169.254.x.x`.

## Architecture

- `server.js`: Node.js web server and JSON API.
- `tools/packet_agent.py`: Linux `AF_PACKET` raw-socket engine.
- `public/`: browser UI and KETI logo.
- `examples/`: editable packet profiles.
- `docs/two-node-test.md`: two-PC test procedure.

Node handles the UI and API. Python handles the privileged packet work. This avoids fragile Node native packet addons while still using Linux standard raw sockets.

## Install

```bash
git clone https://github.com/hwkim3330/202605.git
cd 202605
npm install
```

## Run

Frame preview works as a normal user:

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

1. Select the test interface.
2. On the receiver PC, press `Start Capture`.
3. On the sender PC, choose UDP, ICMP, or ARP.
4. Set destination MAC/IP and payload.
5. Press `Send Packet`.
6. Use `Discover` to find ARP neighbors on the selected link.

`Preview Frame` only generates and decodes the frame locally. It does not transmit anything.

## Verification

```bash
npm run check
python3 tools/packet_agent.py build < examples/udp_profile.json
```

API checks:

```bash
curl http://127.0.0.1:8080/api/interfaces
curl -X POST http://127.0.0.1:8080/api/build \
  -H 'content-type: application/json' \
  --data-binary @examples/udp_profile.json
```

## Notes

- Use this on an isolated lab interface.
- Broadcast ARP and crafted VLAN traffic can affect other devices on the same segment.
- Link-local networks often assign `/16`, but discovery defaults to a local `/24` around the selected IP to keep scans practical.
