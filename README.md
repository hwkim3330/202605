# Ethernet Packet Lab

Two-node Ethernet packet experiment tool.

The project uses:

- Node.js HTTP server for the browser UI and API.
- Python Linux `AF_PACKET` raw sockets for Ethernet II frame build/send/capture.
- Standard frame formats: Ethernet II, 802.1Q VLAN, IPv4, UDP, ICMP Echo, ARP.

The old `EthernetPacketGenerator_v1.zip` was Windows WPF/SharpPcap oriented. This repo keeps the protocol idea but moves the lab path to Linux-friendly raw sockets so two PCs can run sender and receiver roles.

## Quick start

```bash
npm start
```

Open:

```text
http://localhost:8080
```

Actual packet send/capture needs raw-socket privileges:

```bash
sudo npm start
```

## Check

```bash
npm run check
python3 tools/packet_agent.py build < examples/udp_profile.json
```

## Files

- `server.js`: dependency-free Node.js web/API server.
- `tools/packet_agent.py`: frame builder, decoder, sender, receiver.
- `public/`: browser UI.
- `examples/`: ready-to-edit UDP, ICMP, ARP profiles.
- `docs/two-node-test.md`: two-PC lab procedure.

## Safety

Run this only on a lab interface or isolated test network. The tool can transmit crafted L2 frames, including broadcast ARP and VLAN-tagged traffic.
