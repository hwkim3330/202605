# Two-node Ethernet test

## Topology

Use a direct cable or a switch between two Linux machines.

- PC A: sender, example IP `192.168.100.10/24`
- PC B: receiver, example IP `192.168.100.20/24`

Raw Ethernet send/capture requires `CAP_NET_RAW`. Running the server with `sudo` is simplest during lab work.

## Run

On both PCs:

```bash
git clone https://github.com/hwkim3330/202605.git
cd 202605
./run-lab.sh
```

Manual start for actual send/capture:

```bash
sudo env PATH="$PATH" npm start
```

Open `http://<pc-ip>:8080`.

If PC B is connected to PC A's USB/Ethernet interface, use the IP assigned to that interface. Link-local addresses usually look like `169.254.x.x`.

## Receiver flow

1. Select the test interface.
2. Open `Capture`.
3. Keep filters empty for the first test.
4. Press `Start Capture`.

The default UI leaves receive filters empty so broadcast and unknown-destination tests are visible. Add Source MAC, Destination MAC, or EtherType filters only when the capture stream is too noisy.

## Sender flow

1. Select the test interface.
2. Open `Sender`.
3. Choose a Test Profile, starting with ARP, ICMP, then UDP.
4. Set Destination MAC/IP and Source MAC/IP.
5. Press `Preview Frame` if you want to inspect bytes.
6. Press `Send Packet`.

## CLI examples

Build a frame without root:

```bash
python3 tools/packet_agent.py build < examples/03_udp_unicast_basic.json
```

Capture with root:

```bash
sudo python3 tools/packet_agent.py capture <<'JSON'
{"interface":"eth0","timeoutSec":10,"maxFrames":10}
JSON
```

Send with root:

```bash
sudo python3 tools/packet_agent.py send < examples/03_udp_unicast_basic.json
```
