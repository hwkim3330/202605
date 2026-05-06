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
npm start
```

For actual send/capture:

```bash
sudo npm start
```

Open `http://<pc-ip>:8080`.

If PC B is connected to PC A's USB/Ethernet interface, use the IP assigned to that interface. On the current machine this was verified locally on both `172.31.51.213:8080` and `192.168.1.1:8080`.

## Receiver flow

1. Select the test interface.
2. Set Source MAC to the receiver NIC MAC.
3. Press `Capture`.

The default UI leaves receive filters empty so broadcast and unknown-destination tests are visible. Add Source MAC, Destination MAC, or EtherType filters only when the capture stream is too noisy.

## Sender flow

1. Select the test interface.
2. Set Source MAC to the sender NIC MAC.
3. Set Destination MAC to receiver NIC MAC or `ff:ff:ff:ff:ff:ff`.
4. Set Source IP and Destination IP.
5. Press `Build`, then `Send`.

## CLI examples

Build a frame without root:

```bash
python3 tools/packet_agent.py build < examples/udp_profile.json
```

Capture with root:

```bash
sudo python3 tools/packet_agent.py capture <<'JSON'
{"interface":"eth0","timeoutSec":10,"maxFrames":10}
JSON
```

Send with root:

```bash
sudo python3 tools/packet_agent.py send < examples/udp_profile.json
```
