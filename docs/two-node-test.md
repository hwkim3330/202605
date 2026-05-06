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
./install-lab.sh
./run-lab.sh
```

Manual start for actual send/capture:

```bash
sudo env PATH="$PATH" npm start
```

Open each PC's own local UI:

```text
PC A -> http://localhost:8080
PC B -> http://localhost:8080
```

Do not open PC A's `:8080` from PC B expecting to control PC B's NIC. The browser talks to the server it opened, and the server controls only its own local interfaces.

Remote URL access is only for intentionally controlling a different lab PC:

```text
http://<lab-pc-ip>:8080
```

## One-screen control

After `./run-lab.sh` is running on both PCs, one browser can orchestrate both nodes.

Example link-local addresses:

```text
PC A sender   http://169.254.5.7:8080
PC B receiver http://169.254.148.199:8080
```

1. Open either UI.
2. Open `Control`.
3. Put PC A's URL in `Sender Node URL`.
4. Put PC B's URL in `Receiver Node URL`.
5. Press `Probe Nodes`.
6. Select the sender interface and receiver interface.
7. Pick the profile and fields in `Sender`.
8. Return to `Control` and press `Run E2E Test`.

The server will start receiver capture first, wait briefly, send from the sender node, then generate:

```text
reports/e2e-latest.html
reports/e2e-latest.json
```

For the user's current link-local setup, start with:

```text
Sender Node URL   http://169.254.5.7:8080
Sender Interface  enxc84d44263ba6
Receiver Node URL http://169.254.148.199:8080
Receiver Interface enxc84d4420405b
```

If `Probe Nodes` fails, verify that both nodes are running, the firewall allows TCP `8080`, and both interfaces have `169.254.x.x/16` addresses.

## Update

On both PCs:

```bash
cd 202605
./update-lab.sh
./run-lab.sh
```

## Receiver flow

1. On the receiver PC itself, open `http://localhost:8080`.
2. Select the receiver test interface.
3. Open `Capture`.
4. Keep filters empty for the first test.
5. Press `Start Capture`.

The default UI leaves receive filters empty so broadcast and unknown-destination tests are visible. Add Source MAC, Destination MAC, or EtherType filters only when the capture stream is too noisy.

## Sender flow

1. On the sender PC itself, open `http://localhost:8080`.
2. Select the sender test interface.
3. Open `Sender`.
4. Choose a Test Profile, starting with ARP, ICMP, then UDP.
5. Set Destination MAC/IP and Source MAC/IP.
6. Press `Preview Frame` if you want to inspect bytes.
7. Press `Send Packet`.

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
