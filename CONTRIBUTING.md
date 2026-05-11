# Contributing

Welcome. This is a small, focused tool. Contributions that match its
spirit — *honest measurement of a two-PC Ethernet link from usermode* —
are very welcome.

## Quick start for contributors

```bash
git clone https://github.com/hwkim3330/202605.git
cd 202605
./install-lab.sh          # checks prereqs, runs npm install
./run-lab.sh              # starts the server with sudo for CAP_NET_RAW
python3 -m unittest tools.test_packet_agent -v
```

## Code map

| Where | What |
|---|---|
| `server.js`                          | Node.js HTTP server. Static UI + JSON API + two-PC orchestration. No native deps. |
| `tools/packet_agent.py`              | Privileged Python agent. `build` / `send` / `capture` / `capture-stream` / `verify-prbs` over stdio JSON. |
| `tools/serial_agent.py`              | TTY / USB-serial console agent (termios stdlib, no pyserial). |
| `tools/test_packet_agent.py`         | 22 unit + round-trip + PRBS property tests. |
| `public/`                            | Browser UI: `index.html`, `app.js`, `styles.css`, `keti.png`. |
| `examples/*.json`                    | 27 example profiles (ARP / ICMP / UDP / VLAN / TSN / performance). |
| `testprofiles/*.json`                | 5 standard test suites the Packet List can load. |
| `docs/methodology.md`                | What every measurement actually measures. |
| `docs/API.md`                        | HTTP endpoints + Profile / Decoded-frame shapes. |
| `docs/samples/`                      | HTML + JSON + .pcap samples from real runs. |

## Coding style

- **No npm runtime dependencies**. We use Node's standard library only.
  Add one and the install story breaks for offline / restricted labs.
- **Pure Python stdlib** in the agents — no pyserial, no scapy. Keep
  `python3 tools/packet_agent.py build < x.json` working on any
  vanilla Python 3.10+.
- **Two-space indent** for JS/CSS/HTML/JSON, four-space for Python
  (enforced by `.editorconfig`). UTF-8, LF endings, trailing-newline.
- **Inline comments explain *why*, not what.** Code is read more than
  written; favour clarity over cleverness.

## What we accept

- Bug fixes (especially anything you found by actually running the lab).
- New protocol decoders / builders that fit in `tools/packet_agent.py`
  symmetrically (if you can build it, you should be able to decode it).
- Methodology improvements with corresponding `docs/methodology.md`
  updates.
- UI ergonomics, accessibility fixes, keyboard shortcuts.
- Sample reports / pcaps captured against representative gear.

## What's out of scope

See the "What we don't measure (and shouldn't pretend to)" section of
[`docs/methodology.md`](docs/methodology.md). Briefly:

- Anything that needs hardware timestamping for correctness
  (`SO_TIMESTAMPING` HW path).
- Anything that needs DPDK / XDP to go faster than userland AF_PACKET.
- Vendor-specific switch CLI / SNMP / NETCONF integrations — those
  belong in a separate tool, not in the lab core.
- Authentication / multi-tenant features — this is a *lab* tool, not a
  production service.

## Tests

Round-trip property tests are the most valuable kind: they prove
`build_frame` and `decode_frame` are inverses for every field a profile
can carry. If you add a new field, please add a corresponding round-trip
test in `tools/test_packet_agent.py:RoundTripTests`.

```bash
python3 -m unittest tools.test_packet_agent -v
```

## Commit hygiene

- One logical change per commit.
- Subject line ≤ 72 chars, body line-wrapped at ~72.
- Lead the body with *why*, then *how*, then *verification* (the actual
  command output proving it works).
- See `git log --oneline` for the project's existing voice — bug fixes
  describe the user-visible symptom and the root cause, not just the
  patch.

## PRs

Open against `main`. CI (when enabled — see `docs/ci-template.yml`) runs
syntax check + decoder unit tests + every-example build. Fill in the
PR template, especially the verification section.

Thanks.
