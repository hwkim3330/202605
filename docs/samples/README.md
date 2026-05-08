# Sample reports + machine-readable test data

Real reports captured against a live two-PC link
(`enxc84d44263ba6` ↔ `enxc84d4420405b`, both on `169.254.x.x/16`,
direct cable).

Each test action ships **two artefacts**:

- `NN_*.html` — self-contained Chart.js page that opens straight in any
  browser. Use this to *see* the result.
- `NN_*.json` — the same data in machine form. Use this to diff between
  runs, regression-test, or feed downstream tooling.

When you click **Run** on the corresponding Control card, the live server
writes the same files into `reports/` (gitignored). The samples here are
the latest checked-in snapshots.

---

## Index

| # | Action | HTML | JSON | What it shows |
|---|--------|------|------|---------------|
| 1 | Validation (offline build)  | [01_validation-offline.html](01_validation-offline.html)        | [01_validation-offline.json](01_validation-offline.json)        | All 27 example profiles built and decoded locally — no traffic on the wire. |
| 2 | Wire Validation              | [02_wire-validation.html](02_wire-validation.html)              | [02_wire-validation.json](02_wire-validation.json)              | Sender pushes ARP / ICMP / UDP / payload patterns / 64..1514 sizes / VLAN+PCP across the link, receiver matches. |
| 3 | E2E (single profile)         | [03_e2e.html](03_e2e.html)                                      | [03_e2e.json](03_e2e.json)                                      | One profile (sequence-payload UDP burst) matched on the receiver. |
| 4 | Benchmark                    | [04_benchmark.html](04_benchmark.html)                          | [04_benchmark.json](04_benchmark.json)                          | 500 timestamped UDP packets at 1 ms cadence — latency CDF + per-packet + inter-arrival timeline + histogram. JSON trimmed to the first 100 sample points. |
| 5 | Frame-size sweep             | [05_frame-size-sweep.html](05_frame-size-sweep.html)            | [05_frame-size-sweep.json](05_frame-size-sweep.json)            | 64 / 128 / 256 / 512 / 1024 / 1280 / 1514 B benchmarks chained. |
| 6 | RFC 2544 throughput          | [06_rfc2544-throughput.html](06_rfc2544-throughput.html)        | [06_rfc2544-throughput.json](06_rfc2544-throughput.json)        | Binary-search loss-free fps at the seven RFC 2544 sizes. |

## Sample PCAP

[`pcaps/sample-mixed-traffic.pcap`](pcaps/sample-mixed-traffic.pcap) — 14
frames of mixed UDP / ARP / ICMP traffic captured from the live link,
saved in libpcap format. Open in Wireshark / tcpdump:

```
$ capinfos pcaps/sample-mixed-traffic.pcap | head
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Number of packets:   14
$ tcpdump -r pcaps/sample-mixed-traffic.pcap -nn
```

This is exactly the file format the **`↓ .pcap`** button in the Capture
tab produces.

---

## Latest numbers from these samples

- **01 validation (offline build)** — 27/27 pass, 0 fail
- **02 wire validation** — 30/30 matched, failed=0, ok=true
- **03 e2e** — 8/8 matched
- **04 benchmark** — 500 / 500 received, **0% loss**, 0.63 Mbps (count=500 at 1 ms),
  p50 125 µs · p95 233 µs · jitter 33 µs (clock-skew adjusted)
- **05 frame-size sweep** — all 7 sizes 200/200, 0% loss, 0.43 → 8.85 Mbps
  monotonic with frame size
- **06 RFC 2544 throughput** — quick mode (1 s trials, 1 Gbps link, ±500 fps tolerance):

  | Wire size | Theoretical fps | Loss-free fps | Util % | Mbps  |
  |---:|---:|---:|---:|---:|
  |   64 | 1,488,095 |  5,484 |  0.37 |  2.03 |
  |  128 |   844,594 | 14,546 |  1.72 |  7.82 |
  |  256 |   452,898 | 14,546 |  3.21 | 13.41 |
  |  512 |   234,962 | 14,546 |  6.19 | 21.44 |
  | 1024 |   119,731 | 14,546 | 12.15 | 30.54 |
  | 1280 |    96,153 | 14,546 | 15.13 | 32.48 |
  | 1518 |    81,274 |  6,843 |  8.42 | 27.77 |

> The numbers reflect a **Python-userland AF_PACKET sender** (~14.5 kfps cap
> on this lab CPU). For real RFC 2544 line-rate measurements use a
> hardware traffic generator — this lab is for *functional* validation,
> not line-rate.

## Refresh procedure

```bash
# from a freshly run lab with a live peer:
cd reports
cp latest.{html,json}              ../docs/samples/01_validation-offline.{html,json}
cp testcase-latest.{html,json}     ../docs/samples/02_wire-validation.{html,json}
cp e2e-latest.{html,json}          ../docs/samples/03_e2e.{html,json}
cp benchmark-latest.{html,json}    ../docs/samples/04_benchmark.{html,json}
cp sweep-latest.{html,json}        ../docs/samples/05_frame-size-sweep.{html,json}
cp rfc2544-latest.{html,json}      ../docs/samples/06_rfc2544-throughput.{html,json}
# trim oversized JSON if needed (benchmark ships ~5000 sample points; 100 is plenty for review)
```
