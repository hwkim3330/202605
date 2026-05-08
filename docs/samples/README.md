# Sample reports

Real reports captured against a live two-PC link
(`enxc84d44263ba6` ↔ `enxc84d4420405b`, both 169.254.x.x/16,
direct cable).
Each file is a self-contained HTML page that opens straight in any browser
(Chart.js is loaded from CDN). The exact same files land in
`reports/` when you click **Run** on the corresponding Control card; the
samples here are checked into git as a reference.

| # | File | Action that produced it | What it shows |
|---|------|-------------------------|---------------|
| 1 | [`01_validation-offline.html`](01_validation-offline.html)        | `Run` on the **(legacy) offline build check** | All 27 example profiles built and decoded locally, one row per profile. PASS / FAIL by structural validity only — no traffic on the wire. |
| 2 | [`02_wire-validation.html`](02_wire-validation.html)              | Control → **Wire Validation** | Sender pushes ARP / ICMP / UDP / payload patterns / 64..1514 sizes / VLAN+PCP across the link, receiver captures, server matches by MAC + frame hex. 30/30 pass on this run. |
| 3 | [`03_e2e.html`](03_e2e.html)                                      | Control → **E2E (single profile)** | One profile (sequence-payload UDP burst) matched on the receiver. Useful for sanity-checking a specific custom profile. |
| 4 | [`04_benchmark.html`](04_benchmark.html)                          | Control → **Benchmark** | 500 timestamped UDP packets at 1 ms cadence. Latency CDF + per-packet line + inter-arrival timeline + histogram, plus tx/rx/loss/throughput/p50/p95/p99/jitter chips. |
| 5 | [`05_frame-size-sweep.html`](05_frame-size-sweep.html)            | Control → **Frame-size sweep** | 64 / 128 / 256 / 512 / 1024 / 1280 / 1514 B benchmarks chained, plotted as throughput, loss, latency p95, jitter vs frame size. ~9 s for 7 sizes at count=200. |
| 6 | [`06_rfc2544-throughput.html`](06_rfc2544-throughput.html)        | Control → **RFC 2544 throughput** | Binary-search the maximum loss-free fps at each RFC 2544 wire size (64 / 128 / 256 / 512 / 1024 / 1280 / 1518) with utilisation vs theoretical 1 Gbps line rate, plus per-iteration history. |

> The numbers in these samples reflect a Python-userland AF_PACKET sender (~14.5 kfps cap on this lab CPU). For real RFC 2544 line-rate measurements use a hardware traffic generator — this lab is for *functional* validation, not line-rate.

## How to refresh the samples

```
# from a freshly run lab with a live peer:
cd reports
cp latest.html               ../docs/samples/01_validation-offline.html
cp testcase-latest.html      ../docs/samples/02_wire-validation.html
cp e2e-latest.html           ../docs/samples/03_e2e.html
cp benchmark-latest.html     ../docs/samples/04_benchmark.html
cp sweep-latest.html         ../docs/samples/05_frame-size-sweep.html
cp rfc2544-latest.html       ../docs/samples/06_rfc2544-throughput.html
```

The HTML is self-contained, so committing it gives reviewers a one-click
preview without running the lab themselves.
