# Measurement methodology

What every Control-page action actually measures, the math behind the
numbers, and — *especially* — the limitations. If you're going to put
these numbers in a paper, a customer report, or an incident root-cause,
read this first.

---

## 1. Frame on the wire

The agent uses Linux `AF_PACKET` `SOCK_RAW`. That gives us **everything
the kernel sees**:

- The 14-byte Ethernet header (DA + SA + EtherType / 802.1Q TPID),
- Any 802.1Q tag(s) — including the `0x88a8` outer tag for Q-in-Q,
- The L3 + L4 + payload as built by us.

What we **don't** see:

- The 8-byte preamble + SFD that precedes every frame on the wire
  (handled by the MAC).
- The 4-byte FCS / CRC32 trailer (computed by hardware, stripped before
  the kernel hands the frame up).
- The 12-byte minimum inter-frame gap.

So a "1518-byte RFC 2544 frame" on the wire is **1514 bytes** in our
buffer. The lab corrects for that everywhere it builds (`targetFrameLength`)
or reports a result against a wire size (`/api/rfc2544`'s `bufferSize`
field is 4 less than the reported `size`).

If your NIC has rxvlan offload enabled, the kernel quietly removes the
4-byte 802.1Q tag from the buffer it gives us. We detect this via the
`PACKET_AUXDATA` cmsg, get the `tci` and `tpid` back from the kernel,
and **splice them back into the buffer** before decoding. The result is
that `frame.frameHex` is byte-identical to what left the wire,
regardless of offload state. That's how the wire-validation matcher
ended up exact-byte clean even on offloading NICs.

---

## 2. KETI benchmark marker (loss / latency / jitter / throughput)

The trick that makes our benchmark work without any out-of-band
synchronisation channel:

```
UDP payload bytes 0..15 = "KETI" + uint32-be seq + uint64-be tx_ts_ns
UDP payload bytes 16..  = whatever the configured size requires
```

`tx_ts_ns` is `time.time_ns()` measured *just before the agent calls
`sock.send(frame)`*. The receiver agent stamps every captured frame
with `rx_ts_ns = time.time_ns()` at `recvmsg()` time. The benchmark
analyser pulls both timestamps out, matches by `seq`, and reports:

```
loss%        = 1 - (matched / sent)
throughput   = bytes_sent · 8 / elapsed
latencyNs[i] = rx_ts_ns[i] - tx_ts_ns[i]
```

### Latency: clock-skew adjustment

`tx_ts` is from the sender PC's wall clock; `rx_ts` is from the
receiver's. NTP typically synchronises ms-accurate, *not* µs-accurate.
On the lab, the two PCs' NTP daemons differ by ~1–2 ms. **The raw
one-way latency number is not measuring link latency — it's measuring
NTP skew + link latency.**

Honest reporting: we compute both and report the *clock-skew adjusted*
distribution as the headline number:

```
latencyAdjustedUs[i] = (latencyNs[i] - min(latencyNs)) / 1000
```

This subtracts the run's minimum sample (assumed to be the closest the
two clocks ever agreed). It's a **lower bound** on jitter — variance is
preserved — but the absolute value is no longer meaningful as
"propagation time on the link". It's "propagation + queueing − minimum
of (propagation + queueing) over the run". Honest hack.

If you need real one-way latency, you need either:
- `SO_TIMESTAMPING` with `SOF_TIMESTAMPING_TX_HARDWARE` /
  `SOF_TIMESTAMPING_RX_HARDWARE` and a NIC that supports it
  (Intel i210, i225, most TSN NICs); the hardware stamps frames before
  they leave the PHY, defeating clock skew, or
- PTP / IEEE 1588 disciplining both NIC clocks to a master.

We don't currently implement either; the report is honest about that.

### Jitter

We report `jitterUs.mean = mean(|Δlatency|)`. That's the simple form
(matches the way most benchmarking tools and the original RFC 2544
reference measure it).

It is **not** the RTP jitter from RFC 3550 §6.4.1, which is an
exponentially-smoothed `J = J + (|D| - J) / 16`. If you're comparing
against an RTP analyser, do `mean(|Δlatency|)` on its samples too.

### Throughput

`elapsedSec` is measured around the agent's send loop only:

```python
start = time.monotonic()
for index in range(count):
    sock.send(frame)
    if interval_ms > 0: time.sleep(interval_ms / 1000)
elapsed = time.monotonic() - start
```

For sub-millisecond intervals we replace `time.sleep` with a monotonic
spin/yield because Linux kernel ticks round `time.sleep(< 1ms)` up to
a tick (typically 1 ms). Without that, the *actual* offered rate is
much lower than the requested rate.

The Mbps number is `(bytes_sent · 8) / elapsedSec` — does not include
preamble + SFD + IFG (the on-the-wire overhead). For "wire-rate"
comparisons add 20 bytes per frame: `(bytes + count · 20) · 8 / elapsed`.

---

## 3. RFC 2544 §26 throughput (Control card)

We do a per-frame-size **binary search for the highest loss-free fps**:

```
lo = 500
hi = min(theoretical_fps, userlandCapPps)        # default 30000
for iter in 8 iterations or while (hi - lo) > tolerance:
    fps = (lo + hi) // 2
    run a benchmark for trialDurationSec at this fps
    if loss == 0: lo = fps; record best
    else:         hi = fps
```

### Where this differs from a real RFC 2544 box

| RFC 2544 (proper) | Our quick-mode |
|---|---|
| 60-second trial per iteration | 1–2 seconds |
| Hardware-precise IFG | Python `time.sleep` / spin-wait |
| Tested at line rate (1G/10G/100G) | Capped at ~14.5 kfps because Python AF_PACKET userland tops out around there on commodity CPUs |
| MAC address learning phase before the test | None |
| Tested with several flow tuples | Single flow |

We display this honestly. The HTML report includes a `note` field that
says "Linux usermode AF_PACKET cannot deliver hardware-precise IFG;
results are an upper bound on what the agent + kernel can sustain
loss-free." The `userlandCapPps` parameter is exposed so the operator
can clamp it to whatever their CPU actually achieves.

If you want real RFC 2544 numbers, use a hardware traffic generator
(Spirent, Ixia, hardware-accelerated TRex). This lab is for
**functional** validation — does the link forward / shape /
classify / police correctly? — not for line-rate measurement.

---

## 4. PRBS BER (`/api/verify-prbs`)

Real bit-error-rate measurement, not just loss percentage.

The sender builds frames with `payload.mode = "prbs"`, configurable
`order` (7 / 15 / 23 / 31) and `seed`. We use a Galois-style LFSR with
the canonical taps from O.150 / O.151 / RFC 4814. The output is
**deterministic given (order, seed, size)**.

The receiver runs `python3 tools/packet_agent.py verify-prbs <<JSON`
with the same `order` and `seed`, regenerates the *exact* expected
payload, and XORs it byte-by-byte against the captured payload. The
popcount of the XOR is the count of differing bits. Sum across frames
divides by total bits → **BER**.

```
BER = bit_errors / bits_compared
```

This is a real BER measurement under the assumption that the receiver
captures *every* frame (no loss). If frames are lost, those bits aren't
counted at all — they're just absent. BER and loss are orthogonal:

- Loss tells you "frames went missing" (queue overflow, link drop,
  policer drop).
- BER tells you "of the bits that did arrive, how many were corrupted"
  (PHY-level integrity, FCS errors that the NIC accepted, mismarshalled
  serdes, EMI on a long cable, etc.).

A 0% loss + 0 BER run is the strong statement: the link is bit-perfect.
Most real links are. If you see non-zero BER at userland speeds, the
PHY or cable is wrong before you even start TSN scheduling.

### Limitations

- The receiver must be running at a rate it can absorb. A backed-up
  raw socket drops frames at the kernel and BER is undercounted (the
  bits that vanished aren't compared). Watch the `kdrops` chip in the
  Capture tab.
- We compare the *first `payloadSize` bytes* of each UDP payload. If
  someone re-injects different data into the flow (NAT? middlebox?)
  the BER will be huge — that's actually correct behaviour, the link is
  not transparent.

---

## 5. Wire Validation matcher

`/api/wire-validation` runs the standard 27-profile suite and matches
captured frames to sent ones. The matcher is two-tier:

1. If the step's payload is *deterministic* (counter / repeat / fixed
   hex / text / sequence — `expectedFrameHex` is set), match by exact
   byte-by-byte equality on `frame.frameHex`. This is the strongest
   match: if any byte changed, no match.
2. Otherwise (random / benchmark — payload differs every frame), fall
   back to a structural match: same source MAC + dest MAC + protocol +
   VLAN id/priority (if we sent one) + IP src/dst + L4 ports.

For VLAN-tagged steps we also accept the **VLAN-stripped** variant of
the expected frame, because rxvlan-offload NICs deliver the frame
without the 4-byte tag (we splice it back when AUX VLAN cmsg is
available, but defensive matching is cheap).

Per-step `matched.length` is **capped at `expectedCount`** — a step
that runs in a loop and emits identical frames doesn't greedily claim
later loop iterations' frames.

### Why this matters

The earlier (broken) matcher consumed all loop-iteration frames into
loop 1's bucket and reported loops 2..N as 0 matched. The send was
correct; the report was wrong. We caught this only because a user ran
a long Packet List with `Repeat: ✓` and noticed.

---

## 6. Capture stream (live NDJSON)

Frames flow:

```
NIC ─┐
     ├── kernel AF_PACKET ─► python recvmsg ─► JSON line on stdout
     │   PACKET_AUXDATA → strip-back tag                                                
     │   PACKET_STATISTICS → drop counter
     ▼
   [ keti-server.js subprocess pipe ] ─► HTTP NDJSON ─► browser fetch.body.read()
                                                            │
                                                            ▼
                                                    pendingRows[] queue
                                                            │
                                                            ▼ (every animation frame)
                                                    DocumentFragment append
                                                       (one layout pass)
```

When the browser falls behind we apply backpressure: `res.write` returns
false, we `child.stdout.pause()`, and resume on `'drain'`. So the
**python agent slows down** to whatever the browser can absorb. No
deadlock, no implicit drops at the network layer. The agent's
`PACKET_STATISTICS` chip in the toolbar will show the kernel-side
drops if the offered rate is too high for *any* link in the chain.

DOM is capped at 2000 visible rows; the underlying `capture.packets[]`
array at 50,000 (FIFO-evicted with a single warn toast on first eviction).
Filter re-application iterates the underlying array, not the DOM.

---

## 7. Round-trip property tests

`tools/test_packet_agent.py` includes **round-trip property tests**:
for every (protocol, set of fields) combination, build a frame and
assert that decoding the resulting bytes reproduces the original
fields. If `build` and `decode` are inverses-of-each-other (they
should be, by construction), this property holds for any input. If
either side is buggy, the test catches it.

This is stronger than the table-driven decode tests because it
*generates* the input bytes from the same code that handles user
profiles, so adding a new field automatically gains a round-trip
test by virtue of being declared.

---

## 8. What we don't measure (and shouldn't pretend to)

- **Switch CPU load**, **switch buffer occupancy**, **shaper drops** —
  needs SNMP or vendor CLI integration. Out of scope.
- **PHY symbol errors** — needs MDIO / `ethtool -S`. Out of scope.
- **Hardware queue counters** for TSN priority verification — needs
  `tc qdisc show` or vendor mibs. Future work.
- **Line-rate at 1 Gbps and above** — needs DPDK / XDP or a hardware
  traffic generator. Out of scope (see RFC 2544 limitations above).
- **Cable length / fault location** — TDR is a hardware test.

What this lab *does* measure correctly: functional correctness of the
two-node link end-to-end at usermode speeds, with byte-exact frame
verification, real bit-error-rate measurement on demand, and
comparable-across-runs latency / jitter / loss numbers under a
clearly-disclosed methodology.
