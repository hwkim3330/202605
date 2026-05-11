---
name: Feature request
about: A new capability that fits the lab's scope.
title: '[feature] '
labels: enhancement
---

### Problem

<!-- What can't you do today without this? What's the actual use case? -->

### Proposed solution

<!-- One concrete shape — endpoint name, UI element, output format. -->

### Alternatives considered

<!-- Other ways to solve the same problem, and why they don't fit. -->

### Out of scope?

The lab is **functional validation at usermode AF_PACKET speeds** — not
a line-rate traffic generator, not a TSN switch, not a vendor-specific
test platform. See [`docs/methodology.md`](../../docs/methodology.md)
for what we explicitly don't measure. If your request needs hardware
timestamping, DPDK / XDP, vendor MIBs, or sub-µs IFG, please flag that
up front so we can decide together if it's a fit.
