---
name: Bug report
about: Something the lab does wrong — wrong measurement, crash, layout glitch.
title: '[bug] '
labels: bug
---

### What happened

<!-- One paragraph. What you did, what you expected, what you got. -->

### Reproduction

1.
2.
3.

### Environment

- Lab version (top-right `v` chip on the UI, or `git rev-parse --short HEAD`):
- OS / distro:
- Node.js version (`node -v`):
- Python version (`python3 -V`):
- NIC driver (`ethtool -i <iface>` if available):
- Browser:

### Logs / screenshots

<details><summary>Server log (tail /tmp/lab.log or wherever ./run-lab.sh prints to)</summary>

```
paste here
```
</details>

<details><summary>Browser console errors</summary>

```
paste here
```
</details>

### Sample artefact

If the bug is about a measurement, attach the JSON report from `reports/`
(or a .pcap from `↓ .pcap` if the bug is about capture). It saves a ton
of back-and-forth.
