# WPF desktop companion

`wpf/EthernetPacketGenerator/` is a **Windows-native** packet generator + live
capture application written in C# + WPF + SharpPcap + PacketDotNet. It is the
desktop sibling of the browser-based lab at the repository root.

| | Web lab (`/`)                                            | WPF companion (`wpf/`)                              |
|---|---|---|
| Platform | Linux only (AF_PACKET)                                  | Windows only (Npcap)                                |
| UI       | Browser (any modern Chromium / Firefox / Safari)         | WPF native window                                   |
| Packet build | Form-based with auto-rebuild preview                | Block-based stack builder with drag-drop palette    |
| Capture  | Live NDJSON stream, layered hex, PCAP/PCAP-NG export    | SharpPcap live, decode tree, .pcapng export         |
| Send     | Python AF_PACKET agent                                  | SharpPcap                                           |
| HTTP API | Yes — Node.js `server.js` (24 endpoints)                | Yes — `LabApiServer.cs` (cross-talks with web lab)  |

The two share the same conceptual model (a list of *packet steps* + *delay
events*, each step a stack of protocol layers) and can interoperate over the
HTTP API: a Windows WPF instance can act as the **peer** for a Linux web lab
and vice versa. That's why both expose `/api/interfaces`, `/api/build`,
`/api/send`, `/api/capture` with matching JSON shapes.

## Build

```powershell
# On Windows, in PowerShell:
cd wpf\EthernetPacketGenerator
dotnet restore
dotnet build -c Release
dotnet run --project EthernetPacketGenerator
```

Requires .NET 8 SDK + Npcap (install with "WinPcap API-compatible Mode"
enabled). Run as Administrator if Npcap requires elevated privileges.

The Linux web lab does **not** depend on this; they're independent
build targets that happen to share the same git repository for
convenience.

## What's wired

- **Build & Send tab** — block builder + protocol palette + per-packet
  protocol settings + hex dump with block-byte highlighting + decode
  tree + packet list sequence (with delay events) + send control.
- **Live Capture tab** — uses the same NIC the user picks on the
  Send-tab interface dropdown, no separate dropdown. Wireshark-style
  three pane: packet list / decode tree / hex dump. Toolbar buttons
  Start / Stop / Clear / Save .pcapng + a BPF-style filter input.

See [`BUILD.md`](EthernetPacketGenerator/BUILD.md) (sub-folder) for the
upstream build / Npcap notes.
