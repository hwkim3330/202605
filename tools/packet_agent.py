#!/usr/bin/env python3
import argparse
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
from typing import Any

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_8021Q = 0x8100
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


def fail(message: str, code: int = 1) -> None:
    print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    raise SystemExit(code)


def read_json() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {exc}")


def mac_to_bytes(value: str) -> bytes:
    parts = value.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {value}")
    return bytes(int(part, 16) for part in parts)


def bytes_to_mac(value: bytes) -> str:
    return ":".join(f"{b:02x}" for b in value)


def ip_to_bytes(value: str) -> bytes:
    return socket.inet_aton(value)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def hexdump(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def payload_bytes(profile: dict[str, Any], sequence: int | None = None) -> bytes:
    payload = profile.get("payload", {})
    if isinstance(payload, str):
        return payload.encode()
    mode = payload.get("mode", "text")
    if mode == "hex":
        return bytes.fromhex(payload.get("data", "").replace(" ", ""))
    if mode == "counter":
        size = int(payload.get("size", 32))
        return bytes((i % 256 for i in range(size)))
    if mode == "random":
        size = int(payload.get("size", 32))
        return os.urandom(size)
    if mode == "repeat":
        value = int(str(payload.get("byte", "0x00")), 0) & 0xFF
        size = int(payload.get("size", 32))
        return bytes([value]) * size
    if mode == "sequence":
        seq = int(payload.get("start", 1) if sequence is None else sequence)
        template = payload.get("template", "KETI_TEST_SEQ_{seq:06d}")
        return template.format(seq=seq, time=f"{time.time():.6f}").encode()
    return str(payload.get("data", "ethernet-packet-lab")).encode()


def ethernet_header(profile: dict[str, Any], ether_type: int) -> bytes:
    dst = mac_to_bytes(profile["dstMac"])
    src = mac_to_bytes(profile["srcMac"])
    vlan = profile.get("vlan")
    if vlan and vlan.get("enabled"):
        priority = int(vlan.get("priority", 0)) & 0x7
        dei = 1 if vlan.get("dei") else 0
        vlan_id = int(vlan.get("id", 1)) & 0xFFF
        tci = (priority << 13) | (dei << 12) | vlan_id
        return dst + src + struct.pack("!HHH", ETH_P_8021Q, tci, ether_type)
    return dst + src + struct.pack("!H", ether_type)


def build_ipv4(profile: dict[str, Any], proto: int, l4_payload: bytes) -> bytes:
    ip = profile.get("ipv4", {})
    src = ip_to_bytes(ip["src"])
    dst = ip_to_bytes(ip["dst"])
    ttl = int(ip.get("ttl", 64))
    tos = int(ip.get("tos", 0))
    ident = int(ip.get("id", random.randint(0, 0xFFFF)))
    flags_fragment = int(ip.get("flagsFragment", 0x4000))
    total_len = 20 + len(l4_payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        tos,
        total_len,
        ident,
        flags_fragment,
        ttl,
        proto,
        0,
        src,
        dst,
    )
    csum = checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:] + l4_payload


def build_udp(profile: dict[str, Any], sequence: int | None = None) -> bytes:
    udp = profile.get("udp", {})
    data = payload_bytes(profile, sequence)
    src_port = int(udp.get("srcPort", 40000))
    dst_port = int(udp.get("dstPort", 50000))
    length = 8 + len(data)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = ip_to_bytes(profile["ipv4"]["src"]) + ip_to_bytes(profile["ipv4"]["dst"]) + struct.pack("!BBH", 0, IP_PROTO_UDP, length)
    csum = checksum(pseudo + header + data)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, csum) + data


def build_icmp(profile: dict[str, Any], sequence: int | None = None) -> bytes:
    icmp = profile.get("icmp", {})
    data = payload_bytes(profile, sequence)
    icmp_type = int(icmp.get("type", 8))
    code = int(icmp.get("code", 0))
    ident = int(icmp.get("id", 0x2026))
    seq = int(icmp.get("seq", 1))
    header = struct.pack("!BBHHH", icmp_type, code, 0, ident, seq)
    csum = checksum(header + data)
    return struct.pack("!BBHHH", icmp_type, code, csum, ident, seq) + data


def build_arp(profile: dict[str, Any]) -> bytes:
    arp = profile.get("arp", {})
    operation = int(arp.get("operation", 1))
    sender_mac = mac_to_bytes(arp.get("senderMac", profile["srcMac"]))
    sender_ip = ip_to_bytes(arp["senderIp"])
    target_mac = mac_to_bytes(arp.get("targetMac", "00:00:00:00:00:00"))
    target_ip = ip_to_bytes(arp["targetIp"])
    return struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, operation) + sender_mac + sender_ip + target_mac + target_ip


def build_frame(profile: dict[str, Any], sequence: int | None = None) -> tuple[bytes, dict[str, Any]]:
    protocol = profile.get("protocol", "udp").lower()
    if protocol == "udp":
        l4 = build_udp(profile, sequence)
        frame = ethernet_header(profile, ETH_P_IP) + build_ipv4(profile, IP_PROTO_UDP, l4)
    elif protocol == "icmp":
        l4 = build_icmp(profile, sequence)
        frame = ethernet_header(profile, ETH_P_IP) + build_ipv4(profile, IP_PROTO_ICMP, l4)
    elif protocol == "arp":
        frame = ethernet_header(profile, ETH_P_ARP) + build_arp(profile)
    elif protocol == "raw":
        ether_type = int(str(profile.get("etherType", "0x88b5")), 0)
        frame = ethernet_header(profile, ether_type) + payload_bytes(profile, sequence)
    else:
        raise ValueError(f"unsupported protocol: {protocol}")

    if len(frame) < 60:
        frame += bytes(60 - len(frame))
    target_len = profile.get("targetFrameLength")
    if target_len:
        target = int(target_len)
        if target < len(frame):
            raise ValueError(f"targetFrameLength {target} is smaller than built frame length {len(frame)}")
        frame += bytes(target - len(frame))
    return frame, decode_frame(frame)


def decode_frame(frame: bytes) -> dict[str, Any]:
    if len(frame) < 14:
        return {"length": len(frame), "error": "truncated ethernet header"}
    offset = 14
    ether_type = struct.unpack("!H", frame[12:14])[0]
    decoded: dict[str, Any] = {
        "length": len(frame),
        "ethernet": {
            "dstMac": bytes_to_mac(frame[0:6]),
            "srcMac": bytes_to_mac(frame[6:12]),
            "etherType": f"0x{ether_type:04x}",
        },
    }
    if ether_type == ETH_P_8021Q and len(frame) >= 18:
        tci, inner_type = struct.unpack("!HH", frame[14:18])
        decoded["vlan"] = {
            "priority": (tci >> 13) & 0x7,
            "dei": bool(tci & 0x1000),
            "id": tci & 0x0FFF,
            "etherType": f"0x{inner_type:04x}",
        }
        ether_type = inner_type
        offset = 18
    if ether_type == ETH_P_IP and len(frame) >= offset + 20:
        ihl = (frame[offset] & 0x0F) * 4
        proto = frame[offset + 9]
        total_len = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        decoded["ipv4"] = {
            "src": socket.inet_ntoa(frame[offset + 12 : offset + 16]),
            "dst": socket.inet_ntoa(frame[offset + 16 : offset + 20]),
            "ttl": frame[offset + 8],
            "protocol": proto,
            "totalLength": total_len,
            "checksumValid": checksum(frame[offset : offset + ihl]) == 0,
        }
        l4 = offset + ihl
        if proto == IP_PROTO_UDP and len(frame) >= l4 + 8:
            src_port, dst_port, length, csum = struct.unpack("!HHHH", frame[l4 : l4 + 8])
            decoded["udp"] = {"srcPort": src_port, "dstPort": dst_port, "length": length, "checksum": f"0x{csum:04x}"}
        elif proto == IP_PROTO_ICMP and len(frame) >= l4 + 8:
            typ, code, csum, ident, seq = struct.unpack("!BBHHH", frame[l4 : l4 + 8])
            decoded["icmp"] = {"type": typ, "code": code, "checksum": f"0x{csum:04x}", "id": ident, "seq": seq}
    elif ether_type == ETH_P_ARP and len(frame) >= offset + 28:
        arp = frame[offset : offset + 28]
        decoded["arp"] = {
            "operation": struct.unpack("!H", arp[6:8])[0],
            "senderMac": bytes_to_mac(arp[8:14]),
            "senderIp": socket.inet_ntoa(arp[14:18]),
            "targetMac": bytes_to_mac(arp[18:24]),
            "targetIp": socket.inet_ntoa(arp[24:28]),
        }
    return decoded


def list_interfaces() -> None:
    addr_map: dict[str, list[dict[str, Any]]] = {}
    try:
        ip_out = subprocess.check_output(["ip", "-j", "addr"], text=True)
        for item in json.loads(ip_out):
            addr_map[item.get("ifname", "")] = [
                {"local": a.get("local"), "prefixlen": a.get("prefixlen")}
                for a in item.get("addr_info", [])
                if a.get("family") == "inet"
            ]
    except Exception:
        addr_map = {}

    interfaces = []
    for name in sorted(os.listdir("/sys/class/net")):
        base = f"/sys/class/net/{name}"
        try:
            mac = open(f"{base}/address", encoding="utf8").read().strip()
            state = open(f"{base}/operstate", encoding="utf8").read().strip()
            mtu = int(open(f"{base}/mtu", encoding="utf8").read().strip())
        except OSError:
            continue
        interfaces.append({"name": name, "mac": mac, "state": state, "mtu": mtu, "ipv4": addr_map.get(name, [])})
    print(json.dumps({"ok": True, "interfaces": interfaces}, ensure_ascii=False))


def command_build() -> None:
    profile = read_json()
    try:
        frame, decoded = build_frame(profile)
    except Exception as exc:
        fail(str(exc))
    print(json.dumps({"ok": True, "frameHex": frame.hex(), "hexdump": hexdump(frame), "decoded": decoded}, ensure_ascii=False))


def command_send() -> None:
    profile = read_json()
    interface = profile.get("interface")
    if not interface:
        fail("interface is required")
    count = int(profile.get("count", 1))
    interval_ms = float(profile.get("intervalMs", 1000))
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
        start = time.monotonic()
        sent = 0
        decoded = None
        payload = profile.get("payload", {})
        seq_start = int(payload.get("start", 1)) if isinstance(payload, dict) else 1
        for index in range(count):
            frame, decoded = build_frame(profile, seq_start + index)
            sent += sock.send(frame)
            if interval_ms > 0 and index != count - 1:
                time.sleep(interval_ms / 1000)
        elapsed = time.monotonic() - start
    except PermissionError:
        fail("raw socket permission denied. Run the server/agent with sudo or CAP_NET_RAW.")
    except Exception as exc:
        fail(str(exc))
    finally:
        try:
            sock.close()
        except Exception:
            pass
    print(json.dumps({"ok": True, "framesSent": count, "bytesSent": sent, "elapsedSec": elapsed, "decoded": decoded}, ensure_ascii=False))


def command_capture() -> None:
    req = read_json()
    interface = req.get("interface")
    if not interface:
        fail("interface is required")
    timeout_sec = float(req.get("timeoutSec", 10))
    max_frames = int(req.get("maxFrames", 20))
    ether_type_filter = req.get("etherType")
    dst_mac_filter = req.get("dstMac", "").lower()
    src_mac_filter = req.get("srcMac", "").lower()
    frames = []
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((interface, 0))
        sock.settimeout(0.5)
        deadline = time.monotonic() + timeout_sec
        while len(frames) < max_frames and time.monotonic() < deadline:
            try:
                frame, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            decoded = decode_frame(frame)
            eth = decoded.get("ethernet", {})
            if ether_type_filter and eth.get("etherType") != ether_type_filter.lower():
                continue
            if dst_mac_filter and eth.get("dstMac", "").lower() != dst_mac_filter:
                continue
            if src_mac_filter and eth.get("srcMac", "").lower() != src_mac_filter:
                continue
            frames.append({
                "timestamp": time.time(),
                "interface": addr[0] if addr else interface,
                "length": len(frame),
                "frameHex": frame.hex(),
                "hexdump": hexdump(frame[:256]),
                "decoded": decoded,
            })
    except PermissionError:
        fail("raw socket permission denied. Run the server/agent with sudo or CAP_NET_RAW.")
    except Exception as exc:
        fail(str(exc))
    finally:
        try:
            sock.close()
        except Exception:
            pass
    print(json.dumps({"ok": True, "frames": frames}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Ethernet Packet Lab raw-socket agent")
    parser.add_argument("command", choices=["interfaces", "build", "send", "capture"])
    args = parser.parse_args()
    if args.command == "interfaces":
        list_interfaces()
    elif args.command == "build":
        command_build()
    elif args.command == "send":
        command_send()
    elif args.command == "capture":
        command_capture()


if __name__ == "__main__":
    main()
