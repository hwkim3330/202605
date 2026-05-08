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
ETH_P_IPV6 = 0x86dd
ETH_P_LLDP = 0x88cc
ETH_P_PTP  = 0x88f7
ETH_P_LACP = 0x8809
ETH_P_QINQ = 0x88a8
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMPV6 = 58
PTP_TYPES = {0:"Sync",1:"Delay_Req",2:"Pdelay_Req",3:"Pdelay_Resp",8:"Follow_Up",9:"Delay_Resp",10:"Pdelay_Resp_Follow_Up",11:"Announce",12:"Signaling",13:"Management"}
ICMPV6_TYPES = {1:"Destination Unreachable",2:"Packet Too Big",3:"Time Exceeded",4:"Parameter Problem",128:"Echo Request",129:"Echo Reply",133:"RS",134:"RA",135:"NS",136:"NA",137:"Redirect",143:"MLDv2 Report"}
TCP_FLAG_BITS = [(0x100,"NS"),(0x80,"CWR"),(0x40,"ECE"),(0x20,"URG"),(0x10,"ACK"),(0x8,"PSH"),(0x4,"RST"),(0x2,"SYN"),(0x1,"FIN")]
LLDP_TLVS = {0:"End",1:"ChassisID",2:"PortID",3:"TTL",4:"PortDesc",5:"SystemName",6:"SystemDesc",7:"SystemCap",8:"MgmtAddr",127:"Org"}


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
    if mode == "benchmark":
        size = int(payload.get("size", 64))
        seq = int(payload.get("start", 1) if sequence is None else sequence)
        ts_ns = time.time_ns()
        header = b"KETI" + struct.pack("!IQ", seq & 0xFFFFFFFF, ts_ns & 0xFFFFFFFFFFFFFFFF)
        if size <= len(header):
            return header[:size]
        return header + bytes(size - len(header))
    if mode == "prbs":
        # Pseudo-random bit sequences per RFC 4814 / O.150 — useful for line BER
        # checks. Polynomial-deterministic so receiver can re-generate and verify.
        size = int(payload.get("size", 256))
        order = int(payload.get("order", 23))  # 7 / 15 / 23 typical
        taps = {7: (7, 6), 15: (15, 14), 23: (23, 18), 31: (31, 28)}.get(order, (23, 18))
        state = int(payload.get("seed", 0x7FFFFF)) & ((1 << taps[0]) - 1)
        if state == 0:
            state = 0x1
        out = bytearray(size)
        bit = 0
        byte = 0
        for i in range(size * 8):
            new = ((state >> (taps[0] - 1)) ^ (state >> (taps[1] - 1))) & 1
            state = ((state << 1) | new) & ((1 << taps[0]) - 1)
            byte = (byte << 1) | new
            bit += 1
            if bit == 8:
                out[i // 8] = byte
                byte = 0
                bit = 0
        return bytes(out)
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
    if profile.get("ipv6") and not profile.get("ipv4"):
        ip = profile["ipv6"]
        src = socket.inet_pton(socket.AF_INET6, ip["src"])
        dst = socket.inet_pton(socket.AF_INET6, ip["dst"])
        pseudo = src + dst + struct.pack("!IHBB", length, 0, 0, IP_PROTO_UDP)
    else:
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


def build_ipv6(profile: dict[str, Any], proto: int, l4_payload: bytes) -> bytes:
    ip = profile.get("ipv6", {})
    src = socket.inet_pton(socket.AF_INET6, ip["src"])
    dst = socket.inet_pton(socket.AF_INET6, ip["dst"])
    tc = int(ip.get("trafficClass", 0)) & 0xFF
    flow = int(ip.get("flowLabel", 0)) & 0xFFFFF
    word0 = (6 << 28) | (tc << 20) | flow
    hop = int(ip.get("hopLimit", 64)) & 0xFF
    payload_len = len(l4_payload) & 0xFFFF
    header = struct.pack("!IHBB", word0, payload_len, proto, hop) + src + dst
    return header + l4_payload


def build_tcp(profile: dict[str, Any], sequence: int | None = None) -> bytes:
    tcp = profile.get("tcp", {})
    data = payload_bytes(profile, sequence)
    sp = int(tcp.get("srcPort", 50000))
    dp = int(tcp.get("dstPort", 50001))
    seq = int(tcp.get("seq", 1))
    ack = int(tcp.get("ack", 0))
    flag_map = {"FIN": 0x001, "SYN": 0x002, "RST": 0x004, "PSH": 0x008, "ACK": 0x010, "URG": 0x020, "ECE": 0x040, "CWR": 0x080, "NS": 0x100}
    flags = 0
    for f in tcp.get("flags", ["SYN"]):
        flags |= flag_map.get(str(f).upper(), 0)
    win = int(tcp.get("window", 65535))
    off_flags = (5 << 12) | flags  # 20-byte header (5 32-bit words)
    header = struct.pack("!HHIIHHHH", sp, dp, seq, ack, off_flags, win, 0, 0)
    # checksum (over pseudo-header + tcp + data) for IPv4 only here; IPv6 needs different pseudo
    is_v6 = profile.get("ipv6") and not profile.get("ipv4")
    if is_v6:
        ip = profile["ipv6"]
        src = socket.inet_pton(socket.AF_INET6, ip["src"])
        dst = socket.inet_pton(socket.AF_INET6, ip["dst"])
        pseudo = src + dst + struct.pack("!IHBB", len(header) + len(data), 0, 0, IP_PROTO_TCP)
    else:
        ip = profile.get("ipv4", {})
        pseudo = ip_to_bytes(ip["src"]) + ip_to_bytes(ip["dst"]) + struct.pack("!BBH", 0, IP_PROTO_TCP, len(header) + len(data))
    csum = checksum(pseudo + header + data)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHIIHHHH", sp, dp, seq, ack, off_flags, win, csum, 0) + data


def build_frame(profile: dict[str, Any], sequence: int | None = None) -> tuple[bytes, dict[str, Any]]:
    protocol = profile.get("protocol", "udp").lower()
    if protocol == "udp":
        l4 = build_udp(profile, sequence)
        if profile.get("ipv6") and not profile.get("ipv4"):
            frame = ethernet_header(profile, ETH_P_IPV6) + build_ipv6(profile, IP_PROTO_UDP, l4)
        else:
            frame = ethernet_header(profile, ETH_P_IP) + build_ipv4(profile, IP_PROTO_UDP, l4)
    elif protocol == "tcp":
        l4 = build_tcp(profile, sequence)
        if profile.get("ipv6") and not profile.get("ipv4"):
            frame = ethernet_header(profile, ETH_P_IPV6) + build_ipv6(profile, IP_PROTO_TCP, l4)
        else:
            frame = ethernet_header(profile, ETH_P_IP) + build_ipv4(profile, IP_PROTO_TCP, l4)
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
    if ether_type in (ETH_P_8021Q, ETH_P_QINQ) and len(frame) >= 18:
        tci, inner_type = struct.unpack("!HH", frame[14:18])
        decoded["vlan"] = {
            "tpid": f"0x{ether_type:04x}",
            "priority": (tci >> 13) & 0x7,
            "dei": bool(tci & 0x1000),
            "id": tci & 0x0FFF,
            "etherType": f"0x{inner_type:04x}",
        }
        ether_type = inner_type
        offset = 18
        # Q-in-Q: another 802.1Q header right after
        if ether_type == ETH_P_8021Q and len(frame) >= offset + 4:
            tci2, inner2 = struct.unpack("!HH", frame[offset:offset+4])
            decoded["vlanInner"] = {
                "tpid": "0x8100",
                "priority": (tci2 >> 13) & 0x7,
                "dei": bool(tci2 & 0x1000),
                "id": tci2 & 0x0FFF,
                "etherType": f"0x{inner2:04x}",
            }
            ether_type = inner2
            offset += 4
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
            udp_payload = frame[l4 + 8 : l4 + length] if length >= 8 else b""
            if len(udp_payload) >= 16 and udp_payload[:4] == b"KETI":
                seq, ts_ns = struct.unpack("!IQ", udp_payload[4:16])
                decoded["benchmark"] = {"seq": seq, "txTimestampNs": ts_ns}
        elif proto == IP_PROTO_ICMP and len(frame) >= l4 + 8:
            typ, code, csum, ident, seq = struct.unpack("!BBHHH", frame[l4 : l4 + 8])
            decoded["icmp"] = {"type": typ, "code": code, "checksum": f"0x{csum:04x}", "id": ident, "seq": seq}
        elif proto == IP_PROTO_TCP and len(frame) >= l4 + 20:
            sp, dp, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", frame[l4 : l4 + 20])
            data_off = ((off_flags >> 12) & 0xF) * 4
            flags = off_flags & 0x1FF
            flag_names = [name for bit, name in TCP_FLAG_BITS if flags & bit]
            decoded["tcp"] = {
                "srcPort": sp, "dstPort": dp, "seq": seq, "ack": ack,
                "dataOffset": data_off, "flags": flag_names, "flagsRaw": f"0x{flags:03x}",
                "window": win, "checksum": f"0x{csum:04x}", "urgent": urg,
            }
    elif ether_type == ETH_P_IPV6 and len(frame) >= offset + 40:
        word = struct.unpack("!I", frame[offset:offset+4])[0]
        version = (word >> 28) & 0xF
        tc = (word >> 20) & 0xFF
        flow = word & 0xFFFFF
        payload_len = struct.unpack("!H", frame[offset+4:offset+6])[0]
        next_hdr = frame[offset+6]
        hop_limit = frame[offset+7]
        try:
            src_v6 = socket.inet_ntop(socket.AF_INET6, frame[offset+8:offset+24])
            dst_v6 = socket.inet_ntop(socket.AF_INET6, frame[offset+24:offset+40])
        except Exception:
            src_v6 = dst_v6 = "?"
        decoded["ipv6"] = {
            "version": version, "trafficClass": tc, "flowLabel": flow,
            "payloadLength": payload_len, "nextHeader": next_hdr, "hopLimit": hop_limit,
            "src": src_v6, "dst": dst_v6,
        }
        l4 = offset + 40
        if next_hdr == IP_PROTO_UDP and len(frame) >= l4 + 8:
            sp, dp, length, csum = struct.unpack("!HHHH", frame[l4:l4+8])
            decoded["udp"] = {"srcPort": sp, "dstPort": dp, "length": length, "checksum": f"0x{csum:04x}"}
        elif next_hdr == IP_PROTO_TCP and len(frame) >= l4 + 20:
            sp, dp, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", frame[l4:l4+20])
            flags = off_flags & 0x1FF
            decoded["tcp"] = {
                "srcPort": sp, "dstPort": dp, "seq": seq, "ack": ack,
                "dataOffset": ((off_flags >> 12) & 0xF) * 4,
                "flags": [name for bit, name in TCP_FLAG_BITS if flags & bit],
                "flagsRaw": f"0x{flags:03x}", "window": win, "checksum": f"0x{csum:04x}", "urgent": urg,
            }
        elif next_hdr == IP_PROTO_ICMPV6 and len(frame) >= l4 + 4:
            typ = frame[l4]
            code = frame[l4+1]
            csum = struct.unpack("!H", frame[l4+2:l4+4])[0]
            decoded["icmpv6"] = {
                "type": typ, "code": code, "typeName": ICMPV6_TYPES.get(typ, f"type {typ}"),
                "checksum": f"0x{csum:04x}",
            }
    elif ether_type == ETH_P_LLDP and len(frame) >= offset + 4:
        tlvs = []
        p = offset
        while p + 2 <= len(frame):
            hdr = struct.unpack("!H", frame[p:p+2])[0]
            ttype = (hdr >> 9) & 0x7F
            tlen = hdr & 0x1FF
            p += 2
            if ttype == 0:  # End-of-LLDPDU
                break
            if p + tlen > len(frame):
                break
            value = frame[p:p+tlen]
            entry = {"type": ttype, "name": LLDP_TLVS.get(ttype, f"TLV-{ttype}"), "length": tlen}
            try:
                if ttype == 1 and tlen >= 1:  # Chassis ID
                    entry["subtype"] = value[0]
                    entry["value"] = bytes_to_mac(value[1:7]) if value[0] == 4 and tlen >= 7 else value[1:].hex()
                elif ttype == 2 and tlen >= 1:  # Port ID
                    entry["subtype"] = value[0]
                    try:
                        entry["value"] = value[1:].decode("ascii", errors="replace")
                    except Exception:
                        entry["value"] = value[1:].hex()
                elif ttype == 3 and tlen >= 2:  # TTL
                    entry["value"] = struct.unpack("!H", value[:2])[0]
                elif ttype in (4, 5, 6) and tlen > 0:  # Port/Sys/Sys descriptions, ASCII
                    entry["value"] = value.decode("utf-8", errors="replace")
                elif ttype == 127 and tlen >= 4:  # Org-specific
                    entry["oui"] = value[:3].hex()
                    entry["subtype"] = value[3]
                    entry["data"] = value[4:].hex()
                else:
                    entry["raw"] = value.hex()
            except Exception:
                entry["raw"] = value.hex()
            tlvs.append(entry)
            p += tlen
        decoded["lldp"] = {"tlvCount": len(tlvs), "tlvs": tlvs}
    elif ether_type == ETH_P_PTP and len(frame) >= offset + 34:
        h0 = frame[offset]
        msg_type = h0 & 0x0F
        version = frame[offset+1] & 0x0F
        msg_len = struct.unpack("!H", frame[offset+2:offset+4])[0]
        domain = frame[offset+4]
        flags = struct.unpack("!H", frame[offset+6:offset+8])[0]
        seq_id = struct.unpack("!H", frame[offset+30:offset+32])[0]
        control = frame[offset+32]
        log_msg_int = struct.unpack("!b", frame[offset+33:offset+34])[0]
        decoded["ptp"] = {
            "messageType": msg_type, "messageName": PTP_TYPES.get(msg_type, f"type {msg_type}"),
            "version": version, "messageLength": msg_len, "domain": domain,
            "flags": f"0x{flags:04x}", "sequenceId": seq_id, "control": control,
            "logMessageInterval": log_msg_int,
        }
    elif ether_type == ETH_P_LACP:
        decoded["lacp"] = {"raw": frame[offset:offset+min(50, len(frame)-offset)].hex()}
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
                if a.get("family") == "inet" and a.get("local") and ":" not in a.get("local", "")
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
        start_ns = time.time_ns()
        sent = 0
        decoded = None
        payload = profile.get("payload", {})
        seq_start = int(payload.get("start", 1)) if isinstance(payload, dict) else 1
        tx_records = []
        record_each = bool(profile.get("recordTimestamps")) or (
            isinstance(payload, dict) and payload.get("mode") == "benchmark"
        )
        # Sub-millisecond sleeps are unreliable on Linux (rounded up to the
        # scheduler tick, typically 1 ms or more). For interval_ms < 1, we use
        # a monotonic-based busy/yield wait keyed off the start time so the
        # actual rate matches the requested rate.
        sub_ms = 0 < interval_ms < 1.0
        target_period_ns = int(interval_ms * 1_000_000) if sub_ms else 0
        for index in range(count):
            frame, decoded = build_frame(profile, seq_start + index)
            tx_ns = time.time_ns()
            sent += sock.send(frame)
            if record_each:
                tx_records.append({"seq": seq_start + index, "txTimestampNs": tx_ns, "length": len(frame)})
            if interval_ms <= 0 or index == count - 1:
                continue
            if sub_ms:
                # Spin-wait until the next slot. Yields via os.sched_yield to
                # avoid burning a whole core when other CPUs are free.
                next_due_ns = tx_ns + target_period_ns
                while time.time_ns() < next_due_ns:
                    try:
                        os.sched_yield()
                    except AttributeError:
                        pass
            else:
                time.sleep(interval_ms / 1000)
        elapsed = time.monotonic() - start
        end_ns = time.time_ns()
    except PermissionError:
        fail("raw socket permission denied. Run the server/agent with sudo or CAP_NET_RAW.")
    except Exception as exc:
        fail(str(exc))
    finally:
        try:
            sock.close()
        except Exception:
            pass
    print(json.dumps({
        "ok": True,
        "framesSent": count,
        "bytesSent": sent,
        "elapsedSec": elapsed,
        "startTimestampNs": start_ns,
        "endTimestampNs": end_ns,
        "decoded": decoded,
        "txRecords": tx_records,
    }, ensure_ascii=False))


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
            rx_ns = time.time_ns()
            decoded = decode_frame(frame)
            eth = decoded.get("ethernet", {})
            if ether_type_filter and eth.get("etherType") != ether_type_filter.lower():
                continue
            if dst_mac_filter and eth.get("dstMac", "").lower() != dst_mac_filter:
                continue
            if src_mac_filter and eth.get("srcMac", "").lower() != src_mac_filter:
                continue
            frames.append({
                "timestamp": rx_ns / 1e9,
                "rxTimestampNs": rx_ns,
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


def command_capture_stream() -> None:
    req = read_json()
    interface = req.get("interface")
    if not interface:
        fail("interface is required")
    timeout_sec = float(req.get("timeoutSec", 0) or 0)
    max_frames = int(req.get("maxFrames", 0) or 0)
    ether_type_filter = (req.get("etherType") or "").lower() or None
    dst_mac_filter = (req.get("dstMac") or "").lower()
    src_mac_filter = (req.get("srcMac") or "").lower()
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((interface, 0))
        sock.settimeout(0.25)
    except PermissionError:
        fail("raw socket permission denied. Run the server/agent with sudo or CAP_NET_RAW.")
        return
    except Exception as exc:
        fail(str(exc))
        return
    print(json.dumps({"type": "start", "interface": interface, "timestampNs": time.time_ns()}), flush=True)
    deadline = time.monotonic() + timeout_sec if timeout_sec > 0 else None
    count = 0
    try:
        while True:
            if deadline and time.monotonic() >= deadline:
                break
            if max_frames and count >= max_frames:
                break
            try:
                frame, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            rx_ns = time.time_ns()
            decoded = decode_frame(frame)
            eth = decoded.get("ethernet", {})
            if ether_type_filter and eth.get("etherType") != ether_type_filter:
                continue
            if dst_mac_filter and eth.get("dstMac", "").lower() != dst_mac_filter:
                continue
            if src_mac_filter and eth.get("srcMac", "").lower() != src_mac_filter:
                continue
            count += 1
            print(json.dumps({
                "type": "frame",
                "n": count,
                "timestamp": rx_ns / 1e9,
                "rxTimestampNs": rx_ns,
                "length": len(frame),
                "frameHex": frame.hex(),
                "hexdump": hexdump(frame[:256]),
                "decoded": decoded,
            }), flush=True)
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
        try:
            print(json.dumps({"type": "end", "count": count}), flush=True)
        except BrokenPipeError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Ethernet Packet Lab raw-socket agent")
    parser.add_argument("command", choices=["interfaces", "build", "send", "capture", "capture-stream"])
    args = parser.parse_args()
    if args.command == "interfaces":
        list_interfaces()
    elif args.command == "build":
        command_build()
    elif args.command == "send":
        command_send()
    elif args.command == "capture":
        command_capture()
    elif args.command == "capture-stream":
        command_capture_stream()


if __name__ == "__main__":
    main()
