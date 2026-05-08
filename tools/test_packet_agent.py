"""Unit tests for the packet_agent decoder.

Synthesises canonical frames byte-for-byte and asserts the decoder pulls out
the right fields. No raw socket needed; this is pure parsing logic.

Run with:  python3 -m unittest discover -s tools -p 'test_*.py'
"""
from __future__ import annotations

import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import packet_agent as pa  # noqa: E402


def _pack_eth(dst: str, src: str, etype: int) -> bytes:
    return pa.mac_to_bytes(dst) + pa.mac_to_bytes(src) + struct.pack("!H", etype)


class EthernetTests(unittest.TestCase):
    def test_basic_ethernet(self):
        f = _pack_eth("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:01", 0x88b5) + b"\x00" * 50
        d = pa.decode_frame(f)
        self.assertEqual(d["ethernet"]["dstMac"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(d["ethernet"]["srcMac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(d["ethernet"]["etherType"], "0x88b5")

    def test_8021q_vlan(self):
        tci = (5 << 13) | 100  # PCP=5, VID=100
        eth = pa.mac_to_bytes("ff:ff:ff:ff:ff:ff") + pa.mac_to_bytes("aa:bb:cc:dd:ee:01")
        f = eth + struct.pack("!HHH", 0x8100, tci, 0x0800) + b"\x45" + b"\x00" * 39
        d = pa.decode_frame(f)
        self.assertEqual(d["vlan"]["id"], 100)
        self.assertEqual(d["vlan"]["priority"], 5)

    def test_qinq_double_tag(self):
        outer = (7 << 13) | 10
        inner = (3 << 13) | 20
        eth = pa.mac_to_bytes("ff:ff:ff:ff:ff:ff") + pa.mac_to_bytes("aa:bb:cc:dd:ee:01")
        f = eth + struct.pack("!HH", 0x88a8, outer) + struct.pack("!HH", 0x8100, inner) + struct.pack("!H", 0x0800) + b"\x45" + b"\x00" * 39
        d = pa.decode_frame(f)
        self.assertEqual(d["vlan"]["id"], 10)
        self.assertEqual(d["vlan"]["priority"], 7)
        self.assertEqual(d["vlanInner"]["id"], 20)
        self.assertEqual(d["vlanInner"]["priority"], 3)


class IPv4Tests(unittest.TestCase):
    def _ipv4_udp(self, src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80, payload=b"hello"):
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + 8 + len(payload), 1, 0x4000, 64, pa.IP_PROTO_UDP, 0,
            socket.inet_aton(src), socket.inet_aton(dst),
        )
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        return _pack_eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", pa.ETH_P_IP) + ip + udp

    def test_ipv4_udp(self):
        f = self._ipv4_udp()
        d = pa.decode_frame(f + b"\x00" * 30)  # pad to min 60
        self.assertEqual(d["ipv4"]["src"], "10.0.0.1")
        self.assertEqual(d["ipv4"]["dst"], "10.0.0.2")
        self.assertEqual(d["udp"]["srcPort"], 12345)
        self.assertEqual(d["udp"]["dstPort"], 80)

    def test_ipv4_tcp_syn(self):
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 40, 1, 0x4000, 64, pa.IP_PROTO_TCP, 0,
            socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"),
        )
        tcp = struct.pack("!HHIIHHHH", 12345, 80, 1, 0, (5 << 12) | 0x002, 65535, 0, 0)
        f = _pack_eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", pa.ETH_P_IP) + ip + tcp
        d = pa.decode_frame(f + b"\x00" * 20)
        self.assertEqual(d["tcp"]["srcPort"], 12345)
        self.assertEqual(d["tcp"]["dstPort"], 80)
        self.assertIn("SYN", d["tcp"]["flags"])

    def test_dns_query(self):
        # DNS standard query for example.com
        dns = struct.pack("!HHHHHH", 0xabcd, 0x0100, 1, 0, 0, 0)
        dns += b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + 8 + len(dns), 1, 0x4000, 64, pa.IP_PROTO_UDP, 0,
            socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"),
        )
        udp = struct.pack("!HHHH", 12345, 53, 8 + len(dns), 0) + dns
        f = _pack_eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", pa.ETH_P_IP) + ip + udp
        d = pa.decode_frame(f)
        self.assertEqual(d["dns"]["id"], 0xabcd)
        self.assertEqual(d["dns"]["qr"], "query")
        self.assertEqual(d["dns"]["qdCount"], 1)

    def test_icmp_dest_unreachable_inner(self):
        inner_ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0x4000, 64, pa.IP_PROTO_UDP, 0,
            socket.inet_aton("9.9.9.9"), socket.inet_aton("8.8.8.8"),
        )
        inner_udp = struct.pack("!HHHH", 50000, 53, 8, 0)
        icmp = struct.pack("!BBHHH", 3, 3, 0, 0, 0) + inner_ip + inner_udp
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0x4000, 64, pa.IP_PROTO_ICMP, 0,
            socket.inet_aton("8.8.8.8"), socket.inet_aton("9.9.9.9"),
        )
        f = _pack_eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", pa.ETH_P_IP) + ip + icmp
        d = pa.decode_frame(f)
        self.assertEqual(d["icmp"]["type"], 3)
        self.assertIn("inner", d["icmp"])
        self.assertEqual(d["icmp"]["inner"]["dstPort"], 53)


class IPv6Tests(unittest.TestCase):
    def test_ipv6_udp(self):
        flow = (6 << 28).to_bytes(4, "big") + (8).to_bytes(2, "big") + bytes([pa.IP_PROTO_UDP, 64])
        src = socket.inet_pton(socket.AF_INET6, "fe80::1")
        dst = socket.inet_pton(socket.AF_INET6, "fe80::2")
        udp = struct.pack("!HHHH", 1234, 5678, 8, 0)
        f = _pack_eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", pa.ETH_P_IPV6) + flow + src + dst + udp
        d = pa.decode_frame(f)
        self.assertEqual(d["ipv6"]["src"], "fe80::1")
        self.assertEqual(d["ipv6"]["dst"], "fe80::2")
        self.assertEqual(d["udp"]["dstPort"], 5678)


class L2Tests(unittest.TestCase):
    def test_arp_request(self):
        arp = struct.pack(
            "!HHBBH", 1, pa.ETH_P_IP, 6, 4, 1
        ) + pa.mac_to_bytes("aa:bb:cc:dd:ee:01") + socket.inet_aton("10.0.0.1")
        arp += pa.mac_to_bytes("00:00:00:00:00:00") + socket.inet_aton("10.0.0.2")
        f = _pack_eth("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:01", pa.ETH_P_ARP) + arp
        d = pa.decode_frame(f + b"\x00" * 18)
        self.assertEqual(d["arp"]["operation"], 1)
        self.assertEqual(d["arp"]["senderIp"], "10.0.0.1")
        self.assertEqual(d["arp"]["targetIp"], "10.0.0.2")

    def test_lldp_tlvs(self):
        def tlv(t, v):
            return struct.pack("!H", ((t & 0x7F) << 9) | (len(v) & 0x1FF)) + v
        body = (
            tlv(1, bytes([4]) + pa.mac_to_bytes("aa:bb:cc:dd:ee:01"))
            + tlv(2, bytes([5]) + b"port-1")
            + tlv(3, struct.pack("!H", 120))
            + tlv(5, b"router")
            + tlv(0, b"")
        )
        f = _pack_eth("01:80:c2:00:00:0e", "aa:bb:cc:dd:ee:01", pa.ETH_P_LLDP) + body
        d = pa.decode_frame(f)
        self.assertEqual(d["lldp"]["tlvCount"], 4)
        sysname = next(t for t in d["lldp"]["tlvs"] if t["name"] == "SystemName")
        self.assertEqual(sysname["value"], "router")

    def test_ptp_announce(self):
        ptp = bytes([0x0b, 0x02]) + (64).to_bytes(2, "big") + bytes([0, 0]) + (0x0008).to_bytes(2, "big") + bytes(28)
        f = _pack_eth("01:1b:19:00:00:00", "aa:bb:cc:dd:ee:01", pa.ETH_P_PTP) + ptp
        d = pa.decode_frame(f)
        self.assertEqual(d["ptp"]["messageName"], "Announce")


class PayloadTests(unittest.TestCase):
    def test_prbs_deterministic(self):
        # Same seed/order ⇒ same bytes (essential for receiver-side BER comparison)
        a = pa.payload_bytes({"payload": {"mode": "prbs", "size": 32, "order": 23, "seed": 0x7fffff}})
        b = pa.payload_bytes({"payload": {"mode": "prbs", "size": 32, "order": 23, "seed": 0x7fffff}})
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_benchmark_marker(self):
        p = pa.payload_bytes({"payload": {"mode": "benchmark", "size": 64, "start": 99}}, sequence=99)
        self.assertEqual(p[:4], b"KETI")
        seq, ts_ns = struct.unpack("!IQ", p[4:16])
        self.assertEqual(seq, 99)
        self.assertGreater(ts_ns, 1_700_000_000_000_000_000)


if __name__ == "__main__":
    unittest.main()
