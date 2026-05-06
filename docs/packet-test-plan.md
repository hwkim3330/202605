# Packet test plan

Use this order. Do not start with TAS/PSFP. First prove the basic Ethernet path.

## 1. Basic communication

1. ARP Request/Reply
2. ICMP Echo
3. UDP Unicast

Check that destination/source MAC, EtherType, IPv4 checksum, UDP/ICMP fields, and payload are decoded correctly on the receiver.

## 2. Integrity

1. Sequence payload
2. AA55 pattern
3. Counter pattern
4. Random/repeat byte patterns when needed

Use sequence payloads to detect loss, duplication, and out-of-order delivery.

## 3. Frame size sweep

Test these frame sizes first:

- 64 bytes
- 128 bytes
- 256 bytes
- 512 bytes
- 1024 bytes
- 1514 bytes without FCS

`AF_PACKET` does not include Ethernet FCS. A 1514-byte untagged frame here corresponds to 1518 bytes on the wire including FCS.

## 4. VLAN and PCP

1. Untagged UDP
2. VLAN 10 PCP 0
3. VLAN 10 PCP 7
4. VLAN 20 isolation

Confirm that VLAN tag, VID, PCP, and payload are preserved through the path.

## 5. Switching behavior

1. Broadcast ARP
2. Unknown unicast
3. MAC learning
4. L2 multicast

Use additional capture PCs or switch counters when validating flooding and learning behavior.

## 6. Policy checks

1. MAC-based ACL candidate
2. VLAN-based ACL candidate
3. UDP port ACL candidate
4. Policing/rate limit candidate
5. Mirroring candidate

The included `ACL UDP Block Candidate` profile uses UDP destination port `60001`.

## 7. TSN preparation

1. Periodic UDP 1 ms
2. PCP 7 TAS candidate traffic
3. PCP 3/5 CBS candidate traffic
4. PSFP Stream A/B candidates

This tool is a functional packet generator, not a line-rate precision traffic generator. Use it to validate fields, forwarding, filtering, and basic timing behavior before moving to dedicated TSN/performance equipment.
