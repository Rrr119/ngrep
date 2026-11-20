#!/usr/bin/env python3
"""
Generate deterministic pcap fixtures for the ngrep five-tuple / -o tests.

Only the Python standard library is used, so the fixtures can be regenerated
on any machine without scapy/tcpdump/text2pcap.  All files are classic
libpcap format (magic 0xa1b2c3d4), linktype DLT_EN10MB (Ethernet).
"""

import os
import struct
import sys

DLT_EN10MB = 1
ETH_HLEN = 14
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(ethertype, payload):
    dst = b"\x02\x00\x00\x00\x00\x01"
    src = b"\x02\x00\x00\x00\x00\x02"
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ident=1):
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total_len = 20 + len(payload)
    ver_ihl = 0x45
    tos = 0
    flags_frag = 0
    ttl = 64
    hdr = struct.pack("!BBHHHBBH", ver_ihl, tos, total_len, ident,
                      flags_frag, ttl, proto, 0) + src_b + dst_b
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(src, dst, nxt, payload):
    src_b = socket_inet_pton6(src)
    dst_b = socket_inet_pton6(dst)
    ver_tc_fl = 0x60000000
    hdr = struct.pack("!IHBB", ver_tc_fl, len(payload), nxt, 64) + src_b + dst_b
    return hdr + payload


def socket_inet_pton6(addr):
    head, _, tail = addr.partition("::")
    head_parts = [int(x, 16) for x in head.split(":")] if head else []
    tail_parts = [int(x, 16) for x in tail.split(":")] if tail else []
    missing = 8 - len(head_parts) - len(tail_parts)
    parts = head_parts + [0] * missing + tail_parts
    return b"".join(struct.pack("!H", p) for p in parts)


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12),
                      0xFFFF, flags, 0)
    pseudo_checksum = 0
    return hdr + payload, pseudo_checksum


def udp(sport, dport, payload):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    return hdr + payload


class PcapWriter:
    def __init__(self, path):
        self.path = path
        self.frames = []
        self.ts = 1_700_000_000

    def add(self, frame):
        self.frames.append((self.ts, 0, frame))
        self.ts += 1

    def save(self):
        with open(self.path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                65535, DLT_EN10MB))
            for ts_sec, ts_usec, frame in self.frames:
                f.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame),
                                    len(frame)))
                f.write(frame)


def build_tcp_flow(path):
    """Five-tuple + payload combination matching over TCP."""
    pw = PcapWriter(path)

    # Matching flow 10.0.0.1:12345 -> 10.0.0.2:80, payload contains "user=admin"
    seg, _ = tcp(12345, 80, b"POST /login HTTP/1.1\r\nuser=admin\r\n")
    pw.add(ethernet(0x0800, ipv4("10.0.0.1", "10.0.0.2", IPPROTO_TCP, seg, 1)))

    # Same five-tuple but payload without the pattern.
    seg, _ = tcp(12345, 80, b"GET /index.html HTTP/1.1\r\n", seq=2)
    pw.add(ethernet(0x0800, ipv4("10.0.0.1", "10.0.0.2", IPPROTO_TCP, seg, 2)))

    # Pattern present, but a different (reversed) five-tuple.
    seg, _ = tcp(80, 12345, b"HTTP/1.1 200 OK\r\nuser=admin\r\n")
    pw.add(ethernet(0x0800, ipv4("10.0.0.2", "10.0.0.1", IPPROTO_TCP, seg, 3)))

    # Same hosts/ports, different transport protocol (UDP): tuple mismatch.
    pw.add(ethernet(0x0800,
                    ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                         udp(12345, 80, b"user=admin over udp"), 4)))

    # Different ports on the same hosts: tuple mismatch.
    seg, _ = tcp(4444, 443, b"user=admin elsewhere")
    pw.add(ethernet(0x0800, ipv4("10.0.0.1", "10.0.0.2", IPPROTO_TCP, seg, 5)))

    pw.save()


def build_udp_pcre(path):
    """UDP traffic for -o PCRE-style output, including capture groups."""
    pw = PcapWriter(path)

    pw.add(ethernet(0x0800,
                    ipv4("192.168.1.10", "8.8.8.8", IPPROTO_UDP,
                         udp(53000, 53, b"query name=alpha.example.com tail"), 1)))
    pw.add(ethernet(0x0800,
                    ipv4("192.168.1.10", "8.8.8.8", IPPROTO_UDP,
                         udp(53001, 53,
                             b"secret=hunter2 and secret=hunter3 end"), 2)))
    pw.add(ethernet(0x0800,
                    ipv4("192.168.1.11", "8.8.8.8", IPPROTO_UDP,
                         udp(53002, 53, b"nothing interesting here"), 3)))
    pw.add(ethernet(0x0800,
                    ipv4("192.168.1.10", "1.1.1.1", IPPROTO_UDP,
                         udp(53003, 53, b"secret=only-on-other-dns"), 4)))

    pw.save()


def build_ipv6_binary(path):
    """IPv6 + binary (-X) matching, wildcards and mixed-protocol traffic."""
    pw = PcapWriter(path)

    # IPv6 UDP packets with a binary marker.
    pw.add(ethernet(0x86DD,
                    ipv6("2001:db8::1", "2001:db8::2", IPPROTO_UDP,
                         udp(40000, 53, b"\xde\xad\xbe\xef payload one"))))
    pw.add(ethernet(0x86DD,
                    ipv6("2001:db8::1", "2001:db8::2", IPPROTO_UDP,
                         udp(40001, 53, b"prefix \xde\xad\xbe\xef suffix"))))

    # IPv6 TCP packet with the same marker (different protocol).
    seg, _ = tcp(40002, 80, b"\xde\xad\xbe\xef over tcp")
    pw.add(ethernet(0x86DD,
                    ipv6("2001:db8::1", "2001:db8::2", IPPROTO_TCP, seg)))

    # IPv6 ICMPv6 packet (no ports).
    icmp6 = struct.pack("!BBH", 128, 0, 0) + b"\x00" * 4
    pw.add(ethernet(0x86DD,
                    ipv6("2001:db8::1", "2001:db8::2", IPPROTO_ICMPV6, icmp6)))

    # IPv4 UDP packet with the marker (different address family).
    pw.add(ethernet(0x0800,
                    ipv4("172.16.0.1", "172.16.0.2", IPPROTO_UDP,
                         udp(40003, 53, b"\xde\xad\xbe\xef over v4"))))

    pw.save()


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(__file__)
    os.makedirs(outdir, exist_ok=True)

    build_tcp_flow(os.path.join(outdir, "tcp-flow.pcap"))
    build_udp_pcre(os.path.join(outdir, "udp-pcre.pcap"))
    build_ipv6_binary(os.path.join(outdir, "ipv6-binary.pcap"))

    for name in ("tcp-flow.pcap", "udp-pcre.pcap", "ipv6-binary.pcap"):
        print("wrote", os.path.join(outdir, name))


if __name__ == "__main__":
    main()
