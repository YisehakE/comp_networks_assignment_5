from __future__ import annotations

import struct

from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str


IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
TCP_HEADER_LEN = 20
TCPIP_HEADER_LEN = IP_HEADER_LEN + TCP_HEADER_LEN
UDPIP_HEADER_LEN = IP_HEADER_LEN + UDP_HEADER_LEN

TCP_RECEIVE_WINDOW = 64

class IPv4Header:
    def __init__(self, length: int, ttl: int, protocol: int, checksum: int,
            src: str, dst: str) -> IPv4Header:
        self.length = length
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src = src
        self.dst = dst

    @classmethod
    def from_bytes(cls, hdr: bytes) -> IPv4Header:
        length, = struct.unpack('!H', hdr[2:4])
        ttl, = struct.unpack('!B', hdr[8:9])
        protocol, = struct.unpack('!B', hdr[9:10])
        checksum, = struct.unpack('!H', hdr[10:12])
        src = ip_binary_to_str(hdr[12:16])
        dst = ip_binary_to_str(hdr[16:20])
        return cls(length, ttl, protocol, checksum, src, dst)

    def to_bytes(self) -> bytes:
        hdr = b'\x45\x00'
        hdr += struct.pack('!H', self.length)
        hdr += b'\x00\x00\x00\x00'
        hdr += struct.pack('!B', self.ttl)
        hdr += struct.pack('!B', self.protocol)
        hdr += struct.pack('!H', self.checksum)
        hdr += ip_str_to_binary(self.src)
        hdr += ip_str_to_binary(self.dst)
        return hdr


class ICMPHeader:
    def __init__(self, typ: int, code: int, checksum: int) -> ICMPHeader:
        self.type = typ
        self.code = code
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, hdr: bytes) -> ICMPHeader:
        typ, = struct.unpack('!B', hdr[0:1])
        code, = struct.unpack('!B', hdr[1:2])
        checksum, = struct.unpack('!H', hdr[2:4])
        return cls(typ, code, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!B', self.type)
        hdr += struct.pack('!B', self.code)
        hdr += struct.pack('!H', self.checksum)
        return hdr


class UDPHeader:
    def __init__(self, sport: int, dport: int, length: int,
            checksum: int) -> UDPHeader:
        self.sport = sport
        self.dport = dport
        self.checksum = checksum
        self.length = length

    @classmethod
    def from_bytes(cls, hdr: bytes) -> UDPHeader:
        sport, = struct.unpack('!H', hdr[:2])
        dport, = struct.unpack('!H', hdr[2:4])
        length, = struct.unpack('!H', hdr[4:6])
        checksum, = struct.unpack('!H', hdr[6:8])
        return cls(sport, dport, length, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', self.sport)
        hdr += struct.pack('!H', self.dport)
        hdr += struct.pack('!H', self.length)
        hdr += struct.pack('!H', self.checksum)
        return hdr


class TCPHeader:
    def __init__(self, sport: int, dport: int, seq: int, ack: int,
            flags: int, checksum: int) -> TCPHeader:
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, hdr: bytes) -> TCPHeader:
        sport, = struct.unpack('!H', hdr[:2])
        dport, = struct.unpack('!H', hdr[2:4])
        seq, = struct.unpack('!I', hdr[4:8])
        ack, = struct.unpack('!I', hdr[8:12])
        flags, = struct.unpack('!B', hdr[13:14])
        checksum, = struct.unpack('!H', hdr[16:18])
        return cls(sport, dport, seq, ack, flags, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', self.sport)
        hdr += struct.pack('!H', self.dport)
        hdr += struct.pack('!I', self.seq)
        hdr += struct.pack('!I', self.ack)
        hdr += struct.pack('!B', (TCP_HEADER_LEN // 4) << 4)
        hdr += struct.pack('!B', self.flags)
        hdr += struct.pack('!H', TCP_RECEIVE_WINDOW)
        hdr += struct.pack('!H', self.checksum)
        hdr += b'\x00\x00'
        return hdr
