import os
import socket
import struct

from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str

from host import Host
from mysocket import UDPSocket, TCPSocketBase

class TransportHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.socket_mapping_udp = {}
        self.socket_mapping_tcp = {}

    def handle_tcp(self, pkt: bytes) -> None:
        ip_hdr = pkt[:20]
        src_ip = ip_binary_to_str(ip_hdr[12:16])
        dst_ip = ip_binary_to_str(ip_hdr[16:20])

        tcp_hdr = pkt[20:40]
        src_port, = struct.unpack('!H', tcp_hdr[:2])
        dst_port, = struct.unpack('!H', tcp_hdr[2:4])
        if (dst_ip, dst_port, src_ip, src_port) in self.socket_mapping_tcp:
            sock = self.socket_mapping_tcp[(dst_ip, dst_port, src_ip, src_port)]
            sock.handle_packet(pkt)
        elif (dst_ip, dst_port, None, None) in self.socket_mapping_tcp:
            sock = self.socket_mapping_tcp[(dst_ip, dst_port, None, None)]
            sock.handle_packet(pkt)
        else:
            self.no_socket_tcp(pkt)

    def handle_udp(self, pkt: bytes) -> None:
        ip_hdr = pkt[:20]
        src_ip = ip_binary_to_str(ip_hdr[12:16])
        dst_ip = ip_binary_to_str(ip_hdr[16:20])

        udp_hdr = pkt[20:28]
        src_port, = struct.unpack('!H', udp_hdr[:2])
        dst_port, = struct.unpack('!H', udp_hdr[2:4])
        if (dst_ip, dst_port) in self.socket_mapping_udp:
            sock = self.socket_mapping_udp[(dst_ip, dst_port)]
            sock.handle_packet(pkt)
        else:
            self.no_socket_udp(pkt)

    def install_socket_udp(self, local_addr: str, local_port: int,
            sock: UDPSocket) -> None:
        self.socket_mapping_udp[(local_addr, local_port)] = sock

    def install_listener_tcp(self, local_addr: str, local_port: int,
            sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, None, None)] = sock

    def install_socket_tcp(self, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int, sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, \
                remote_addr, remote_port)] = sock

    def no_socket_udp(self, pkt: bytes) -> None:
        from scapy.all import IP, ICMP
        ip = IP(pkt)
        newip = IP(src=ip.dst, dst=ip.src)
        icmp = ICMP(type=3, code=3)
        pkt = newip / icmp / pkt
        self.send_packet(bytes(pkt)) 

    def no_socket_tcp(self, pkt: bytes) -> None:
        from scapy.all import TCP, IP
        ip = IP(pkt)
        tcp = ip.getlayer(TCP)
        newip = IP(src=ip.dst, dst=ip.src)
        newtcp = TCP(sport=tcp.dport, dport=tcp.sport, flags=0x04)
        pkt = newip / newtcp
        self.send_packet(bytes(pkt)) 
