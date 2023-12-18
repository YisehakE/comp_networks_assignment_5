#!/usr/bin/python3

import argparse
import asyncio
import json
import os
import socket
import sys

from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from forwarding_table import ForwardingTable
from prefix import *

#FIXME
from scapy.all import Ether, IP, ARP

#From /usr/include/linux/if_ether.h:
ETH_P_IP = 0x0800 # Internet Protocol packet
ETH_P_ARP = 0x0806 # Address Resolution packet

#From /usr/include/net/if_arp.h:
ARPHRD_ETHER = 1 # Ethernet 10Mbps
ARPOP_REQUEST = 1 # ARP request
ARPOP_REPLY = 2 # ARP reply

#From /usr/include/linux/in.h:
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class Host(BaseHost):
    def __init__(self, ip_forward):
        super(Host, self).__init__()

        self._ip_forward = ip_forward
        self._arp_table = {}
        self.pending = []

        # do any additional initialization here

        self.forwarding_table = ForwardingTable()
        routes = json.loads(os.environ['COUGARNET_ROUTES'])
        for prefix, intf, next_hop in routes:
            self.forwarding_table.add_entry(prefix, intf, next_hop)

        for intf in self.physical_interfaces:
            prefix = '%s/%d' % \
                    (self.int_to_info[intf].ipv4_addrs[0],
                            self.int_to_info[intf].ipv4_prefix_len)
            self.forwarding_table.add_entry(prefix, intf, None)

    def _handle_frame(self, frame, intf):
        eth = Ether(frame)
        if eth.dst == 'ff:ff:ff:ff:ff:ff' or eth.dst == self.int_to_info[intf].mac_addr:

            if eth.type == ETH_P_IP:
                self.handle_ip(bytes(eth.payload), intf)
            elif eth.type == ETH_P_ARP:
                self.handle_arp(bytes(eth.payload), intf)
        else:
            self.not_my_frame(frame, intf)

    def handle_ip(self, pkt, intf):
        ip = IP(pkt)
        all_addrs = []
        ip_bcast = self.bcast_for_int(intf)

        for intf1 in self.int_to_info:
            all_addrs += self.int_to_info[intf1].ipv4_addrs

        if ip.dst == '255.255.255.255' or ip.dst == ip_bcast or ip.dst in all_addrs:
            if ip.proto == IPPROTO_TCP:
                self.handle_tcp(pkt)
            elif ip.proto == IPPROTO_UDP:
                self.handle_udp(pkt)
        else:
            self.not_my_packet(pkt, intf)

    def handle_tcp(self, pkt):
        pass

    def handle_udp(self, pkt):
        pass

    def handle_arp(self, pkt, intf):
        arp = ARP(pkt)
        if arp.op == ARPOP_REQUEST:
            self.handle_arp_request(bytes(pkt), intf)
        else:
            self.handle_arp_response(bytes(pkt), intf)

    def handle_arp_response(self, pkt, intf):
        pkt = ARP(pkt)
        self._arp_table[pkt.psrc] = pkt.hwsrc
        for pkt1, next_hop1, intf1 in self.pending[:]:
            if next_hop1 == pkt.psrc and intf1 == intf:
                eth = Ether(src=self.int_to_info[intf1].mac_addr, dst=self._arp_table[next_hop1], type=ETH_P_IP)
                frame = eth / pkt1
                self.send_frame(bytes(frame), intf1)
                self.pending.remove((pkt1, next_hop1, intf1))

    def handle_arp_request(self, pkt, intf):
        pkt = ARP(pkt)
        if pkt.pdst == self.int_to_info[intf].ipv4_addrs[0]:
            self._arp_table[pkt.psrc] = pkt.hwsrc
            eth = Ether(src=self.int_to_info[intf].mac_addr, dst=pkt.hwsrc, type=ETH_P_ARP)
            arp = ARP(hwsrc=self.int_to_info[intf].mac_addr, psrc=pkt.pdst,
                    hwdst=pkt.hwsrc, pdst=pkt.psrc, op=ARPOP_REPLY)
            frame = eth / arp
            self.send_frame(bytes(frame), intf)

    def send_packet_on_int(self, pkt, intf, next_hop):
        print(f'Attempting to send packet on {intf} with next hop {next_hop}:\n{repr(pkt)}')

        ip_bcast = self.bcast_for_int(intf)
        eth, frame, arp = None, None, None

        if ip_bcast == next_hop:
            eth = Ether(src=self.int_to_info[intf].mac_addr, dst='ff:ff:ff:ff:ff:ff', type=ETH_P_IP)
            frame = eth / pkt
            self.send_frame(bytes(frame), intf)    
        elif next_hop in self._arp_table:
            eth = Ether(src=self.int_to_info[intf].mac_addr, dst=self._arp_table[next_hop], type=ETH_P_IP)
            frame = eth / pkt
            self.send_frame(bytes(frame), intf)
        else:
            eth = Ether(src=self.int_to_info[intf].mac_addr, dst='ff:ff:ff:ff:ff:ff', type=ETH_P_ARP)
            arp = ARP(hwsrc=self.int_to_info[intf].mac_addr,
                    psrc=self.int_to_info[intf].ipv4_addrs[0],
                    pdst=next_hop, op=ARPOP_REQUEST)
            frame = eth / arp
            self.send_frame(bytes(frame), intf)
            self.pending.append((pkt, next_hop, intf))

    def send_packet(self, pkt):
        print(f'Attempting to send packet:\n{repr(pkt)}')
        ip = IP(pkt)
        intf, next_hop = self.forwarding_table.get_entry(ip.dst)
        if next_hop is None:
            next_hop = ip.dst
        if intf is None:
            return
        self.send_packet_on_int(pkt, intf, next_hop)

    def forward_packet(self, pkt):
        ip = IP(pkt)
        ip.ttl -= 1
        if ip.ttl <= 0:
            return
        self.send_packet(bytes(pkt))

    def not_my_frame(self, frame, intf):
        pass

    def not_my_packet(self, pkt, intf):
        #return #XXX
        if self._ip_forward:
            self.forward_packet(pkt)
        else:
            pass
        

    def bcast_for_int(self, intf: str) -> str:
        ip_int = ip_str_to_int(self.int_to_info[intf].ipv4_addrs[0])
        ip_prefix_int = ip_prefix(ip_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        ip_bcast_int = ip_prefix_last_address(ip_prefix_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        bcast = ip_int_to_str(ip_bcast_int, socket.AF_INET)
        return bcast

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    with Host(args.router) as host:
        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
