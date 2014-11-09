#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

# Later move to firewall.py
TCP_PROTOCOL_NUM = 1
UDP_PROTOCOL_NUM = 17
ICMP_PROTOCOL_NUM = 50

# Import from archive.py
from archive import TCPArchive, UDPArchive, ICMPArchive, DNSArchive
from countryCodeDict import CountryCodeDict

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        print 'bypass Phase 1 mode!'
        # construct a CountryCodeDict
        
    def handle_packet(self, pkt_dir, pkt):
        # The example code here prints out the source/destination IP addresses,
        # which is unnecessary for your submission.
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'

        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))
        print type(pkt)
        # print (pkt)

        # ... and simply allow the packet.
        self.default_allow(pkt_dir, pkt)

    def packet_allocator(self, pkt_dir, pkt):
        protocolNumber # parse pkt and get protocol
        if protocolNumber == TCP_PROTOCOL_NUM:
            return TCPArchive(pkt_dir, pkt)
        elif protocolNumber == UDP UDP_PROTOCOL_NUM:
            if is_DNS_query_packet(pkt_dir, pkt):
                return DNSArchive(pkt_dir, pkt)
            else
                return UDPArchive(pkt_dir,pkt)
        elif protocolNumber == ICMP_PROTOCOL_NUM:
            return ICMPArchive(pkt_dir, pkt)
        else:
            self.default_allow(pkt_dir, pkt

    def default_allow(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def is_DNS_query_packet(self, pkt_dir, pkt):
        pass