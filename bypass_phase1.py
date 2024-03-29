#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

# Later move to firewall.py
# Import from archive.py
from archive import TCPArchive, UDPArchive, ICMPArchive, DNSArchive, Archive
from firewall import TCP_PROTOCOL_NUM, UDP_PROTOCOL_NUM, ICMP_PROTOCOL_NUM
from countryCodeDict import CountryCodeDict

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.countryCodeDict = CountryCodeDict('geoipdb.txt')
        self.count = 0

        print 'bypass Phase 1 mode!'
        # construct a CountryCodeDict
        
    def handle_packet(self, pkt_dir, pkt):
        protocolInt = ord(pkt[9:10])
        if self.count <=1 and protocolInt == 6:
            f = open ('tcppacketpool' + str(self.count), 'w')
            f.write(pkt)
            self.count += 1
        dst_ip = pkt[16:20]

        archive = self.packet_allocator(pkt_dir, pkt, self.countryCodeDict)
        print(archive)
        #    ... and simply allow the packet.
        self.default_allow(pkt_dir, pkt)

    def packet_allocator(self, pkt_dir, pkt, countryCodeDict):
        protocolNumber = ord(pkt[9:10]) # parse pkt and get protocol
        if protocolNumber == TCP_PROTOCOL_NUM:
            return TCPArchive(pkt_dir, pkt, self.countryCodeDict)
        elif protocolNumber == UDP_PROTOCOL_NUM:
            if self.is_DNS_query_packet(pkt_dir, pkt):
                return DNSArchive(pkt_dir, pkt, self.countryCodeDict)
            else:
                return UDPArchive(pkt_dir, pkt, self.countryCodeDict)
        elif protocolNumber == ICMP_PROTOCOL_NUM:
            return ICMPArchive(pkt_dir, pkt, self.countryCodeDict)
        else:
            self.default_allow(pkt_dir, pkt)
            return None	

    def is_DNS_query_packet(self, pkt_dir, pkt):
        ipLength = (15 & ord(pkt[0:1])) * 4
        dst_port = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
        qdcount = struct.unpack('!H', pkt[(ipLength + 12):(ipLength + 14)])[0]
        qNameLength = self.getQNameLength(pkt_dir, pkt)
        qtype = struct.unpack('!H', pkt[(ipLength + 20 + qNameLength):(ipLength + 22 + qNameLength)])[0]
        qclass = struct.unpack('!H', pkt[(ipLength + 22 + qNameLength):(ipLength + 24 + qNameLength)])[0]
        # print str(dst_port)
        # print str(qdcount)
        if pkt_dir == PKT_DIR_OUTGOING and dst_port == 53 and qdcount == 1 and qclass == 1:
            if qtype == 1 or qtype ==28:
                return True
        return False

    def default_allow(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def getQNameLength(self, pkt_dir, pkt):
        ipLength = (15 & ord(pkt[0:1])) * 4
        countByte = 0
        indicator = ord(pkt[(ipLength + 20):(ipLength + 21)])
        while (indicator != 0):
            countByte = indicator + countByte + 1
            indicator = ord(pkt[(ipLength + 20 + countByte):(ipLength + 21 + countByte)])
        countByte += 1
        return countByte