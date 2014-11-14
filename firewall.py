#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

from rulePool import StaticRulesPool
from countryCodeDict import CountryCodeDict
from archive import TCPArchive, UDPArchive, ICMPArchive, DNSArchive, Archive

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

import socket
import struct
import time

LETTER = "abcdefghijklmnopqrstuvwxyz"

PASS = True
DROP = False
PASS_STR = "pass"
DROP_STR = "drop"

TCP_PROTOCOL = "tcp"
TCP_PROTOCOL_NUM = 6
UDP_PROTOCOL = "udp"
UDP_PROTOCOL_NUM = 17
ICMP_PROTOCOL = "icmp"
ICMP_PROTOCOL_NUM = 1
DNS_APP = "dns"

ANY = "any"
MAX_PORTNUM = 65535

DEFAULT_POLICY = PASS
DEBUG = False

GEOIPDB_FILE = 'geoipdb.txt'

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.staticRulesPool = StaticRulesPool(config['rule'])
        self.countryCodeDict = CountryCodeDict(GEOIPDB_FILE)

        # TODO: Load the firewall rules (from rule_filename) here.
        print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                config['rule']

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        pass

    # TODO: You can add more methods as you want.
    def packet_allocator(self, pkt_dir, pkt):


    def is_DNS_query_packet(self, pkt_dir, pkt):
        # spce
        # return a bool value

# TODO: You may want to add more classes/functions as well.
