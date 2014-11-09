#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

TCP_PROTOCOL = "tcp"
UDP_PROTOCOL = "udp"
ICMP_PROTOCOL = "icmp"

PASS = 1
DROP = 0


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

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
