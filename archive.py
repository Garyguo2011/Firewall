from rulesPool import Rule
from countryCodeDirectionary import *
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time


################### IP layer ####################
class Archive(object):
	def __init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip):
		# IPv4 parsing rule need here
		# In another word, All of Archive has IP Header
		self.direction = pkt_dir
		self.protocol = protocol
		if pkt_dir = PKT_DIR_INCOMING:
			self.externalIP = src_ip       #IP store as number
		else:
			self.externalIP = dst_ip
		self.countryCode = countryCodeDictionary.lookup(externalIP)      # need look up CountryCodeDirectionary
		self.packet = pkt           # Exact packet (i.e. str version of original packet)
		self.verdict = True

	def __str__(self):
		return ""
		# implement for debugging purpose


################### Transport layer ####################
class TCPArchive (Archive):
	def __init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip):
		# Packet is String Type
		# Need to implement TCP parsing rule
		if pkt_dir = PKT_DIR_INCOMING:
			self.externalPort = struct.unpack('!H', pkt[20:22])
		else:
			self.externalPort = struct.unpack('!H', pkt[22:24])
		Archive.__init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip)
		
class UDPArchive (Archive):
	def __init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip):
		# Packet is String Type
		# Need to implement UDP parsing rule
		if pkt_dir = PKT_DIR_INCOMING:
			self.externalPort = struct.unpack('!H', pkt[20:22])
		else:
			self.externalPort = struct.unpack('!H', pkt[22:24])
		Archive.__init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip):
		
class ICMPArchive (Archive):
	def __init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip):
		# Packet is String Type
		# Need to implement UDP parsing rule
		# ICMP has type field
		self.type = ord(pkt[20:21])
		Archive.__init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip)

################### Application layer ####################
class DNSArchive(UDPArchive):
	def __init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip):
		# DNSArchieve build on top of UDPArchive
		self.app = "dns"
		self.domainName = 
		UDPArchive.__init__(self, pkt_dir, pkt, protocol, src_ip, dst_ip)
