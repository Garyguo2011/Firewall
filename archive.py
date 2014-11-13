# from rulesPool import Rule
from countryCodeDict import CountryCodeDict
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time


TCP_PROTOCOL = "tcp"
UDP_PROTOCOL = "udp"
ICMP_PROTOCOL = "icmp"
DNS_APP = "dns"
LETTER = "abcdefghijklmnopqrstuvwxyz"
ANY = "any"
PASS_STR = "pass"
DROP_STR = "drop"
PASS = True
DROP = False
MAX_PORTNUM = 65535
DEFAULT_POLICY = PASS
DEBUG = False

################### IP layer ####################
class Archive(object):
	def __init__(self, pkt_dir, pkt):
		# IPv4 parsing rule need here
		# In another word, All of Archive has IP Header
		self.direction = pkt_dir
		protocolInt = ord(pkt[9:10])
		if protocolInt == 1:
			self.protocol = ICMP_PROTOCOL
		elif protocolInt == 6:
			self.protocol = TCP_PROTOCOL
		elif protocolInt == 17:
			self.protocol = UDP_PROTOCOL
		if pkt_dir == PKT_DIR_INCOMING:
			src_ip = pkt[12:16]
			self.externalIP = src_ip       #IP store as number
		else:
			dst_ip = pkt[16:20]
			self.externalIP = dst_ip
		# self.countryCode = countryCodeDict.lookup(externalIP)      # need look up CountryCodeDirectionary
		self.packet = pkt           # Exact packet (i.e. str version of original packet)
		self.verdict = True

	
		# implement for debugging purpose


################### Transport layer ####################
class TCPArchive (Archive):
	def __init__(self, pkt_dir, pkt):
		# Packet is String Type
		# Need to implement TCP parsing rule
		ipLength = (15 & ord(pkt[0:1])) * 4
		if pkt_dir == PKT_DIR_INCOMING:
			self.externalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]
		else:
			self.externalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
		Archive.__init__(self, pkt_dir, pkt)

		
class UDPArchive (Archive):
	def __init__(self, pkt_dir, pkt):
		# Packet is String Type
		# Need to implement UDP parsing rule
		ipLength = (15 & ord(pkt[0:1])) * 4
		if pkt_dir == PKT_DIR_INCOMING:
			self.externalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]
		else:
			self.externalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
		Archive.__init__(self, pkt_dir, pkt)
		
class ICMPArchive (Archive):
	def __init__(self, pkt_dir, pkt):
		# Packet is String Type
		# Need to implement UDP parsing rule
		# ICMP has type field
		ipLength = (15 & ord(pkt[0:1])) * 4
		self.type = ord(pkt[ipLength:(ipLength + 1)])
		Archive.__init__(self, pkt_dir, pkt)

################### Application layer ####################
class DNSArchive(UDPArchive):
	def __init__(self, pkt_dir, pkt):
		# DNSArchieve build on top of UDPArchive
		self.app = DNS_APP
		self.domainName = self.findDomainName(pkt_dir, pkt)
		UDPArchive.__init__(self, pkt_dir, pkt)

	def findDomainName(self, pkt_dir, pkt):
		ipLength = (15 & ord(pkt[0:1])) * 4
		indicator = ord(pkt[(ipLength + 20):(ipLength + 21)])
		domainName = ''
		countByte = 0
		while (indicator != 0):
			for i in range(1, indicator + 1):
				elemInt = ord(pkt[(ipLength + 20 + countByte + i):(ipLength + 21 + countByte + i)])
				elem = chr(elemInt)
				domainName = domainName + elem
			countByte = indicator + countByte + 1
			indicator = ord(pkt[(ipLength + 20 + countByte):(ipLength + 21 + countByte)])
			if (indicator != 0):
				domainName = domainName + '.'
		return domainName

