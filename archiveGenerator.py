# from rulesPool import Rule
from countryCodeDict import CountryCodeDict
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time

TCP_PROTOCOL = "tcp"
UDP_PROTOCOL = "udp"
ICMP_PROTOCOL = "icmp"

################### IP layer ####################
class Archive(object):
	def __init__(self, pkt_dir, protocol, externalIP, countryCode, packet, verdict):
		self.direction = pkt_dir
		self.protocol = protocol
		self.externalIP = self.ipstr_to_int(ipStr)
		self.countryCode = countryCode
		self.packet = packet
		self.verdict = True

	def ipstr_to_int(self, ipStr):
		fieldList = ipStr.split(".")
		return (int(fieldList[0]) << 24) + (int(fieldList[1]) << 16) + (int(fieldList[2]) << 8) + (int(fieldList[3]))

	def __str__(self):
		return ""
		# implement for debugging purpose

	def getDirection(self):
		return self.direction

	def getProtocol(self):
		return self.protocol

	def getExternalIP(self):
		return self.externalIP

	def getCountryCode(self):
		return self.countryCode

	def getPacket(self):
		return self.packet

	def getVerdict(self):
		return self.verdict

################### Transport layer ####################
class TCPArchive (Archive):
	def __init__(self, pkt_dir, protocol, externalIP, countryCode, packet, verdict, externalPort):
		self.externalPort = externalPort
		Archive.__init__(self, pkt_dir, TCP_PROTOCOL, externalIP, countryCode, packet, verdict)
	
	def getExternalPort():
		return self.getExternalPort

class UDPArchive (Archive):
	def __init__(self, pkt_dir, protocol, externalIP, countryCode, packet, verdict, externalPort):
		self.externalPort = externalPort
		Archive.__init__(self, pkt_dir, UDP_PROTOCOL, externalIP, countryCode, packet, verdict)

	def getExternalPort():
		return self.getExternalPort
		
class ICMPArchive (Archive):
	def __init__(self, pkt_dir, protocol, externalIP, countryCode, packet, verdict, inputtype):
		self.type = inputtype
		Archive.__init__(self, pkt_dir, ICMP_PROTOCOL, externalIP, countryCode, packet, verdict)

	def getType(self):
		return self.type

################### Application layer ####################
class DNSArchive(UDPArchive):
	def __init__(self, pkt_dir, protocol, externalIP, countryCode, packet, verdict, externalPort, app, domainName):
		self.app = app
		self.domainName = domainName
		UDPArchive.__init__(self, pkt_dir, UDP_PROTOCOL, externalIP, countryCode, packet, verdict, externalPort)

	def getDomainName():
		return self.domainName