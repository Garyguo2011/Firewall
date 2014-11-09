from rulesPool import Rule

################### Infrastructure ####################
class MatchRulesPool(object):
	def __init__(self):
		self.pool = []

	def add (self, rule):
		if type(rule) is Rule:
			self.pool.append(rule.getIndex(), rule.getVerdict())

	def isPass(self):

	def size(self):
		return len(self.pool)

	def isEmpty(self):
		return len(self.pool) == 0

################### IP layer ####################
class Archive(object):
	def __init__(self, pkt_dir, pkt):
		# IPv4 parsing rule need here
		# In another word, All of Archive has IP Header
		self.direction = pkt_dir
		self.protocol
		self.externalIP       #IP stor as number
		self.countryCode      # need look up CountryCodeDirectionary
		self.packet           # Exact packet (i.e. str version of original packet)
		self.matchRules = RulePool()

	def __str__(self):
		return ""
		# implement for debugging purpose


################### Transport layer ####################
class TCPArchive (Archive):
	def __init__(self, pkt_dir, pkt):
		# Packet is String Type
		# Need to implement TCP parsing rule
		self.externalPort
		Archive.__init__(self, pkt_dir, pkt)
		
class UDPArchive (Archive):
	def __init__(self, pkt_dir, pkt):
		# Packet is String Type
		# Need to implement UDP parsing rule
		self.externalPort
		Archive.__init__(self, pkt_dir, pkt)
		
class ICMPArchive (Archive):
	def __init__(self, pkt_dir, pkt):
		# Packet is String Type
		# Need to implement UDP parsing rule
		# ICMP has type field
		self.type
		Archive.__init__(self, pkt_dir, pkt)

################### Application layer ####################
class DNSArchive(UDPArchive):
	def __init__(self, pkt_dir, pkt):
		# DNSArchieve build on top of UDPArchive
		self.app = "dns"
		self.domainName
		UDPArchive.__init__(self, pkt_dir, pkt)