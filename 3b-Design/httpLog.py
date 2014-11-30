class LogHttpRule(Rule):
	FULL = 0
	WILDCARD = 1
	IPADDRESS = 2
	
	def __init__(self, fieldList):
		Rule.__init__(self, PASS_STR)
		self.type
		self.postfix
		self.app

	def matches(self, archive):
		pass

	def handle(self, archive):
		pass

# 0a is way to seperate http payload
class HttpLog(object):
	def __init__(self):



class TCPConnectionsPool(object):
	def __init__(self):
		# Key: (External IP, Internal Port)
		# Value: Class Connection Entry
		self.connectionPool = {}

	def 

class ConnectionEntry(object):
	def __init__(self):
		self.expectSeq



class HTTPArchive()

