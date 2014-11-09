# Infrastructure

class Rule(object):
    def __init__(self, index, verdict):
        self.index = index                  # record where did the rule occur in conf file
        self.verdict = verdict              # [1: pass 0: drop]

    def __str__(self):
        return "index: %d | verdict: %s | " % (self.index, self.verdict)

    def getIndex(self):
        return self.index

    def getVerdict(self):
        return self.verdict

class GeneralRule(Rule):        # Protocol/IP/Port Rules
    def __init__(self, index, verdict, protocol, isIPPrefix, ipNum, ipPrefixNum, countryCode):
        self.protocol = protocol
        self.isIPPrefix = isIPPrefix                   # [IPPrefix / GeoIP]
        self.ipPrefixContent = (ipNum, ipPrefixNum)    # any = 0.0.0.0/0  1.2.3.4 = 1.2.3.4/32
        self.countryCode = countryCode
        Rule.__init__(self, index, verdict)

    def __str__(self):
        return Rule.__str__(self) + " protocol: %s | isIPPrefix: %s | ipPrefixContent: %s | countryCode: %s| " % (self.protocol, self.isIPPrefix, self.ipPrefixContent, self.countryCode)

###############################################################################################
# Unit of Rules

class DNSRule(Rule):
    def __init__(self, ruleStr):
        # ruleStr is type String need to parsing
        # Need DNS Rule parsing
        self.app = "dns"
        self.isPostfix
        self.postfix
        Rule.__init__(self, index, verdict)

    def __str__(self):
        return "[DNSRule]:" + Rule.__str__(self) +  "app: %s | isPostfix: %s | postfix: %s" % (self.app, self.isPostfix, self.postfix)

# Important: we have already make sure what protocol is before pass into constructor
class ICMPRule(GeneralRule):
    def __init__(self, ....):
        # ruleStr is type String need to parsing
        # Need ICMP Rule parsing
        self.type
        protocol = "icmp"
        GeneralRule.__init__(self, index, verdict, protocol, isIPPrefix, ipNum, ipPrefixNum, countryCode)

    def __str__(self):
        return "[ICMPRule]:" + GeneralRule.__str__(self) + "type: %s" % (self.type)

class UDPRule(GeneralRule):
    def __init__(self, ruleStr):
        # ruleStr is type String need to parsing
        # Need UDP Rule parsing
        self.exPortLower
        self.exportUpper       # single number a =  range(a, a)
        protocol = "udp"
        GeneralRule.__init__(self, index, verdict, protocol, isIPPrefix, ipNum, ipPrefixNum, countryCode)

    def __str__(self):
        return "[UDPRule]:" + GeneralRule.__str__(self) + "PortRange[%d, %d]" % (self.exPortLower, self.exportUpper)

class TCPRule(GeneralRule):
    def __init__(self, ruleStr):
        # ruleStr is type String need to parsing
        # Need TCP Rule parsing
        self.exPortLower
        self.exportUpper
        protocol = "tcp"
        GeneralRule.__init__(self, index, verdict, protocol, isIPPrefix, ipNum, ipPrefixNum, countryCode)

    def __str__(self):
        return "[UDPRule]:" + GeneralRule.__str__(self) + "PortRange[%d, %d]" % (self.exPortLower, self.exportUpper)

###############################################################################################
# static rules pool and matching rules pool

class StaticRulesPool(object):
    def __init__(self, conffile):
        self.lst = []
        fptr = open (conffile)
        buf = fptr.readline()
        while buf != "" :
            rule = self.parseBuffer(buf)
            if rule:
                self.add(rule)

    def parseBuffer (self, buf):
        if buf == None or len(buf) == 0 or buf[0] == '%' or buf[0] == '\n':
            return None
        else:
            # add more parsing logic and
            # Important: Case Insensitivie need something like tolower()

    def size(self):
        return len(self.lst)

    def isEmpty(self):
        return len(self.lst) == 0

    def add(self, rule):
        if type(rule) in [ICMPRule, UDPRule, TCPRule, DNSRule]:
            self.lst.append(rule)