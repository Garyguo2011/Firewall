# Infrastructure

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

# Rule Interface [important: have to implement matches function]
class Rule(object):
    def __init__(self, verdictStr):
        # self.index = index                  # record where did the rule occur in conf file
        if verdictStr == PASS_STR:
            self.verdict = PASS              # [1: pass 0: drop]
        else:
            self.verdict = DROP

    def __str__(self):
        if self.verdict == True:
            strVerdict = "pass"
        else:
            strVerdict = "drop"
        if DEBUG:
            return "verdict: %s|" % (strVerdict)
        else:
            return "%s" % (strVerdict)

    def getVerdict(self):
        return self.verdict

    def matches(self, archive):
        pass

class GeneralRule(Rule):        # Protocol/IP/Port Rules
    def __init__(self, ruleStr):
        fieldList = ruleStr.lower().split("%")[0].split("\n")[0].split()
        assert len(fieldList) == 4 and (fieldList[1] == TCP_PROTOCOL or fieldList[1] == UDP_PROTOCOL or fieldList[1] == ICMP_PROTOCOL), "[ERROR] %r is no Proper General Rule"
        Rule.__init__(self, fieldList[0])
        self.protocol = fieldList[1]
        self.isIPPrefix = self.is_ip_prefix(fieldList[2])
        
        if self.isIPPrefix:
            self.ipPrefixContent = self.parse_ip_prefix(fieldList[2])
            self.countryCode = None
        else:
            self.ipPrefixContent = None
            self.countryCode = fieldList[2]

        self.externalPortRange = self.parse_port_range(fieldList[3])

    def is_ip_prefix(self, inputStr):
        if len(inputStr) == 2 and inputStr[0] in LETTER and inputStr[1] in LETTER:
            return False
        else:
            return True

    def parse_ip_prefix(self, inputStr):
        if inputStr == ANY:
            return 0, 0
        fieldList = inputStr.split("/")
        if len(fieldList) == 1:
            return self.ip_str_to_int(inputStr), 32
        elif len(fieldList) == 2:
            return self.ip_str_to_int(fieldList[0]), int(fieldList[1])
        else:
            print ("Syntax Error: " + inputStr)

    def ip_str_to_int(self, ipStr):
        fieldList = ipStr.split(".")
        if len (fieldList) == 4:
            return int(fieldList[0]) << 24 | int(fieldList[1]) << 16 | int(fieldList[2]) << 8 | int(fieldList[3])
        else:
            print ("Syntax Error: " + ipStr)

    def parse_port_range(self, inputStr):
        if inputStr == ANY:
            return 0, MAX_PORTNUM
        fieldList = inputStr.split("-")
        if len(fieldList) == 1:
            return int(fieldList[0]), int(fieldList[0])
        elif len(fieldList) == 2:
            return int(fieldList[0]), int(fieldList[1])
        else:
            print("Syntax Error: " + inputStr)

    # def matches (self, archive):
    #     if self.protocol_matches(archive) and self.external_ip_matches(archive) and \
    #        self.countrycode_matches(archive) and self.external_port_matches(archive):
    #         return self.Verdict
    #     else:
    #         return DEFAULT_POLICY

    # def protocol_matches(self, archive):
    #     self.protocol == archive.getProtocol()

    # def external_ip_matches(self, archive):
    #     if self.ipPrefixContent != None:
    #         return ((archive.getExternalIP() >> (32 - self.ipPrefixContent[1])) ^ \
    #                (self.ipPrefixContent[0] >> (32 - self.ipPrefixContent[1]))) == 0
    #     else:
    #         return True
    #         # Return True to pass skip this test because it is not ip prefix

    # def countrycode_matches(self, archive):
    #     if self.countryCode != None:
    #         return self.countryCode == archive.getCountryCode()
    #     else:
    #         return True
    #         # Return True to pass skip this test because it is ip prefix

    # def external_port_matches(self, archive):
    #     return self.externalPortRange[0] <= archive.getExternalPort() and archive.getExternalPort() <= self.externalPortRange[1]

    def __str__(self):
        ipPrefixContent_str = str(self.ipPrefixContent)
        if self.ipPrefixContent != None:
            if self.ipPrefixContent[0] == 0 and self.ipPrefixContent[1] == 0:
                ipPrefixContent_str = "any"
            else:
                ipStrList = []
                ipStrList.append((self.ipPrefixContent[0] >> 24) & 15)
                ipStrList.append((self.ipPrefixContent[0] >> 16) & 15)
                ipStrList.append((self.ipPrefixContent[0] >> 8) & 15)
                ipStrList.append((self.ipPrefixContent[0] >> 0) & 15)
                if self.ipPrefixContent[1] == 32:
                    ipPrefixContent_str = "%d.%d.%d.%d" % (ipStrList[0], ipStrList[1], ipStrList[2], ipStrList[3])    
                else:
                    ipPrefixContent_str = "%d.%d.%d.%d/%d" % (ipStrList[0], ipStrList[1], ipStrList[2], ipStrList[3], self.ipPrefixContent[1])
        externalPortRange_str = str(self.externalPortRange)
        if self.externalPortRange[0] == self.externalPortRange[1]:
            externalPortRange_str = str(self.externalPortRange[0])
        elif self.externalPortRange[0] == 0 and self.externalPortRange[1] == MAX_PORTNUM:
            externalPortRange_str = "any"

        if DEBUG:        
            return "[GeneralRule]|" + Rule.__str__(self) + " protocol: %s|isIPPrefix: %s|ipPrefixContent: %s|countryCode: %s|externalPortRange: %s" \
                                        % (self.protocol, self.isIPPrefix, ipPrefixContent_str, self.countryCode, self.externalPortRange)
        else:
            if self.isIPPrefix:
                return Rule.__str__(self) + " %s %s %s" \
                                    % (self.protocol, ipPrefixContent_str, externalPortRange_str)
            else:
                return Rule.__str__(self) + " %s %s %s" \
                                    % (self.protocol, self.countryCode, externalPortRange_str)

###############################################################################################
# Unit of Rules
class DNSRule(Rule):
    def __init__(self, ruleStr):
        # ruleStr is type String need to parsing
        # Need DNS Rule parsing
        fieldList = ruleStr.lower().split("%")[0].split("\n")[0].split()
        assert len(fieldList) == 3 and fieldList[1] == "dns", "[ERROR]: '%r' is not DNS Rule"
        Rule.__init__(self, fieldList[0])                # Set up Verdict
        self.app = fieldList[1]
        
        domainStr = fieldList[2]
        if len(domainStr) == 0:
            print("Parse Error: DNS Don't have domainStr")
        elif len(domainStr) == 1 and domainStr[1] == "*":
            self.isPostfix = True
            self.postfix = ""
        elif len(domainStr) >= 2 and domainStr[0:2] == "*.":
            self.isPostfix = True
            self.postfix = domainStr[1:]
        else:
            self.isPostfix = False
            self.postfix = domainStr

    # def matches (self, archive):
    #     if type(archive) == DNSArchive:
    #         return self.app_matches(archive) and self.domain_matches(archive)
    #     else:
    #         return DEFAULT_POLICY

    # def app_matches(self, archive):
    #     return self.app == archive.getApp()

    # def domain_matches(self, archive):
    #     if self.isPostfix:
    #         for i in range(0, len(archive.getDomainName())):
    #             if archive.getDomainName()[i:] == self.postfix:
    #                 return True
    #         return False
    #     else:
    #         return archive.getDomainName() == self.postfix

    def __str__(self):
        postfix_str = str(self.postfix)
        if self.isPostfix:
            postfix_str = "*" + str(self.postfix)
        if DEBUG:
            return "[DNSRule]|" + Rule.__str__(self) +  "app: %s | isPostfix: %s | postfix: %s" % (self.app, self.isPostfix, self.postfix)
        else:
            return Rule.__str__(self) +  " %s %s" % (self.app, postfix_str)

# Important: we have already make sure what protocol is before pass into constructor
# class ICMPRule(GeneralRule):
#     def __init__(self, ruleStr):
#         # ruleStr is type String need to parsing
#         # Need ICMP Rule parsing
#         fieldList = buf.lower().split(" ")
#         assert len(fieldList) == 3 and fieldList[1] == "icmp", "[ERROR]: '%r' is not icmp Rule"
#         self.type 
#         protocol = "icmp"
#         GeneralRule.__init__(self, index, verdict, protocol, isIPPrefix, ipNum, ipPrefixNum, countryCode)

#     def __str__(self):
#         return "[ICMPRule]:" + GeneralRule.__str__(self) + "type: %s" % (self.type)

# class UDPRule(GeneralRule):
#     def __init__(self, ruleStr):
#         # ruleStr is type String need to parsing
#         # Need UDP Rule parsing
#         self.lowerBound
#         self.upperBound       # single number a =  range(a, a)
#         protocol = "udp"
#         GeneralRule.__init__(self, index, verdict, protocol, isIPPrefix, ipNum, ipPrefixNum, countryCode)

#     def __str__(self):
#         return "[UDPRule]:" + GeneralRule.__str__(self) + "PortRange[%d, %d]" % (self.exPortLower, self.exportUpper)

# class TCPRule(GeneralRule):
#     def __init__(self, ruleStr):
#         # ruleStr is type String need to parsing
#         # Need TCP Rule parsing
#         self.exPortLower
#         self.exportUpper
#         protocol = "tcp"
#         GeneralRule.__init__(self, index, verdict, protocol, isIPPrefix, ipNum, ipPrefixNum, countryCode)

#     def __str__(self):
#         return "[UDPRule]:" + GeneralRule.__str__(self) + "PortRange[%d, %d]" % (self.exPortLower, self.exportUpper)

###############################################################################################
# static rules pool and matching rules pool

class StaticRulesPool(object):
    def __init__(self, conffile):
        self.rule_list = []
        try:
            fptr = open (conffile)
            buf = fptr.readline()
            while buf != "" :
                rule = self.parseBuffer(buf)
                if rule:
                    self.add(rule)
                buf = fptr.readline()
        except IOError:
            print ("'%s'" % (conffile))

    def parseBuffer (self, buf):
        if buf == None or len(buf) == 0 or buf[0] == '%' or buf[0] == '\n':
            return None
        else:
             # add more parsing logic and
            # Important: Case Insensitivie need something like tolower()
            fieldList = buf.lower().split("%")[0].split("\n")[0].split()
            assert (len(fieldList) == 3 or len(fieldList) == 4), "%r contains some syntax error"
            ruleType = fieldList[1]
            if ruleType == ICMP_PROTOCOL or ruleType == UDP_PROTOCOL or ruleType == TCP_PROTOCOL:
                return GeneralRule(buf)
            elif ruleType == DNS_APP:
                return DNSRule(buf)
            else:
                return None
    
    def add(self, rule):
        if type(rule) in [GeneralRule, DNSRule]:
            # Save a reverse configuration rule
            self.rule_list.insert(0, rule)

    def check(self, archive):
        if self.isEmpty():
            return
        for rule in self.rule_list:
            if rule.matches(archive):
                archive.setVerdict(rule.getVerdict())
                return

    def isEmpty(self):
        return len(self.rule_list) == 0

    def __str__(self):
        output = ""
        for rule in self.rule_list[::-1]:
            output += rule.__str__() + "\n"
        return output
