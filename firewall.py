#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

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

MALFORM_PACKET = "MALFORM PACKET"
DNS_PARSE_ERROR = "**DNS MALFORM**"
ERROR_HAPPEN = -1

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        try:
            self.staticRulesPool = StaticRulesPool(config['rule'])
            self.countryCodeDict = CountryCodeDict(GEOIPDB_FILE)
        except Exception:
            pass
        # print(self.staticRulesPool)
        # TODO: Load the firewall rules (from rule_filename) here.
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        try:
            if pkt == None or len(pkt) == 0:
                raise MalformError(MALFORM_PACKET + "1")
            archive = self.packet_allocator(pkt_dir, pkt, self.countryCodeDict)
            if archive != None and archive.isValid():
                self.staticRulesPool.check(archive)
                # if self.staticRulesPool.check(archive) == PASS:
                if archive.getVerdict() == PASS:
                    self.send(pkt_dir, pkt)
        except MalformError as e:
            pass
        except Exception as e:
            pass

    # TODO: You can add more methods as you want.
    #################### bypass_phase1.py ########################

    def packet_allocator(self, pkt_dir, pkt, countryCodeDict):
        self.malformCheck(pkt_dir, pkt)
        protocolNumber = ord(pkt[9:10]) # parse pkt and get protocol
        if protocolNumber == TCP_PROTOCOL_NUM:
            return TCPArchive(pkt_dir, pkt, self.countryCodeDict)
        elif protocolNumber == UDP_PROTOCOL_NUM:
            if self.is_DNS_query_packet(pkt_dir, pkt) == True:
                return DNSArchive(pkt_dir, pkt, self.countryCodeDict)
            else:
                return UDPArchive(pkt_dir, pkt, self.countryCodeDict)
        elif protocolNumber == ICMP_PROTOCOL_NUM:
            return ICMPArchive(pkt_dir, pkt, self.countryCodeDict)
        else:
            # Defualt Allow
            self.send(pkt_dir, pkt)
            return None

    def is_DNS_query_packet(self, pkt_dir, pkt):
        ipLength = (15 & ord(pkt[0:1])) * 4
        if len(pkt) < ipLength + 14:
            return False
        dst_port = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
        qdcount = struct.unpack('!H', pkt[(ipLength + 12):(ipLength + 14)])[0]
        qNameLength = self.getQNameLength(pkt_dir, pkt)
        if qNameLength == ERROR_HAPPEN or len(pkt) < ipLength + 24 + qNameLength:
            return False
        qtype = struct.unpack('!H', pkt[(ipLength + 20 + qNameLength):(ipLength + 22 + qNameLength)])[0]
        qclass = struct.unpack('!H', pkt[(ipLength + 22 + qNameLength):(ipLength + 24 + qNameLength)])[0]
        if pkt_dir == PKT_DIR_OUTGOING and dst_port == 53 and qdcount == 1 and qclass == 1:
            if qtype == 1 or qtype ==28:
                return True
        return False

    def send (self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def getQNameLength(self, pkt_dir, pkt):
        if pkt == None or len(pkt) == 0 or len(pkt) < 1:
            return ERROR_HAPPEN
        ipLength = (15 & ord(pkt[0:1])) * 4
        countByte = 0
        if len(pkt) < ipLength + 21:
            return ERROR_HAPPEN
        indicator = ord(pkt[(ipLength + 20):(ipLength + 21)])
        while (indicator != 0):
            countByte = indicator + countByte + 1
            if len(pkt) < ipLength + 21 + countByte:
                return ERROR_HAPPEN
            indicator = ord(pkt[(ipLength + 20 + countByte):(ipLength + 21 + countByte)])
        countByte += 1
        return countByte

    def malformCheck(self, pkt_dir, pkt):
        if pkt == None or len(pkt) < 20:
            raise MalformError(MALFORM_PACKET + "2")
        ipLength = (15 & ord(pkt[0:1])) * 4
        if len(pkt) < ipLength:
            raise MalformError(MALFORM_PACKET + "3")
        totalLength = struct.unpack('!H', pkt[2:4])[0]
        if len(pkt) != totalLength:
            raise MalformError(MALFORM_PACKET + " totalLength")

    ################################################################

# TODO: You may want to add more classes/functions as well.
class MalformError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

##########################################################################################
######################## rulesPool.py ####################################################
##########################################################################################

# Infrastructure
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

    def handle(self, archive):
        pass

class GeneralRule(Rule):        # Protocol/IP/Port Rules
    def __init__(self, fieldList):
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
            pass
            # print ("Syntax Error: " + inputStr)

    def ip_str_to_int(self, ipStr):
        fieldList = ipStr.split(".")
        if len (fieldList) == 4:
            result = (int(fieldList[0]) << 24) + (int(fieldList[1]) << 16) + (int(fieldList[2]) << 8) + int(fieldList[3])
            return (int(fieldList[0]) << 24) + (int(fieldList[1]) << 16) + (int(fieldList[2]) << 8) + int(fieldList[3])
        else:
            pass
            # print ("Syntax Error: " + ipStr)

    def parse_port_range(self, inputStr):
        if inputStr == ANY:
            return 0, MAX_PORTNUM
        fieldList = inputStr.split("-")
        if len(fieldList) == 1:
            return int(fieldList[0]), int(fieldList[0])
        elif len(fieldList) == 2:
            return int(fieldList[0]), int(fieldList[1])
        else:
            pass
            # print("Syntax Error: " + inputStr)

    def matches (self, archive):
        if self.protocol_matches(archive) and self.external_ip_matches(archive) and \
           self.countrycode_matches(archive) and self.external_port_matches(archive):
            return True
        else:
            return False

    def protocol_matches(self, archive):
        return self.protocol == archive.getProtocol()

    def external_ip_matches(self, archive):
        if self.ipPrefixContent != None:
            return ((archive.getExternalIP() >> (32 - self.ipPrefixContent[1])) ^ \
                   (self.ipPrefixContent[0] >> (32 - self.ipPrefixContent[1]))) == 0
        else:
            return True
            # Return True to pass skip this test because it is not ip prefix

    def countrycode_matches(self, archive):
        if self.countryCode != None:
            return self.countryCode == archive.getCountryCode()
        else:
            return True
            # Return True to pass skip this test because it is ip prefix

    def external_port_matches(self, archive):
        if type(archive) == ICMPArchive:
            cmpData = archive.getType()
        else:
            cmpData = archive.getExternalPort()
        return self.externalPortRange[0] <= cmpData and cmpData <= self.externalPortRange[1]

    def __str__(self):
        ipPrefixContent_str = str(self.ipPrefixContent)
        if self.ipPrefixContent != None:
            if self.ipPrefixContent[0] == 0 and self.ipPrefixContent[1] == 0 and not DEBUG:
                ipPrefixContent_str = "any"
            else:
                ipStrList = []
                ipStrList.append((self.ipPrefixContent[0] >> 24) & 255)
                ipStrList.append((self.ipPrefixContent[0] >> 16) & 255)
                ipStrList.append((self.ipPrefixContent[0] >> 8) & 255)
                ipStrList.append((self.ipPrefixContent[0] >> 0) & 255)
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
    def __init__(self, fieldList):
        Rule.__init__(self, fieldList[0])
        self.app = fieldList[1]
        domainStr = fieldList[2]
        if len(domainStr) == 0:
            pass
            # print("Parse Error: DNS Don't have domainStr")
        elif len(domainStr) == 1 and domainStr[0] == "*":
            self.isPostfix = True
            self.postfix = ""
        elif len(domainStr) >= 2 and domainStr[0:2] == "*.":
            self.isPostfix = True
            self.postfix = domainStr[1:]
        else:
            self.isPostfix = False
            self.postfix = domainStr

    def matches (self, archive):
        if type(archive) == DNSArchive:
            return self.app_matches(archive) and self.domain_matches(archive)
        else:
            return False

    def app_matches(self, archive):
        return self.app == archive.getApp()

    def domain_matches(self, archive):
        if self.isPostfix and len(self.postfix) == 0:
            return True
        if self.isPostfix:
            for i in range(0, len(archive.getDomainName())):
                if archive.getDomainName()[i:] == self.postfix:
                    return True
            return False
        else:
            return archive.getDomainName() == self.postfix

    def __str__(self):
        postfix_str = str(self.postfix)
        if self.isPostfix:
            postfix_str = "*" + str(self.postfix)
        if DEBUG:
            return "[DNSRule]|" + Rule.__str__(self) +  "app: %s | isPostfix: %s | postfix: %s" % (self.app, self.isPostfix, self.postfix)
        else:
            return Rule.__str__(self) +  " %s %s" % (self.app, postfix_str)

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
            # print ("'%s' does not exist: use default pass" % (conffile))
            pass

    def parseBuffer (self, buf):
        if buf == None or len(buf) == 0 or buf[0] == '%' or buf[0] == '\n':
            return None
        fieldList = buf.lower().split("%")[0].split("\n")[0].split()
        if len(fieldList) < 3 or len(fieldList) > 4:
            return None
        ruleType = fieldList[1]
        if (ruleType == ICMP_PROTOCOL or ruleType == UDP_PROTOCOL or ruleType == TCP_PROTOCOL) and len(fieldList) == 4:
            return GeneralRule(fieldList)
        elif ruleType == DNS_APP and len(fieldList) == 3:
            return DNSRule(fieldList)
        else:
            return None
    
    def add(self, rule):
        if type(rule) in [GeneralRule, DNSRule]:
            # Save a reverse configuration rule
            self.rule_list.insert(0, rule)

    def check(self, archive):
        if self.isEmpty():
            return DEFAULT_POLICY
        for rule in self.rule_list:
            if rule.matches(archive):
                # print( ">>> Match Last Rule: [" + rule.__str__() + "]")
                archive.setVerdict(rule.getVerdict())
        # print(">>> DEFAULT_PASS")
        # return DEFAULT_POLICY

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    def matchLogRules(self, httpRequest):
        # true if there is a match
        # false otherwise


    def isEmpty(self):
        return len(self.rule_list) == 0

    def __str__(self):
        output = ""
        for rule in self.rule_list[::-1]:
            output += rule.__str__() + "\n"
        return output

##########################################################################################
######################## countryCodeDict.py  #############################################
##########################################################################################

class CountryCodeEntry(object):
    def __init__(self, lowerIPnum, higherIPnum, countryCode):
        self.lowerIPnum = lowerIPnum
        self.higherIPnum = higherIPnum
        self.countryCode = countryCode

    def compareWithLower(self, ipNumber):
        if ipNumber > self.lowerIPnum:
            return 1
        elif ipNumber == self.lowerIPnum:
            return 0
        else:
            return -1

    def compareWithHigher(self, ipNumber):
        if ipNumber > self.higherIPnum:
            return 1
        elif ipNumber < self.higherIPnum:
            return -1
        else:
            return 0

class CountryCodeDict(object):
    def __init__(self, dataBase):
        self.incLst=[]
        try:
            inputFile = open(dataBase)
            fileLine = inputFile.readline()
            count = 0
            while fileLine:
                self.add(fileLine)
                fileLine = inputFile.readline()
        except IOError:
            # print ("'%s' doesn't exist" % dataBase)
            pass

    def add (self, inputStr):
        elem = inputStr[:-1].split()
        llist = elem[0].split('.')
        lowerIPnum = (int(llist[0]) << 24) + (int(llist[1]) << 16) + (int(llist[2])  << 8) + int(llist[3])
        higherIPnum = elem[1]
        hlist = elem[1].split('.')
        higherIPnum = (int(hlist[0]) << 24) + (int(hlist[1]) << 16) + (int(hlist[2])  << 8) + int(hlist[3])
        countrycode = elem[2].lower()
        self.incLst.append(CountryCodeEntry(lowerIPnum, higherIPnum, countrycode))

    def lookup(self, ipNumber):
        if len(self.incLst) == 0:
            return None
        else:
            return self.binary_search(ipNumber, 0, len(self.incLst) - 1)

    def binary_search(self, ip, imin, imax):
        if (imax < imin):
            return None
        imid = (imin + imax) / 2
        if (self.incLst[imid].compareWithLower(ip) == -1):
            return self.binary_search(ip, imin, imid - 1)
        elif (self.incLst[imid].compareWithLower(ip) == 1):
            if (self.incLst[imid].compareWithHigher(ip) != 1):
                return self.incLst[imid].countryCode 
            else:
                return self.binary_search(ip, imid + 1, imax)
        else:
            return self.incLst[imid].countryCode   

##########################################################################################
######################## archive.py  #####################################################
##########################################################################################

class Archive(object):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        # IPv4 parsing rule need here
        # In another word, All of Archive has IP Header
        self.direction = pkt_dir
        if len(pkt) < 1:
            raise MalformError(MALFORM_PACKET + "4")
        ipLength = (15 & ord(pkt[0:1])) * 4
        if len(pkt) < ipLength or len(pkt) < 20:
            raise MalformError(MALFORM_PACKET + "5")
        protocolInt = ord(pkt[9:10])
        if protocolInt == 1:
            self.protocol = ICMP_PROTOCOL
        elif protocolInt == 6:
            self.protocol = TCP_PROTOCOL
        elif protocolInt == 17:
            self.protocol = UDP_PROTOCOL
        if pkt_dir == PKT_DIR_INCOMING:
            src_ip = struct.unpack('!L', pkt[12:16])[0]
            self.externalIP = src_ip       #IP store as number
        else:
            dst_ip = struct.unpack('!L', pkt[16:20])[0]
            self.externalIP = dst_ip
        self.countryCode = countryCodeDict.lookup(self.externalIP)      # need look up CountryCodeDirectionary
        self.packet = pkt                                                # Exact packet (i.e. str version of original packet)
        self.verdict = PASS
        self.valid = True

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

    def setVerdict(self, verdict):
        self.verdict = verdict

    def isValid(self):
        return self.valid

    def __str__(self):
        if self.direction == PKT_DIR_INCOMING:
            direction_str = "----> PKT_DIR_INCOMING"
        else:
            direction_str = "<---- PKT_DIR_OUTGOING"
        externalIP_str = self.ip_int_to_str(self.externalIP)
        return "\n------------\n[IP Layer]: direction: %s | protocol: %s | externalIP: %s | countryCode: %s | valid: %s" % \
                                            (direction_str, self.protocol, externalIP_str, self.countryCode, self.valid)

    def ip_int_to_str(self, ipNum):
        ipStrList = []
        ipStrList.append((ipNum >> 24) & 255)
        ipStrList.append((ipNum >> 16) & 255)
        ipStrList.append((ipNum >> 8) & 255)
        ipStrList.append((ipNum >> 0) & 255)
        return "%d.%d.%d.%d" % (ipStrList[0], ipStrList[1], ipStrList[2], ipStrList[3])

################### Transport layer ####################
class TCPArchive (Archive):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        if pkt == None or len(pkt) < 1:
            raise MalformError(MALFORM_PACKET + "6")
        ipLength = (15 & ord(pkt[0:1])) * 4
        if len(pkt) < ipLength + 13:
            raise MalformError(MALFORM_PACKET + "7")
        offset = ((ord(pkt[ipLength + 12: ipLength + 13]) >> 4) & 15) * 4
        # Pkt doesn't contain enough length for TCP
        if len(pkt) < ipLength + 20 or len(pkt) < ipLength + offset:
            raise MalformError(MALFORM_PACKET + "8")
        if pkt_dir == PKT_DIR_INCOMING:
            self.externalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]
            self.internalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]    # add for 3b
            # self.externalSeqNo = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]
            # self.internalSeqNo = struct.unpack('!L', pkt[(ipLength + 8): (ipLength + 12)])[0]
        else:
            self.externalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
            self.internalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]          # add for 3b
            # self.externalSeqNo = struct.unpack('!L', pkt[(ipLength + 8): (ipLength + 12)])[0]
            # self.internalSeqNo = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]
        self.seqno = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]
        self.ackno = struct.unpack('!L', pkt[(ipLength + 8): (ipLength + 12)])[0]
        self.data = pkt[ipLength + offset: len(pkt)]
        Archive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def getExternalPort(self):
        return self.externalPort

    def getInternalPort(self):
        return self.internalPort

    # def getExternalSeqNo(self):
    #     return self.externalSeqNo

    # def getInternalSeqNo(self):
    #     return self.internalSeqNo

    def getSeqNo(self):
        return self.seqno

    def getAckNo(self):
        return self.ackno

    def getData():
        # impelemtaiton
        return self.data

    def getDataSize(self):
        return len(self.data)

    def is_SYN(self):
        return (ord(pkt[ipLength + 13: ipLength + 14]) & 2) == 2

    def is_ACK(self):
        return (ord(pkt[ipLength + 13: ipLength + 14]) & 16) == 16

    def is_FIN(self):
        return (ord(pkt[ipLength + 13: ipLength + 14]) & 1) == 1

    def is_RST(self):
        return (ord(pkt[ipLength + 13: ipLength + 14]) & 4) == 4

    def __str__(self):
        return Archive.__str__(self) + "\n" + "[TCP Layer]: externalPort: %d | internalPort: %d | externalSeqNo: %d | internalSeqNo: %d | is_ACK: %s | is_FIN: %s | is_RST: %s" % 
                                                    (self.externalPort, self.internalPort, self.externalSeqNo, self.internalSeqNo, self.is_ACK(), self.is_FIN(), self.is_RST())

class UDPArchive (Archive):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        # Packet is String Type
        # Need to implement UDP parsing rule
        if pkt == None or len(pkt) < 1:
            raise MalformError(MALFORM_PACKET + "9")
        ipLength = (15 & ord(pkt[0:1])) * 4
        # Pkt doesn't contain enough length for UDP
        if len(pkt) < ipLength + 8:
            raise MalformError(MALFORM_PACKET)
        udp_length = struct.unpack('!H', pkt[(ipLength + 4):(ipLength + 6)])[0]
        if len(pkt) < ipLength + udp_length:
            raise MalformError(MALFORM_PACKET + "10")
        if pkt_dir == PKT_DIR_INCOMING:
            self.externalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]
        else:
            self.externalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
        Archive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def getExternalPort(self):
        return self.externalPort

    def __str__(self):
        return Archive.__str__(self) + "\n" + "[UDP Layer]: externalPort: %d" % (self.externalPort)
        
class ICMPArchive (Archive):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        # Packet is String Type
        # Need to implement UDP parsing rule
        # ICMP has type field
        if pkt == None or len(pkt) < 1:
            raise MalformError(MALFORM_PACKET + "11")
        ipLength = (15 & ord(pkt[0:1])) * 4
        # Pkt doesn't contain enough length for ICMP
        if len(pkt) < ipLength + 8:
            raise MalformError(MALFORM_PACKET + "12")
        self.type = ord(pkt[ipLength:(ipLength + 1)])
        Archive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def getType(self):
        return self.type

    def __str__(self):
        return Archive.__str__(self) + "\n" + "[ICMP Layer]: Type: %d" % (self.type)

################### Application layer ####################
class DNSArchive(UDPArchive):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        # DNSArchieve build on top of UDPArchive
        self.app = DNS_APP
        self.domainName = self.findDomainName(pkt_dir, pkt)
        UDPArchive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def findDomainName(self, pkt_dir, pkt):
        if pkt == None or len(pkt) < 1:
            raise MalformError(DNS_PARSE_ERROR + "13")
        ipLength = (15 & ord(pkt[0:1])) * 4
        if len(pkt) < ipLength + 21:
            raise MalformError(DNS_PARSE_ERROR)
        indicator = ord(pkt[(ipLength + 20):(ipLength + 21)])
        domainName = ''
        countByte = 0
        while (indicator != 0):
            for i in range(1, indicator + 1):
                if len(pkt) < ipLength + 21 + countByte + i:
                    raise MalformError(DNS_PARSE_ERROR + "14")
                elemInt = ord(pkt[(ipLength + 20 + countByte + i):(ipLength + 21 + countByte + i)])
                elem = chr(elemInt)
                domainName = domainName + elem
            countByte = indicator + countByte + 1
            if len(pkt) < ipLength + 21 + countByte:
                raise MalformError(DNS_PARSE_ERROR + "15")
            indicator = ord(pkt[(ipLength + 20 + countByte):(ipLength + 21 + countByte)])
            if (indicator != 0):
                domainName = domainName + '.'
        return domainName.lower()

    def getDomainName(self):
        return self.domainName

    def getApp(self):
        return self.app

    def __str__(self):
        return UDPArchive.__str__(self) + "\n" + "[DNS Layer]: app: %s | domainName: %s" % (self.app, self.domainName)