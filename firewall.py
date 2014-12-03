#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

import socket
import struct
import time


# Remove Latter
#================================
import sys
import subprocess
TESTCASE = True
PRINT_ARCHIVE = False
#================================

LETTER = "abcdefghijklmnopqrstuvwxyz"


PASS = True
DROP = False
PASS_STR = "pass"
DROP_STR = "drop"

DENY_STR = "deny"
LOG_STR = "log"


TCP_PROTOCOL = "tcp"
TCP_PROTOCOL_NUM = 6
UDP_PROTOCOL = "udp"
UDP_PROTOCOL_NUM = 17
ICMP_PROTOCOL = "icmp"
ICMP_PROTOCOL_NUM = 1
DNS_APP = "dns"
HTTP_APP = "http"

HTTP_PORT = 80

ANY = "any"
MAX_PORTNUM = 65535

DEFAULT_POLICY = PASS
DEBUG = False


GEOIPDB_FILE = 'geoipdb.txt'
HTTP_LOG_FILE = 'http.log'

MALFORM_PACKET = "MALFORM PACKET"
DNS_PARSE_ERROR = "**DNS MALFORM**"
ERROR_HAPPEN = -1

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        # try:
        self.staticRulesPool = StaticRulesPool(config['rule'], self.send)
        if PRINT_ARCHIVE:
            print(self.staticRulesPool)
        self.countryCodeDict = CountryCodeDict(GEOIPDB_FILE)
        self.httpLogGenerator = HTTPLogGenerator(HTTP_LOG_FILE, self.staticRulesPool)
        self.connectionsPool = TCPConnectionsPool(self.httpLogGenerator)
        self.i = 0
        # except Exception:
            # pass
        # print(self.staticRulesPool)
        # TODO: Load the firewall rules (from rule_filename) here.
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        # try:
        if pkt == None or len(pkt) == 0:
            raise MalformError(MALFORM_PACKET + "1")
        archive = self.packet_allocator(pkt_dir, pkt, self.countryCodeDict)
        # print ">>>>>>>> " + str(self.i) + " <<<<<<<<<<"
        # print ("\n--> Packet NO: [%d]: %s" % (self.i + 5, archive.__str__()))
        # print (archive)
        # file_ptr = open("dir-2/" + str(self.i) + "-pkt", "w")
        # file_ptr.write(pkt)
        # file_ptr.close()
        # dir_ptr = open("dir-2/" + str(self.i) + "-dir", "w")
        # dir_ptr.write(str(pkt_dir))
        # dir_ptr.close()
        self.i += 1
        if archive != None and archive.isValid():
            self.staticRulesPool.check(archive)
            # ++++++++++ Add for 3b ++++++++++++++++
            if archive.getVerdict() == PASS:
                if self.is_http_traffic(archive):
                    self.connectionsPool.handle_TCP_packet(archive)
                if archive.getVerdict() == PASS:
                    if not TESTCASE:
                        self.send(pkt_dir, pkt)
        # except MalformError as e:
            # pass
        # except Exception as e:
            # pass
        if PRINT_ARCHIVE:
            print ("\n--> Packet NO: [%d]" % (self.i + 5))
            print self.connectionsPool

    def is_http_traffic(self, archive):
        if type(archive) == TCPArchive and archive.getExternalPort() == HTTP_PORT:
            return True
        else:
            return False

    # TODO: You can add more methods as you want.
    #################### bypass_phase1.py ########################

    def packet_allocator(self, pkt_dir, pkt, countryCodeDict):
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        # self.malformCheck(pkt_dir, pkt)
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
        elif verdictStr == DROP_STR or verdictStr == DENY_STR:
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

    def handle(self, archive, send_function):
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
    def __init__(self, conffile, send_function):
        self.rule_list = []
        self.log_rule_list = []
        self.send_function = send_function
        try:
            fptr = open (conffile)
            buf = fptr.readline()
            while buf != "" :
                rule = self.parseBuffer(buf)
                if rule:
                    if type(rule) == LogHttpRule:
                        self.add_log_rule(rule)
                    else:
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

        if fieldList[0] == DENY_STR:
            if fieldList[1] == TCP_PROTOCOL and len(fieldList) == 4:
                return DenyTCPRule(fieldList)
            elif fieldList[1] == DNS_APP and len(fieldList) == 3:
                return DenyDNSRule(fieldList)
        elif fieldList[0] == LOG_STR:
            if fieldList[1] == HTTP_APP and len(fieldList) == 3:
                return LogHttpRule(fieldList)
        elif fieldList[0] == PASS_STR or fieldList[0] == DROP_STR:
            ruleType = fieldList[1]
            if (ruleType == ICMP_PROTOCOL or ruleType == UDP_PROTOCOL or ruleType == TCP_PROTOCOL) and len(fieldList) == 4:
                return GeneralRule(fieldList)
            elif ruleType == DNS_APP and len(fieldList) == 3:
                return DNSRule(fieldList)
        else:
            return None
    
    def add(self, rule):
        if type(rule) in [GeneralRule, DNSRule, DenyDNSRule, DenyTCPRule]:
            # Save a reverse configuration rule
            self.rule_list.insert(0, rule)

    def add_log_rule(self, rule):
        if type(rule) == LogHttpRule:
            self.log_rule_list.insert(0, rule)

    def check(self, archive):
        if self.isEmpty():
            archive.setVerdict(PASS)
        for rule in self.rule_list:
            if rule.matches(archive):
                # print( ">>> Match Last Rule: [" + rule.__str__() + "]")
                rule.handle(archive, self.send_function)
                archive.setVerdict(rule.getVerdict())
                return
        # print(">>> DEFAULT_PASS")

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    def matchLogRules(self, httpRequest):
        if len(self.log_rule_list) == 0:
            return False

        for logrule in self.log_rule_list:
            if logrule.matches(httpRequest):
                # print( ">>> Match Last Rule: [" + rule.__str__() + "]")
                return True
        return False

    def isEmpty(self):
        return len(self.rule_list) == 0

    def __str__(self):
        output = ""
        for rule in self.rule_list[::-1]:
            output += rule.__str__() + "\n"
        output += "======= LOG Rule =======\n"
        for logrule in self.log_rule_list[::-1]:
            output += logrule.__str__() + "\n"
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
        self.ipLength = ipLength
        if len(pkt) < ipLength + 13:
            raise MalformError(MALFORM_PACKET + "7")
        offset = ((ord(pkt[ipLength + 12: ipLength + 13]) >> 4) & 15) * 4
        # Pkt doesn't contain enough length for TCP
        if len(pkt) < ipLength + 20 or len(pkt) < ipLength + offset:
            raise MalformError(MALFORM_PACKET + "8")
        if pkt_dir == PKT_DIR_INCOMING:
            self.externalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]
            self.internalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]    # add for 3b
        else:
            self.externalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
            self.internalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]          # add for 3b
        self.seqno = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]
        self.ackno = struct.unpack('!L', pkt[(ipLength + 8): (ipLength + 12)])[0]
        self.data = pkt[ipLength + offset: len(pkt)]
        Archive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def getExternalPort(self):
        return self.externalPort

    def getInternalPort(self):
        return self.internalPort

    def getSeqNo(self):
        return self.seqno

    def getAckNo(self):
        return self.ackno

    def getData(self):
        # impelemtaiton
        return self.data

    def getDataSize(self):
        return len(self.data)

    def is_SYN(self):
        return (ord(self.getPacket()[self.ipLength + 13: self.ipLength + 14]) & 2) == 2

    def is_FIN(self):
        return (ord(self.getPacket()[self.ipLength + 13: self.ipLength + 14]) & 1) == 1

    def is_RST(self):
        return (ord(self.getPacket()[self.ipLength + 13: self.ipLength + 14]) & 4) == 4

    def __str__(self):
        return Archive.__str__(self) + "\n" + "[TCP Layer]: externalPort: %d | internalPort: %d | seqNo: %d | AckNo: %d | is_SYN: %s | is_FIN: %s | is_RST: %s" % \
                                                    (self.externalPort, self.internalPort, self.seqno, self.ackno, self.is_SYN(), self.is_FIN(), self.is_RST())

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

##########################################################################################
######################## newRule.py  #####################################################
##########################################################################################

class DenyTCPRule(GeneralRule):
    def __init__(self, fieldList):
        GeneralRule.__init__(self, fieldList)

    def handle(self, archive, send_function):
        # Assume the archive you receive is TCPArchive
        # TODO: 
        # Injecting RST Packets: deny*tcp
        rstPacket = self.rstPacketGenerator(archive.getPacket())
        send_function(PKT_DIR_INCOMING, rstPacket)

    def checksum(self, buf, size):
        # Implement this
        result, i = 0, 0
        while i < size - 1:
            elem = struct.unpack('!H', buf[i:i+2])[0]
            result += elem
            i += 2
        if size & 1 == 1:
            elem = ord(buf[i:i+1])
            result += elem
        while result >> 16 != 0:
            result = (result & 65535) + (result >> 16)
        result = result ^ 0xffff
        return struct.pack('!H', result)

    def rstPacketGenerator(self, original):
        # generating ip header
        vihlStr = chr((4 << 4) + 5)    # version + header length
        tosStr = chr(0)    # type of service
        tlStr = struct.pack('!H', 40)    # total length
        idStr = struct.pack('!H', 1)    # identification
        ipffoStr = struct.pack('!H', 0)    # ip flags + fragment offset
        ttlStr = chr(64)    # time to live
        protocolStr = chr(6)    # protocol
        srcAddrStr = original[16:20]    # source address
        dstAddrStr = original[12:16]    # destination address
        buf = vihlStr + tosStr + tlStr + idStr + ipffoStr + ttlStr + protocolStr + srcAddrStr + dstAddrStr
        checksumStr = self.checksum(buf, len(buf))     # checksum
        result = vihlStr + tosStr + tlStr + idStr + ipffoStr + ttlStr + protocolStr + checksumStr + srcAddrStr + dstAddrStr
        # generating tcp header
        ipLength = (15 & ord(original[0:1])) * 4
        srcPortStr = original[ipLength+2:ipLength+4]    # source port 
        dstPortStr = original[ipLength:ipLength+2]    # destination port
        seqNo = struct.unpack('!L', original[ipLength+4:ipLength+8])[0]
        seqNoStr = struct.pack('!L', seqNo)    # sequence number
        ackNoStr = struct.pack('!L', seqNo + 1)    # acknowledge number
        orStr = chr(5 << 4)    # offset + reserved
        tcpfStr = chr(20)    # tcp flags with ACK and RST set
        windowStr = struct.pack('!H', 0)    # window
        upStr = struct.pack('!H', 0)    # urgent pointer
        # checksum
        pseudo_header = srcAddrStr + dstAddrStr + struct.pack('!H', 6) + struct.pack('!H', 20)
        buf =  pseudo_header + srcPortStr + dstPortStr + seqNoStr + ackNoStr + orStr + tcpfStr + windowStr + upStr
        checksumStr = self.checksum(buf, len(buf))
        result = result + srcPortStr + dstPortStr
        result = result + seqNoStr + ackNoStr
        result = result + orStr + tcpfStr + windowStr + checksumStr + upStr
        return result


    def __str__(self):
        return "[TCP DENY Rule] -> " + GeneralRule.__str__(self)

class DenyDNSRule(DNSRule):
    def __init__(self, fieldList):
        DNSRule.__init__(self, fieldList)

    def handle(self, archive, send_function):
        # Assume the archive you receive is TCPArchive
        # TODO:
        # Injecting DNS Response Packets: deny*dns (spec part 2)
        dnsPacket = self.dnsPacketGenerator(archive.getPacket())
        send_function(PKT_DIR_INCOMING, dnsPacket)


    def dnsPacketGenerator(self, original):
        qnameLength = self.getQNameLength(original)
        # generating ip header
        vihlStr = chr((4 << 4) + 5)    # version + header length
        tosStr = chr(0)    # type of service
        totalLength = 20 + 8 + 12 + qnameLength + 4 + qnameLength + 14
        tlStr = struct.pack('!H', totalLength)    # total length
        idStr = struct.pack('!H', 1)    # identification
        ipffoStr = struct.pack('!H', 0)    # ip flags + fragment offset        
        ttlStr = chr(64)    # time to live
        protocolStr = chr(17)    # protocol
        srcAddrStr = original[16:20]    # source address
        dstAddrStr = original[12:16]    # destination address
        buf = vihlStr + tosStr + tlStr + idStr + ipffoStr + ttlStr + protocolStr + srcAddrStr + dstAddrStr
        checksumStr = self.checksum(buf, len(buf))     # checksum
        result = vihlStr + tosStr + tlStr + idStr + ipffoStr + ttlStr + protocolStr + checksumStr + srcAddrStr + dstAddrStr
        # generating udp header
        ipLength = (15 & ord(original[0:1])) * 4
        srcPortStr = original[ipLength+2:ipLength+4]    # source port 
        dstPortStr = original[ipLength:ipLength+2]    # destination port
        length = 8 + 12 + qnameLength + 4 + qnameLength + 14
        lengthStr = struct.pack('!H', length)    # udp + dns length
        checksumStr = struct.pack('!H', 0)    # checksum
        result = result + srcPortStr + dstPortStr + lengthStr + checksumStr
        # generating dns header
        dnsidStr = original[ipLength+8:ipLength+10]
        flag = (1 << 15) | (1 << 10)
        flagStr = struct.pack('!H', flag)    # second line of the header
        qdcountStr = struct.pack('!H', 1)    # QDCOUNT
        ancountStr = struct.pack('!H', 1)    # ANCOUNT 
        nscountStr = struct.pack('!H', 0)    # NSCOUNT
        arcountStr = struct.pack('!H', 0)    # ARCOUNT
        result = result + dnsidStr + flagStr + qdcountStr + ancountStr + nscountStr + arcountStr
        # generating question part
        questionStr = original[ipLength+20:ipLength+24+qnameLength]
        result = result + questionStr
        # generating answer part
        nameStr = original[ipLength+20:ipLength+20+qnameLength]    # name
        typeStr = struct.pack('!H', 1)    # type
        classStr = struct.pack('!H', 1)    # class
        answerttlStr = struct.pack('!H', 1)    # answer
        rdlengthStr = struct.pack('!L', 4)    # rdlength
        rdataStr = socket.inet_aton('54.173.224.150')    #rdata
        result = result + nameStr + typeStr + classStr + answerttlStr + rdlengthStr + rdataStr
        return result

    def getQNameLength(self, pkt):
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

    def checksum(self, buf, size):
        # Implement this
        result, i = 0, 0
        while i < size - 1:
            elem = struct.unpack('!H', buf[i:i+2])[0]
            result += elem
            i += 2
        if size & 1 == 1:
            elem = ord(buf[i:i+1])
            result += elem
        while result >> 16 != 0:
            result = (result & 65535) + (result >> 16)
        result = result ^ 0xffff
        return struct.pack('!H', result)

    def __str__(self):
        return "[DNS DENY Rule] -> " + DNSRule.__str__(self)

##########################################################################################
######################## httpLog.py  #####################################################
##########################################################################################

class LogHttpRule(Rule):
    FULL = 0
    WILDCARD = 1
    IPADDRESS = 2
    IPCHAR = "0123456789."
    
    def __init__(self, fieldList):
        Rule.__init__(self, PASS_STR)
        self.type = None
        self.postfix = None
        self.app =fieldList[1]
        content = fieldList[2]
        self.parse_content(content)

    def parse_content(self, content):
        if len(content) == 0:
            print "Pase Error: DNS Don't have content"
            pass
        elif len(content) == 1 and content[0] == "*":
            self.type = LogHttpRule.WILDCARD
            self.postfix = ""
        elif len(content) >=2 and content[0:2] == "*.":
            self.type = LogHttpRule.WILDCARD
            self.postfix = content[1:]
        else:
            if self.is_IP_address(content):
                self.type = LogHttpRule.IPADDRESS
                self.postfix = self.ip_str_to_int(content)
            else:
                self.type = LogHttpRule.FULL
                self.postfix = content

    def ip_str_to_int(self, ipStr):
        fieldList = ipStr.split(".")
        if len (fieldList) == 4:
            result = (int(fieldList[0]) << 24) + (int(fieldList[1]) << 16) + (int(fieldList[2]) << 8) + int(fieldList[3])
            return (int(fieldList[0]) << 24) + (int(fieldList[1]) << 16) + (int(fieldList[2]) << 8) + int(fieldList[3])
        else:
            pass
            # print ("Syntax Error: " + ipStr)

    def is_IP_address(self, content):
        for i in content:
            if not i in LogHttpRule.IPCHAR:
                return False
        fieldList = content.split(".")
        if len(fieldList) == 4:
            return True
        return False

    def matches(self, httpRequest):
        if self.type == LogHttpRule.WILDCARD and len(self.postfix) == 0:
            return True
        if self.type == LogHttpRule.IPADDRESS:
            if type(httpRequest.getHostName()) == int:
                return self.getHostName() == self.postfix
            elif type(httpRequest.getHostName()) == str and self.is_IP_address(httpRequest.getHostName()):
                return self.ip_str_to_int(HTTPRequest.getHostName()) == self.postfix
            else:
                return False
        elif self.type == LogHttpRule.WILDCARD:
            for i in range(0, len(httpRequest.getHostName())):
                if httpRequest.getHostName()[i:] == self.postfix:
                    return True
            return False
        else:
            return httpRequest.getHostName() == self.postfix

    def __str__(self):
        if self.type == LogHttpRule.IPADDRESS:
            host_name = self.ip_int_to_str(self.postfix)
        elif self.type == LogHttpRule.FULL:
            host_name = self.postfix
        else:
            host_name = "*" + self.postfix
        return "[%s Rule]: %s %s %s" % (LOG_STR, LOG_STR, self.app, host_name)

    def ip_int_to_str(self, ipNum):
        ipStrList = []
        ipStrList.append((ipNum >> 24) & 255)
        ipStrList.append((ipNum >> 16) & 255)
        ipStrList.append((ipNum >> 8) & 255)
        ipStrList.append((ipNum >> 0) & 255)
        return "%d.%d.%d.%d" % (ipStrList[0], ipStrList[1], ipStrList[2], ipStrList[3])

class TCPConnectionsPool(object):
    def __init__(self, logGenerator):
        # Key: (External IP, Internal Port)
        # Value: Class Connection Entry
        self.connectionPool = {}
        self.logGenerator = logGenerator

    def handle_TCP_packet(self, archive):
        # assume input archive is in type of TCP Archive with external port 80
        assert type(archive) == TCPArchive, "archive is not TCPArchive"

        connectionKey = (archive.getExternalIP(), archive.getInternalPort())
        # creat a new connectionEntry: Outgoing SYN
        if archive.getDirection() == PKT_DIR_OUTGOING and archive.is_SYN():
            if connectionKey in self.connectionPool:
                del self.connectionPool[connectionKey]
            self.connectionPool[connectionKey] = ConnectionEntry(self.logGenerator)
            self.connectionPool[connectionKey].handle_Outgoing_SYN(archive)
        # handle Incommping Syn_ack
        elif archive.getDirection() == PKT_DIR_INCOMING and archive.is_SYN():
            if connectionKey in self.connectionPool:
                connectionEntry = self.connectionPool[connectionKey]
                connectionEntry.handle_Incomming_SYN(archive)
            else:
                print "SYN_ACK happen before SYN"
        # hanlde outgoing FIN or RST
        elif archive.is_FIN() or archive.is_RST():
            if connectionKey in self.connectionPool:
                if self.connectionPool[connectionKey].handle_FIN_or_RESET(archive) == PASS:
                    del self.connectionPool[connectionKey]
        # handle normal packet
        else:
            if connectionKey in self.connectionPool:
                self.connectionPool[connectionKey].handle_normal_packet(archive)

    def __str__(self):
        result = "TCPConnectionsPool:\n"
        for k in self.connectionPool.keys():
            result += "-------------------------\n"
            result +=  "[ " + self.ip_int_to_str(k[0]) + ", " + str(k[1]) + " ]: " + self.connectionPool[k].__str__()
            # result += "-------------------------\n"
        return result

    def ip_int_to_str(self, ipNum):
        ipStrList = []
        ipStrList.append((ipNum >> 24) & 255)
        ipStrList.append((ipNum >> 16) & 255)
        ipStrList.append((ipNum >> 8) & 255)
        ipStrList.append((ipNum >> 0) & 255)
        return "%d.%d.%d.%d" % (ipStrList[0], ipStrList[1], ipStrList[2], ipStrList[3])
            
class ConnectionEntry(object):
    def __init__(self, logGenerator):
        self.streamBuffer = TCPStreamBuffer(logGenerator)
        self.incommingExpect = None
        self.outgoingExpect = None    

    def handle_Outgoing_SYN(self, archive):
        self.outgoingExpect = archive.getSeqNo() + 1

    def handle_Incomming_SYN(self, archive):
        self.incommingExpect = archive.getSeqNo() + 1

    def handle_FIN_or_RESET(self, archive):
        if archive.getDirection() == PKT_DIR_OUTGOING:
            if self.compare(archive.getSeqNo(), self.outgoingExpect) > 0:
                archive.setVerdict(DROP)
                return DROP
            else:
                archive.setVerdict(PASS)
                return PASS
        else:
            if self.compare(archive.getSeqNo(), self.incommingExpect) > 0:
                archive.setVerdict(DROP)
                return DROP
            else:
                archive.setVerdict(PASS)
                return PASS

    def handle_normal_packet(self, archive):
        assert type(archive) == TCPArchive, "archive is not TCPArchive"
        # Update internalSeq and externalSeq
        if archive.getDirection() == PKT_DIR_OUTGOING:
            cmp_result = self.compare(archive.getSeqNo(), self.outgoingExpect)
            if cmp_result > 0:
                archive.setVerdict(DROP)
            elif cmp_result == 0:
                self.outgoingExpect = (archive.getSeqNo() + archive.getDataSize())
                archive.setVerdict(PASS)
                self.streamBuffer.handle_new_stream(archive)
            else:
                archive.setVerdict(PASS)
        else:
            cmp_result = self.compare(archive.getSeqNo(), self.incommingExpect)
            if cmp_result > 0:
                archive.setVerdict(DROP)
            elif cmp_result == 0:
                self.incommingExpect = archive.getSeqNo() + archive.getDataSize()
                archive.setVerdict(PASS)
                self.streamBuffer.handle_new_stream(archive)
            else:
                archive.setVerdict(PASS)

    def compare(self, seqNo, expectNo):
        if expectNo + ((2**32) / 2) > 2**32:
            wrapUpperBound = (expectNo + ((2**32)/2)) % (2**32)
            if seqNo > expectNo or (seqNo > 0 and seqNo < wrapUpperBound):
                return 1
            elif seqNo == expectNo:
                return 0
            else:
                return -1
        else:
            if seqNo > expectNo:
                return 1
            elif seqNo == expectNo:
                return 0
            else:
                return -1

    def __str__(self):
        return "incommingExpect: %s | outgoingExpect: %s\n %s"  % (str(self.incommingExpect), str(self.outgoingExpect), self.streamBuffer.__str__())

class TCPStreamBuffer(object):
    def __init__(self, logGenerator):
        # Element in this queue will be tuple (packet_direction, HTTP Rquest/ HTTP Respond)
        self.queue = []
        self.logGenerator = logGenerator

    def handle_new_stream(self, archive):
        self.add_to_stream(archive)
        self.logGenerator.processBufferStream(self.getBuffer())

    def add_to_stream(self, archive):
        if len(self.queue) == 0:
            if archive.getDirection() == PKT_DIR_OUTGOING:
                httpRequest = HTTPRequest(archive)
                self.queue.append(httpRequest)
        else:
            if type(self.tail()) == HTTPRequest:
                if archive.getDirection() == PKT_DIR_OUTGOING:
                    self.tail().append_to_tail(archive)
                else:
                    if archive.getDataSize() != 0:
                        httpRespond = HTTPRespond(archive)
                        self.queue.append(httpRespond)
                    else:
                        pass
            elif type(self.tail()) == HTTPRespond:
                if archive.getDirection() == PKT_DIR_INCOMING:
                    self.tail().append_to_tail(archive)
                else:
                    if archive.getDataSize() != 0:
                        httpRequest = HTTPRequest(archive)
                        self.queue.append(httpRequest)
                    else:
                        pass
        self.logGenerator.processBufferStream(self.getBuffer())

    def getBuffer(self):
        return self.queue

    def tail(self):
        return self.queue[-1]

    def __str__(self):
        result = "TCPStreamBuffer: \n" 
        for el in self.queue:
            result = "**************************\n"
            result += el.__str__() + "\n"
        return result


# ===================== HTTP Log Class ==================

class HTTPLogGenerator(object):
    def __init__(self, logfileName, staticRulesPool):
        self.logfileptr = open(logfileName, 'a')
        self.staticRulesPool = staticRulesPool

    def processBufferStream(self, bufferStreamQueue):
        if len(bufferStreamQueue) == 0 or len(bufferStreamQueue) == 1:
            return

        if len(bufferStreamQueue) % 2 == 1:
            bound = len(bufferStreamQueue) - 1
        else:
            bound = len(bufferStreamQueue)
        i = 0
        while i < bound:
            httpRequest = bufferStreamQueue[i]
            httpRespond = bufferStreamQueue[i + 1]
            if httpRequest.isComplete() and not httpRequest.hasLogged() and  httpRespond.isComplete() and not httpRespond.hasLogged():
                self.handle_http_pair(httpRequest, httpRespond)
            i += 2

    def handle_http_pair(self, httpRequest, httpRespond):
        if self.staticRulesPool.matchLogRules(httpRequest):
            # write to log
            if self.staticRulesPool.matchLogRules(httpRequest):
                httpRequest.setLog()
                httpRespond.setLog()
                logEntry = "%s %s %s %s %s %s\n" % \
                           (httpRequest.host_name, httpRequest.method, httpRequest.path, httpRequest.version, \
                            httpRespond.status_code, httpRespond.object_size)
                self.logfileptr.flush()
                self.logfileptr.write(logEntry)
                self.logfileptr.flush()

# ===================== HTTP Header Class ==================
class HTTPHeader(object):
    def __init__(self):
        self.complete = False
        self.stream = ""
        self.log = False

    def append_to_tail(self, archive):
        if self.complete == False:
            self.stream += archive.getData()
            self.check_complete()

    def check_complete(self):
        # Search entire stream see if "\r\n" has occur
        # if so, set complete = True and call parse_stream()
        if len(self.stream) < 4:
            return
        for i in range(0, len(self.stream) - 3):
            substring = self.stream[i:i+4]
            asciiStr = chr(ord(substring[0])) + chr(ord(substring[1])) + chr(ord(substring[2])) + chr(ord(substring[3]))
            if asciiStr == "\r\n\r\n":
                self.complete = True
                self.stream = self.stream[0:i]
                self.parse_stream()
                break

    def stringGenerator(self, inputStream):
        result = ''
        for i in range(0, len(inputStream)):
            elem = chr(ord(inputStream[i:i+1]))
            result = result + elem
        return result.split('\r\n')

    def parse_stream(self):
        # Subclass need to overide this function
        pass

    def isComplete(self):
        return self.complete

    def getStream(self):
        return self.stream

    def setLog(self):
        self.log = True

    def hasLogged(self):
        return self.log

    def __str__(self):
        result = ''
        for i in range(0, len(self.stream)):
            elem = chr(ord(self.stream[i:i+1]))
            result = result + elem
        return result

class HTTPRequest(HTTPHeader):
    def __init__(self, archive):
        HTTPHeader.__init__(self)
        self.host_name = archive.getExternalIP()
        self.method = ""
        self.path = ""
        self.version = ""
        self.append_to_tail(archive)
    
    def parse_stream(self):
        stream_str_arr = self.stringGenerator(self.stream)
        first_line= stream_str_arr[0]
        first_line_arr = first_line.split(' ')
        self.method = first_line_arr[0]
        self.path = first_line_arr[1]
        self.version = first_line_arr[2] 
        for i in range(0, len(stream_str_arr)):
            line_arr = stream_str_arr[i].split(':')
            if line_arr[0] == 'Host' and len(line_arr) == 2:
                temp = line_arr[1]
                while temp[0:1] == ' ':
                    temp = temp[1:]
                self.host_name = temp

    def getHostName(self):
        return self.host_name

class HTTPRespond(HTTPHeader):
    def __init__(self, archive):
        HTTPHeader.__init__(self)
        self.complete = False
        self.status_code = ""
        self.object_size = -1
        self.append_to_tail(archive)

    def parse_stream(self):
        stream_str_arr = self.stringGenerator(self.stream)
        first_line_arr = stream_str_arr[0].split(' ')
        self.status_code = first_line_arr[1]
        for i in range(0, len(stream_str_arr)):
            line_arr = stream_str_arr[i].split(':')
            if line_arr[0] == 'Content-Length' and len(line_arr) == 2:
                temp = line_arr[1]
                while temp[0:1] == ' ':
                    temp = temp[1:]
                self.object_size = int(temp)
