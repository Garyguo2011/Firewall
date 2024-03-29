import socket
import struct
import time

# from rulesPool import Rule
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from countryCodeDict import CountryCodeDict
from firewall import TCP_PROTOCOL, UDP_PROTOCOL, ICMP_PROTOCOL, DNS_APP, LETTER, ANY, PASS_STR, DROP_STR, PASS, DROP, MAX_PORTNUM, DEFAULT_POLICY, DEBUG

################### IP layer ####################
class Archive(object):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
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
            src_ip = struct.unpack('!L', pkt[12:16])[0]
            self.externalIP = src_ip       #IP store as number
        else:
            dst_ip = struct.unpack('!L', pkt[16:20])[0]
            self.externalIP = dst_ip
        self.countryCode = countryCodeDict.lookup(self.externalIP)      # need look up CountryCodeDirectionary
        self.packet = pkt                                                # Exact packet (i.e. str version of original packet)
        self.verdict = True
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

    # def getVerdict(self):
    #     return self.verdict

    # def setVerdict(self, action):
    #     self.verdict = action

    def isValid(self):
        return self.valid

    def __str__(self):
        if self.direction == PKT_DIR_INCOMING:
            direction_str = "PKT_DIR_INCOMING"
        else:
            direction_str = "PKT_DIR_OUTGOING"
        if self.verdict == PASS:
            verdict_str = "PASS"
        else:
            verdict_str = "DROP"
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
        # Packet is String Type
        # Need to implement TCP parsing rule
        ipLength = (15 & ord(pkt[0:1])) * 4
        if pkt_dir == PKT_DIR_INCOMING:
            self.externalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]
        else:
            self.externalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
        Archive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def getExternalPort():
        return self.getExternalPort

    def __str__(self):
        return Archive.__str__(self) + "\n" + "[TCP Layer]: externalPort: %d" % (self.externalPort)

class UDPArchive (Archive):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        # Packet is String Type
        # Need to implement UDP parsing rule
        ipLength = (15 & ord(pkt[0:1])) * 4
        if pkt_dir == PKT_DIR_INCOMING:
            self.externalPort = struct.unpack('!H', pkt[ipLength:(ipLength + 2)])[0]
        else:
            self.externalPort = struct.unpack('!H', pkt[(ipLength + 2):(ipLength + 4)])[0]
        Archive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def getExternalPort():
        return self.getExternalPort

    def __str__(self):
        return Archive.__str__(self) + "\n" + "[UDP Layer]: externalPort: %d" % (self.externalPort)
        
class ICMPArchive (Archive):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        # Packet is String Type
        # Need to implement UDP parsing rule
        # ICMP has type field
        ipLength = (15 & ord(pkt[0:1])) * 4
        self.type = ord(pkt[ipLength:(ipLength + 1)])
        Archive.__init__(self, pkt_dir, pkt, countryCodeDict)

    def getType(self):
        return self.type

    def __str__(self):
        return Archive.__str__(self) + "\n" + "[UDP Layer]: Type: %d" % (self.type)

################### Application layer ####################
class DNSArchive(UDPArchive):
    def __init__(self, pkt_dir, pkt, countryCodeDict):
        # DNSArchieve build on top of UDPArchive
        self.app = DNS_APP
        self.domainName = self.findDomainName(pkt_dir, pkt)
        UDPArchive.__init__(self, pkt_dir, pkt, countryCodeDict)

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

    def getDomainName(self):
        return self.domainName

    def getApp(self)

    def __str__(self):
        return UDPArchive.__str__(self) + "\n" + "[DNS Layer]: app: %s | domainName: %s" % (self.app, self.domainName)