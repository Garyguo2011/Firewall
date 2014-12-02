import socket
import struct
import time
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING


class DenyTCPRule(Rule):
    def __init__(self, fieldList):
        Rule.__init__(self, DROP_STR)
        # Gary will fill the parse algorithm

    def matches(self, archive):
        # Return bool (Match: True / Don't Match: False)
        # Assume you have already know this infomation
        # Gary will fill the match algorihtm
        pass

    def handle(self, archive):
        # Assume the archive you receive is TCPArchive
        # TODO: 
        # Injecting RST Packets: deny*tcp
        rstPacket = self.rstPacketGenerator(archive.getPacket)
        self.send(PKT_DIR_INCOMING, rstPacket)

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
        buf = result
        srcPortStr = original[ipLength+2:ipLength+4]    # source port 
        dstPortStr = original[ipLength:ipLength+2]    # destination port
        seqNo = struct.unpack('L', original[ipLength+4:ipLength+8])[0]
        seqNoStr = struct.pack('L', seqNo)    # sequence number
        ackNoStr = struct.pack('L', 0)    # acknowledge number
        orStr = chr(5 << 4)    # offset + reserved
        tcpfStr = chr(20)    # tcp flags with ACK and RST set
        windowStr = struct.pack('H', 0)    # window
        upStr = struct.pack('H', 0)    # urgent pointer
        buf = buf + srcPortStr + dstPortStr + seqNoStr + ackNoStr + orStr + tcpfStr + windowStr + upStr
        checksumStr = self.checksum(buf, len(buf))
        result = result + srcPortStr + dstPortStr + seqNoStr + ackNoStr + orStr + tcpfStr + windowStr + checksumStr + upStr
        return result
        




class DenyDNSRule(Rule):
    def __init__(self, fieldList):
        Rule.__init__(self, DROP_STR)
        # Gary will fill the parse algorithm

    def matches(self, archive):
        # Return bool (Match: True / Don't Match: False)
        # Assume you have already know this infomation
        # Gary will fill the match algorihtm

    def handle(self, archive):
        # Assume the archive you receive is TCPArchive
        # TODO:
        # Injecting DNS Response Packets: deny*dns (spec part 2)
        dnsPacket = self.dnsPacketGenerator(archive.getPacket)
        self.send(PKT_DIR_INCOMING, dnsPacket)


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

