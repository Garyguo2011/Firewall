class LogHttpRule(Rule):
    FULL = 0
    WILDCARD = 1
    IPADDRESS = 2
    IPCHAR = "0123456789."
    
    def __init__(self, fieldList):
        Rule.__init__(self, PASS_STR)
        self.type 
        self.postfix
        self.app =fieldList[1]

        content = fieldList[2]

    def parse_content(self, content):
        if len(content) == 0
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
            if self.is_IP_address(httpRequest.getHostName()):
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
        elif archive.getDirection() == PKT_DIR_OUTGOING and archive.is_FIN():
            if connectionKey in self.connectionPool:
                if self.connectionPool[connectionKey].handle_Outgoing_SYN(archive) == PASS:
                    del self.connectionPool[connectionKey]
            else:
                print "outgoing FIN , but don't have %s connectionEntry" % connectionKey
        # handle incomming RST
        elif archive.getDirection() == PKT_DIR_INCOMING and (archive.is_RST() or archive.is_FIN()):
            if connectionKey in self.connectionPool:
                del self.connectionPool[connectionKey]
            else:
                print "%s have already deleted" % connectionKey
        # handle normal packet
        else:
            if connectionKey in self.connectionPool:
                self.connectionPool[connectionKey].handle_normal_packet(archive)
            
class ConnectionEntry(object):
    def __init__(self, logGenerator):
        self.streamBuffer = TCPStreamBuffer(logGenerator)
        self.incommingExpect = None
        self.outgoingExpect = None    

    def handle_Outgoing_SYN(self, archive):
        self.outgoingExpect = archive.getSeqNo() + 1

    def handle_Incomming_SYN(self, archive):
        self.incommingExpect = archive.getSeqNo() + 1

    def handle_Outgoing_FIN(self, archive):
        if self.compare(archive.getSeqNo(), self.outgoingExpect) > 0:
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
                        self.queue.append(archive)
                    else:
                        pass

    def getBuffer(self):
        return self.queue

    def tail(self):
        return self.queue[-1]

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
            if not httpRequest.hasLogged() and not httpRespond.hasLogged():
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
        first_line, second_line = stream_str_arr[0], stream_str_arr[1]
        first_line_arr = first_line.split(' ')
        self.method = first_line_arr[0]
        self.path = first_line_arr[1]
        self.version = first_line_arr[2] 
        second_line_arr = second_line.split(':')
        if second_line_arr[0] == 'Host' and len(second_line_arr) == 2:
            temp = second_line_arr[1]
            while temp[0:1] == ' ':
                temp = temp[1:]
            self.host_name = temp

    def stringGenerator(self, inputStream):
        result = ''
        for i in range(0, len(inputStream)):
            elem = chr(ord(inputStream[i:i+1]))
            result = result + elem
        return result

    def getHostName():
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
            if line_arr[0] == 'Content-Length':
                temp = line_arr[1]
                while temp[0:1] == ' ':
                    temp = temp[1:]
                self.object_size = int(temp)

    def stringGenerator(self, inputStream):
        result = ''
        for i in range(0, len(inputStream)):
            elem = chr(ord(inputStream[i:i+1]))
            result = result + elem
        return result.split('\r\n')

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
                self.stream = self.stream[0:i+4]
                self.parse_stream()

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
