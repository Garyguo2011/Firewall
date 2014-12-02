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
        if len(self.queue) == 2 and \
           type(self.queue[0]) == HTTPRequest and self.queue[0].isComplete() and \
           type(self.queue[1]) == HTTPRespond and self.queue[1].isComplete():
            return self.queue[0], self.queue[1]
        else:
            return None

    def add_to_stream(self, archive):

# ===================== HTTP Log Class ==================

class HTTPLogGenerator(object):
    def __init__(self, logfileName, staticRulesPool):
        self.logfileptr = open(logfileName, 'a')
        self.logRulesPool = staticRulesPool

    def handle_http_pair(self, httpRequest, httpRespond):
        if self.staticRulesPool.matchLogRules(httpRequest):
            # write to log
            logEntry = "%s %s %s %s %s %s\n" % \
                       (httpRequest.host_name, httpRequest.method, httpRequest.path, httpRequest.version, \
                        httpRespond.status_code, httpRespond.object_size)
            self.logfileptr.flush()
            self.logfileptr.write(logEntry)
            self.logfileptr.flush()

# ===================== HTTP Header Class ==================

class HTTPRequest(HTTPHeader):
    def __init__(self, archive):
        self.host_name = archive.getExternalIP()
        self.method = ""
        self.path = ""
        self.version = ""
    
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

class HTTPRespond(HTTPHeader):
    def __init__(self, archive):
        self.complete = False
        self.status_code = ""
        self.object_size = -1

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

    def append_to_tail(self, archive):
        if self.complete == False:
            self.stream += self.get_tcp_payload(archive)
            self.check_complete()

    def get_tcp_payload(self, archive):
        # return None if no data

    def check_complete(self):
        # Search entire stream see if "\r\n" has occur
        # if so, set complete = True and call parse_stream()

    def parse_stream(self):
        # Subclass need to overide this function
        pass

    def isComplete(self):
        return self.complete

    def getStream(self):
        return self.stream