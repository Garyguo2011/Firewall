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
        pass

    def checksum():
        # Implement this


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


