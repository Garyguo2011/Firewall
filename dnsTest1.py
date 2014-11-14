from bypass_phase1 import Firewall
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket

f = open ('dnspacketpool0')
inputbuffer = f.read()


firewallTest = Firewall(None, None, None)

archieve = firewallTest.packet_allocator(PKT_DIR_OUTGOING, inputbuffer)
print 'external ip: ' + socket.inet_ntoa(archieve.externalIP)
print 'protocol: ' + archieve.protocol
print 'externalPort: ' + str(archieve.externalPort)
print 'self.domainName: ' + archieve.domainName