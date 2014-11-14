from bypass_phase1 import Firewall
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket

f = open ('icmppacketpool8')
inputbuffer = f.read()


firewallTest = Firewall(None, None, None)

archieve = firewallTest.packet_allocator(PKT_DIR_OUTGOING, inputbuffer)
print 'external ip: ' + socket.inet_ntoa(archieve.externalIP)
print 'protocol: ' + archieve.protocol
print 'icmp type : ' + str(archieve.type)