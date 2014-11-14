from bypass_phase1 import Firewall
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket

def ip_int_to_str(ipNum):
	ipStrList = []
	ipStrList.append((ipNum >> 24) & 255)
	ipStrList.append((ipNum >> 16) & 255)
	ipStrList.append((ipNum >> 8) & 255)
	ipStrList.append((ipNum >> 0) & 255)
	return "%d.%d.%d.%d" % (ipStrList[0], ipStrList[1], ipStrList[2], ipStrList[3])

f = open ('dnspacketpool0')
inputbuffer = f.read()
firewallTest = Firewall(None, None, None)

archieve = firewallTest.packet_allocator(PKT_DIR_OUTGOING, inputbuffer)
print 'external ip: ' + ip_int_to_str(archieve.externalIP)
print 'protocol: ' + archieve.protocol
print 'externalPort: ' + str(archieve.externalPort)
print 'self.domainName: ' + archieve.domainName

