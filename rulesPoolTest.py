# rulesPoolTest.py

from rulesPool import Rule, GeneralRule, DNSRule, StaticRulesPool
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from archiveGenerator import TCPArchive, UDPArchive, ICMPArchive, DNSArchive

staticRulePool = StaticRulesPool("rulesTest.conf")
print(staticRulePool)

# archivePool = []

# pkt_dir
# protocol = "Don't need worry"
# externalIP 
# countryCode
# packet
# verdict
# externalPort
# app
# domainName

# archivePool.append(TCPArchive(pkt_dir, protocol, externalIP, countryCode, packet, verdict, externalPort))