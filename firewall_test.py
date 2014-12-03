#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

import socket
import struct
import time
import random


from firewall import *

# Remove Latter
#================================
import sys
import subprocess
#================================

fptr = open("http_expect.log", "r")
expect_str = fptr.read()
fptr.close()

################ Flow Test #######################
def log_http_test():
    print "[Test case 1]: test log http *.berkeley.edu, should see 8 logs"
    subprocess.check_output('rm http.log; touch http.log', shell=True)
    config = {}
    config['rule'] = 'flowtest.conf'
    firewall = Firewall(config, None, None)
    for i in range (0, 103):
        file_ptr = open("dir-2/" + str(i) + "-pkt", "r")
        pkt = file_ptr.read()
        file_ptr.close()
        dir_ptr = open("dir-2/" + str(i) + "-dir", "r")
        direction = dir_ptr.read()
        dir_ptr.close()
        if direction == "1":
            pkt_dir = PKT_DIR_OUTGOING
        else:
            pkt_dir = PKT_DIR_INCOMING
        firewall.handle_packet(pkt_dir,pkt)
    output = subprocess.check_output('cat http.log', shell=True)
    entries = subprocess.check_output("cat http.log | wc -l ", shell=True)
    # print ">>>>>> should:"
    # print "www-inst.eecs.berkeley.edu GET /~cs168/fa14 HTTP/1.1 301 254\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/ HTTP/1.1 200 273\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/content.html HTTP/1.1 200 1569\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/overview.html HTTP/1.1 200 2581\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Book.png HTTP/1.1 200 174\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Keycard_A.png HTTP/1.1 200 324\nwww.eecs.berkeley.edu GET /Includes/EECS-images/eecslogo.gif HTTP/1.1 200 828\nwww-inst.eecs.berkeley.edu GET /favicon.ico HTTP/1.1 200 0" 
    # print "<<<<<< actual:"
    # print output
    assert output == expect_str
    print "Total Entries:" + entries

def stringGenerator(inputStream):
        result = ''
        for i in range(0, len(inputStream)):
            elem = chr(ord(inputStream[i:i+1]))
            result = result + elem
        return result

def reassembly_piece_test():
    print "[Test case 2]: reassembly_piece_test"
    subprocess.check_output('rm http.log; touch http.log', shell=True)
    config = {}
    config['rule'] = 'flowtest.conf'
    firewall = Firewall(config, None, None)
    for i in range (0, 13):
        file_ptr = open("dir-2/" + str(i) + "-pkt", "r")
        pkt = file_ptr.read()
        file_ptr.close()
        dir_ptr = open("dir-2/" + str(i) + "-dir", "r")
        direction = dir_ptr.read()
        dir_ptr.close()
        if direction == "1":
            pkt_dir = PKT_DIR_OUTGOING
        else:
            pkt_dir = PKT_DIR_INCOMING

        if i == 10 - 5:

            ipLength = (15 & ord(pkt[0:1])) * 4
            offset = ((ord(pkt[ipLength + 12: ipLength + 13]) >> 4) & 15) * 4
            seqNo = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]

            data = pkt[ipLength + offset: len(pkt)]
            # print "reachi here >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            # dataStr = stringGenerator(data)
            # print chr(ord(data[0]))
            # print "reachi here >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            for i in range(0, len(data)):
                pkt_seq = struct.pack('!L', seqNo + i)
                new_pkt = pkt[0 : (ipLength+4)] + pkt_seq + pkt[(ipLength + 8): (ipLength + offset)] + data[i]
                firewall.handle_packet(pkt_dir, new_pkt)
        else:
            firewall.handle_packet(pkt_dir,pkt)
    output = subprocess.check_output('cat http.log', shell=True)
    print ">>>>>> should:"
    print "www-inst.eecs.berkeley.edu GET /~cs168/fa14 HTTP/1.1 301 254"
    print "<<<<<< actual: "
    print output

def reassembly_not_entire_file_test():
    print "[Test case 3]: reassembly_not_entire_file_test"
    subprocess.check_output('rm http.log; touch http.log', shell=True)
    config = {}
    config['rule'] = 'flowtest.conf'
    firewall = Firewall(config, None, None)
    for i in range (0, 103):
        file_ptr = open("dir-2/" + str(i) + "-pkt", "r")
        pkt = file_ptr.read()
        file_ptr.close()
        dir_ptr = open("dir-2/" + str(i) + "-dir", "r")
        direction = dir_ptr.read()
        dir_ptr.close()
        if direction == "1":
            pkt_dir = PKT_DIR_OUTGOING
        else:
            pkt_dir = PKT_DIR_INCOMING

        if i == 35 - 5:
            ipLength = (15 & ord(pkt[0:1])) * 4
            offset = ((ord(pkt[ipLength + 12: ipLength + 13]) >> 4) & 15) * 4
            seqNo = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]

            data = pkt[ipLength + offset: len(pkt)]
            # print "reachi here >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            # dataStr = stringGenerator(data)
            # print chr(ord(data[0]))
            # print "reachi here >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            for i in range(0, len(data)):
                pkt_seq = struct.pack('!L', seqNo + i)
                new_pkt = pkt[0 : (ipLength+4)] + pkt_seq + pkt[(ipLength + 8): (ipLength + offset)] + data[i]
                firewall.handle_packet(pkt_dir, new_pkt)
        else:
            firewall.handle_packet(pkt_dir,pkt)
    output = subprocess.check_output('cat http.log', shell=True)
    # print ">>>>>> should:"
    # print "www-inst.eecs.berkeley.edu GET /~cs168/fa14 HTTP/1.1 301 254\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/ HTTP/1.1 200 273\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/content.html HTTP/1.1 200 1569\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/overview.html HTTP/1.1 200 2581\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Book.png HTTP/1.1 200 174\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Keycard_A.png HTTP/1.1 200 324\nwww.eecs.berkeley.edu GET /Includes/EECS-images/eecslogo.gif HTTP/1.1 200 828\nwww-inst.eecs.berkeley.edu GET /favicon.ico HTTP/1.1 200 0" 
    # print "<<<<<< actual: "
    # print output
    assert output == expect_str

def packet_out_of_order_test():
    print "[Test case 4]: packet_out_of_order_test"
    subprocess.check_output('rm http.log; touch http.log', shell=True)
    config = {}
    config['rule'] = 'flowtest.conf'
    firewall = Firewall(config, None, None)
    for i in range (0, 103):
        pkt = getPacket(i)
        pkt_dir = getDir(i)
        if i in [random.randint(4, 97), random.randint(4, 97), random.randint(4, 97)]:
            # print getSeqNo(getPacket(i))
            # print ">>>>>>>>>> out of order start <<<<<<<<<<<<<<"
            for j in [i+4, i+3, i+5, i+2, i+1, i]:
                # print getSeqNo(getPacket(j))
                firewall.handle_packet(getDir(j),getPacket(j))
            # print ">>>>>>>>>> out of order End <<<<<<<<<<<<<<"
        else:
            firewall.handle_packet(pkt_dir,pkt)
    output = subprocess.check_output('cat http.log', shell=True)
    # print ">>>>>> should:"
    # print "www-inst.eecs.berkeley.edu GET /~cs168/fa14 HTTP/1.1 301 254\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/ HTTP/1.1 200 273\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/content.html HTTP/1.1 200 1569\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/overview.html HTTP/1.1 200 2581\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Book.png HTTP/1.1 200 174\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Keycard_A.png HTTP/1.1 200 324\nwww.eecs.berkeley.edu GET /Includes/EECS-images/eecslogo.gif HTTP/1.1 200 828\nwww-inst.eecs.berkeley.edu GET /favicon.ico HTTP/1.1 200 0" 
    # print "<<<<<< actual: "
    # print output
    assert output == expect_str

def random_reassembly_piece_test():
    print "[Test case 5]: random_reassembly_piece_test"
    subprocess.check_output('rm http.log; touch http.log', shell=True)
    config = {}
    config['rule'] = 'flowtest.conf'
    firewall = Firewall(config, None, None)
    for i in range (0, 103):
        file_ptr = open("dir-2/" + str(i) + "-pkt", "r")
        pkt = file_ptr.read()
        file_ptr.close()
        dir_ptr = open("dir-2/" + str(i) + "-dir", "r")
        direction = dir_ptr.read()
        dir_ptr.close()
        if direction == "1":
            pkt_dir = PKT_DIR_OUTGOING
        else:
            pkt_dir = PKT_DIR_INCOMING

        protocolNumber = ord(pkt[9:10])    

        if i == random.randint(0, 102) and protocolNumber == 6:
            ipLength = (15 & ord(pkt[0:1])) * 4
            offset = ((ord(pkt[ipLength + 12: ipLength + 13]) >> 4) & 15) * 4
            seqNo = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]

            data = pkt[ipLength + offset: len(pkt)]
            # print "reachi here >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            # dataStr = stringGenerator(data)
            # print chr(ord(data[0]))
            # print "reachi here >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            for i in range(0, len(data)):
                pkt_seq = struct.pack('!L', seqNo + i)
                new_pkt = pkt[0 : (ipLength+4)] + pkt_seq + pkt[(ipLength + 8): (ipLength + offset)] + data[i]
                firewall.handle_packet(pkt_dir, new_pkt)
        else:
            firewall.handle_packet(pkt_dir,pkt)
    output = subprocess.check_output('cat http.log', shell=True)
    # print ">>>>>> should:"
    # print "www-inst.eecs.berkeley.edu GET /~cs168/fa14 HTTP/1.1 301 254\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/ HTTP/1.1 200 273\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/content.html HTTP/1.1 200 1569\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/overview.html HTTP/1.1 200 2581\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Book.png HTTP/1.1 200 174\nwww-inst.eecs.berkeley.edu GET /~cs168/fa14/images/Keycard_A.png HTTP/1.1 200 324\nwww.eecs.berkeley.edu GET /Includes/EECS-images/eecslogo.gif HTTP/1.1 200 828\nwww-inst.eecs.berkeley.edu GET /favicon.ico HTTP/1.1 200 0" 
    # print "<<<<<< actual: "
    # print output
    assert output == expect_str


def getPacket(i):
    file_ptr = open("dir-2/" + str(i) + "-pkt", "r")
    pkt = file_ptr.read()
    file_ptr.close()
    return pkt

def getDir(i):
    dir_ptr = open("dir-2/" + str(i) + "-dir", "r")
    direction = dir_ptr.read()
    dir_ptr.close()    
    if direction == "1":
        pkt_dir = PKT_DIR_OUTGOING
    else:
        pkt_dir = PKT_DIR_INCOMING
    return pkt_dir

def getSeqNo(pkt):
    ipLength = (15 & ord(pkt[0:1])) * 4
    seqno = struct.unpack('!L', pkt[(ipLength + 4): (ipLength + 8)])[0]
    return seqno

log_http_test()
reassembly_piece_test()
reassembly_not_entire_file_test()
packet_out_of_order_test()
random_reassembly_piece_test()