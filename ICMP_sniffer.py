import socket
import pickle
import textwrap
import struct
import sys
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

TAB_1 = ' -'
TAB_2 = '   -'

DATA_TAB_1 = '    '
DATA_TAB_2 = '\t\t  '

def ICMP_sniff():
    sys.stdout = open('icmp_data.txt', 'w')
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    count = 0
    while (count<10):
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)        
        eth = Ethernet(raw_data)

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
           
            # ICMP
            if ipv4.proto == 1:
                count+=1
                print('\nEthernet Frame:')
                print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))
                
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
                print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')                
                print(format_multi_line(DATA_TAB_1, icmp.data))
                with open('icmp_header.txt','wb') as newfile :
                    pickle.dump(ipv4.version, newfile)
                    pickle.dump(ipv4.header_length, newfile)
                    pickle.dump(ipv4.src, newfile)
                    pickle.dump(ipv4.target, newfile)
            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
            # Other IPv4
            else:
                continue

    pcap.close()
#ICMP_sniff()
