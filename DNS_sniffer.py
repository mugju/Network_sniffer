from scapy.all import *
from datetime import datetime
import time
import datetime
import sys

def select_DNS(pkt):
       pkt_time = pkt.sprintf('%sent.time%')


# SELECT/FILTER DNS MSGS
       try:

           dict = []

           # queries
           if DNSQR in pkt and pkt.dport == 53:
               domain = pkt.getlayer(DNS).qd.qname.decode() # .decode() gets rid of the b''
               print('Q - Time: ' + pkt_time + ' , source IP: ' + pkt[IP].src + ' , domain: ' + domain)

           # responses
           elif DNSRR in pkt and pkt.sport == 53:
               domain = pkt.getlayer(DNS).qd.qname.decode()
               print('R - Time: ' + pkt_time + ' , source IP: ' + pkt[IP].src + ' , domain: ' + domain)


           print('----------------------IP Layer-----------------------')
           print('IP version:',pkt[IP].version)
           print('IP Header Length:',pkt[IP].ihl)
           print('Type Of Service:',pkt[IP].tos)
           print('Total Length:',pkt[IP].len)
           print('Identification:',pkt[IP].id)
           print('IP Flags:',pkt[IP].flags)
           print('IP Fragment Offset:',pkt[IP].frag)
           print('IP Time to Live:',pkt[IP].ttl)
           print('IP Protocol:',pkt[IP].proto)
           print('IP Header Checksum:',pkt[IP].chksum)
           print('Source Address:',pkt[IP].src)
           print('Destination Address:',pkt[IP].dst)
           print('---------------------UDP Layer-----------------------')
           print('UDP Source Port:',pkt[UDP].sport)
           print('UDP Destination Port:',pkt[UDP].dport)
           print('UDP Length:',pkt[UDP].len)
           print('UDP Checksum:',pkt[UDP].chksum)
           print('---------------------DNS Layer-----------------------')
           print('DNS Identification:',pkt[DNS].id)
           print('DNS Query/Response:',pkt[DNS].qr)
           print('DNS Operation Code:',pkt[DNS].opcode)
           print('DNS Authoritative Answer:',pkt[DNS].aa)
           print('DNS Truncated:',pkt[DNS].tc)
           print('DNS Recursion Desired:',pkt[DNS].rd)
           print('DNS Recursion Available:',pkt[DNS].ra)
           print('DNS Reserved:',pkt[DNS].z)
           print('DNS Response Code:',pkt[DNS].rcode)


           hexdump(pkt)
           


       except:
           pass

# START SNIFFER
# Select interface and DNS
interface = 'ens33'
bpf = 'udp and port 53'

def DNS_sniff():    
       sys.stdout = open('DNS.txt', 'w')
       sniff(count=4, iface=interface, filter=bpf, store=0,  prn=select_DNS)

