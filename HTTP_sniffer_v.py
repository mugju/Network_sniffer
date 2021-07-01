#20-11-24 Kim Dong Hyeok 
#Http Test Code

import socket
import struct
import textwrap
import sys

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def HTTP_sni():
    #print('sdsa')
    sys.stdout = open('http_data.txt','w')
    f = open("HTTPlog.txt", 'w')
    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    count = 0
    #while True:
    while (count < 15):
        
        raw_data, addr = conn.recvfrom(1024)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
 
            # TCP
            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])
                

                if len(data) > 300 and data[-2:-1] == b'\r'  :
                    count = count + 1
                    # HTTP
                    if src_port == 80 or dest_port == 80 or src_port == 443 or dest_port == 443 :
                        print('\n Ethernet Frame: ')
                        f.write('\n Ethernet Frame:\n')
                        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
                        f.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
                        print(TAB_1 + "IPV4 Packet:")
                        f.write(TAB_1 +" \nIPV4 Packet:\n")
                        print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                        f.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                        print(TAB_2 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                        f.write(TAB_2 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                        
                        print(TAB_1 + 'TCP Segment:')
                        f.write(TAB_1 + '\nTCP Segment:')
                        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                        f.write(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                        print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                        f.write(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                        print(TAB_2 + 'Flags:')
                        f.write(TAB_2 + 'Flags:')
                        print(TAB_2 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                        f.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                        print(TAB_2 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
                        f.write(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
                        
                        print('- HTTP Header:')
                        f.write(TAB_2 + 'HTTP Header:')
                        #print(sys.getsizeof(data))
                        print(data)
                        # f1.write(str(data))

                        print('====================================================================================')
                        #print(data[-2:-1]==b'\r')
                        #print(type(data[-2:-1]))

                        try:
                            print('ok')
                            http = HTTP(data)
                            print(http)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_output_line(DATA_TAB_3, data))
                    
            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_seg(data)



        else:
            continue




# Unpack Ethernet Frame
def ethernet_frame(data):
    #check data
    #print(data)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Format MAC Address
def get_mac_addr(bytes_addr):
    #bytes_str = map('{:02x}'.format, [int(i) for i in bytes_addr])
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserv_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >>4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats the output line
def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
def HTTP(data):
    http = data.decode('utf-8')
    return http

def http_loop():
    i = 1;
    while(i<5):
        HTTP_sni()
        i = i+1
if __name__ == "__main__" :
    #main()
    HTTP_sni()
    #http_loop()
