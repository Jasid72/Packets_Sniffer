from scapy.all import *
import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

Data_TAB_1 = '\t '
Data_TAB_2 = '\t\t '
Data_TAB_3 = '\t\t\t '
Data_TAB_4 = '\t\t\t\t '


def main():
    eth_frame = Ether(dst="00:11:22:33:44:55")
    ip_packet = IP(src="192.168.1.2", dst="192.168.1.1")
    custom_payload = Raw(b"This is a custom payload")

    # Combine the layers to create the packet
    packet = eth_frame , ip_packet , custom_payload
    def packet_handler(packet):
        if Ether in packet:
            eth_frame = packet[Ether]
            print('\nEthernet Frame:')
            print('Destination: {}, Source: {}, Type: 0x{:04x}'.format(eth_frame.dst, eth_frame.src, eth_frame.type))

    # Start packet capture using Scapy's sniff function
    sniff(prn=packet_handler, store=0, count=0)
    if eth_frame == 8:
        (version, header_length, ttl, proto, src, target, data ) = ipv4_packet(data)
        print(TAB_1 + "IPv4 Packets:")
        print(TBA_2 + "Version {}, Header Length{}, TTL{}".format(version, header_length, ttl))
        print(TBA_2 + "Proto {}, Src{}, Target{}".format(proto, src, target))
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)
            print(TAB_1 + "ICMP Packets:")
            print(TAB_2 + "Type {}, Code {}, Checksum{}".format(icmp_type, code, checksum))
            print(TAB_2 + "Data:")
            print(format_multi_line(DATA_TAB_3, data))


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]
# return Properly Formatted MAC Address (i.e AA;BB;CC;DD)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr)
    return ':'.join(bytes_str).upper()
#Unpacks IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src,  traget = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return  version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length]
# Return Properly Formatted IPv4 Address
def ipv4(addr):
    return  ','.join(map(str, addr))
#Unpack ICMP Packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]
#Unpack TCP segment
def tcp_segment(data):
    (src_port, des_port,  sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12)  * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, des_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

main()