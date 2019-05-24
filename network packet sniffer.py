
import socket
import struct
import textwrap

tab_1='\t   '
tab_2='\t\t    '
tab_3='\t\t\t     '
tab_4='\t\t           '

data_tab_1='\t '
data_tab_1='\t\t '
data_tab_1='\t\t\t '
data_tab_1='\t\t\t\t '

# we made a connection using sockets and made non ending loop as the connection is going to get src , dest mac and protocol number
def main():
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, proto, data = Ethernet_Frame(raw_data)
        print('\n Ethernet Frame')
        print('Destination: {} , Source: {} , Protocol: {}'.format(dest_mac, src_mac, proto))

# 8 for ipv4
if proto == 8:
       (version , header_length, ttl , protoo,src,dest,data)=Ipv4_packet(data)
       print(tab_1+ 'ipv4 packet: ')
       print(tab_2+ 'version: {} , header lenght: {} , ttl: {}'.format(version,header_length,ttl))
       print(tab_2+ 'protocol: {} , source: {} , dest: {}'.format(protoo,src,dest))

elif proto == 1:
          icmp_type, code, checksum=Icmp_packet(data)
          print(tab_1+ 'Icmp packet: ')
          print(tab_2+ 'type: {} , code: {} , checksum: {}'.format(icmp_type,code,checksum))
          print(tab_2 + 'data:' )
          print(format_multi_line(data_tab_3,data))
#Tcp
elif protoo==6:
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags)=Tcp_segment(data)
    print(tab_1 + 'TCP segment')
    print(tab_2 + 'source port: {} , destination port: {}'.format(src_port,dest_port))
    print(tab_2 + 'sequence: {} , acknowledgement: {}'.format(sequence,acknowledgement))
    print(tab_2 + 'flags: {}')
    print(tab_3 + 'ARG: {} , ACK: {} , PSH: {} , RST: {}, SYN: {} , FIN: {}'.format(flag_arg,flag_ack,flag_push,flag_rst,flag_syn,flag_fin))
    print(format_multi_line(data_tab_3, data))

elif protoo==17:
    src_port, dest_port, size=Udp_segment(data)
    print(tab_1 + 'UDP segment')
    print(tab_2 + 'source port: {} , destination port: {} , lenght: {}'.format(src_port, dest_port, size))
else:
        print(tab_1 + 'data')
        print(format_multi_line(data_tab_2,data))


# unpacking the ethernet frame and setting the source & destination mac to 2 variables and the protocol part to convert packet to bytes with
# an overall number of 14 and return them
def Ethernet_Frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return [get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]]


# this function take bytes and convert them to MAC address format using map function : AA:BB:CC:DD:EE:FF
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format(), bytes_addr)
    return ':'.join(bytes_str).upper()

def Ipv4_packet(data):
    version_header_lenght=data[0]
    version=version_&_header_lenght >>4
    header_length=(version_header_lenght & 15)*4
    ttl,protoo,src,dest=struct.unpack('! 8x B B 2x 4s 4s ' , data[:20])
    return  version,data[header_length],ttl,ipv4(src),ipv4(dest),header_length,protoo

def ipv4(addr):
    return '.'.join(map(str,addr))

def Icmp_packet(data):
    icmp_type,code,checksum=struct.unpack("! B B H", data[:4])
    return icmp_type,checksum,code,data[:4]

def Tcp_segment(data):
    (src_port,dest_port,sequence,acknowledgement,offset_reserved_flags)=struct.unpack('! H H L L H' , data[:14])
    offset=(offset_reserved_flags >> 12 )*4
    flag_arg = (offset_reserved_flags >> 32) * 5
    flag_ack = (offset_reserved_flags >> 16) * 4
    flag_push = (offset_reserved_flags >> 8) * 3
    flag_rst = (offset_reserved_flags >> 4) * 2
    flag_syn = (offset_reserved_flags >> 2) * 1
    flag_fin = (offset_reserved_flags >> 1) * 4
    return src_port , dest_port , sequence , acknowledgement , data[offset:] , flag_ack,flag_arg , flag_fin,flag_push,flag_rst,flag_syn

def Udp_segment(data):
    src_port , dest_port,size=struct.unpack('! H H 2x H', data[:8])
    return src_port,dest_port,size,data[8:]

def Format_mulity_line(prefix,string,size=80):
    size -= length(prefix)
    if isinstance(string,bytess):
        string="".join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
                size -=1
        return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])

