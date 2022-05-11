import re
import checksum as cs

##
# @fn       _add_header
# @brief    This private method is used to add the message header and checksum value to each packet 
#           that is going to be sent from a sending process to a receiving process.
#
# @param    packet  - A byte array object containing packet data.
#
# @return   Returns the input packet with the header appended to the front of the message, and the
#           packet checksum appended to the end of the message.
#
# @note     Packet Structure:
# |            |             Data              |
# |    Byte    | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | Details
# |           0|       Source Port # [15:8]    | Source port number.
# |           1|       Source Port # [7:0]     | Source port number.
# |           2|       Dest Port #   [15:8]    | Destination port number.
# |           3|       Dest Port #   [7:0]     | Destination port number.
# |           4|       Sequence #    [31:24]   | Packet sequence number.
# |           5|       Sequence #    [23:16]   | Packet sequence number.
# |           6|       Sequence #    [15:8]    | Packet sequence number.
# |           7|       Sequence #    [7:0]     | Packet sequence number.
# |           8|       ACK #         [31:24]   | ACK sequence number.
# |           9|       ACK #         [23:16]   | ACK sequence number.
# |          10|       ACK #         [15:8]    | ACK sequence number.
# |          11|       ACK #         [7:0]     | ACK sequence number.
# |          12| Header Length | 0 | 0 | 0 | 0 | Length of TCP header.
# |          13| C | E | U | A | P |RST|SYN|FIN| C, E: Congestion notifications; A: This is an ACK; RST, SYN, FIN: Connection management;
# |          14|       Recv Window   [15:8]    | # of bits receiver willing to accept.
# |          15|       Recv Window   [7:0]     | # of bits receiver willing to accept.
# |          16|       Checksum      [15:8]    | Checksum
# |          17|       Checksum      [7:0]     | Checksum
# |          18|       URG Data Ptr  [15:8]    | URG
# |          19|       URG Data Ptr  [7:0]     | URG 
# |          20|       TCP Options   [31:24]   | Options
# |          21|       TCP Options   [23:16]   | Options
# |          22|       TCP Options   [15:8]    | Options
# |          23|       TCP Options   [7:0]     | Options
# |          24|              Data             | Data
# |         ...|              Data             | Data
# |         N-1|              Data             | Data  
# |           N|              Data             | Data
def add_header(recv_port, send_port, data, sequence, ack, recv_window, c=0, e=0, u=0, a=0, p=0, rst=0, syn=0, fin=0):        
    # Generate byte array objects from the sequence numbers and TCP parameters
    # passed to the function.
    source_port_no  = recv_port.to_bytes(2, byteorder='big')
    dest_port_no    = send_port.to_bytes(2, byteorder='big')
    sequence_no     = sequence.to_bytes(4, byteorder='big')
    ack_no          = ack.to_bytes(4, byteorder='big')
    header_len      = int((24 and 0xF) << 4).to_bytes(1, byteorder='big')
    management_bits = int((c << 7) or (e << 6) or (u << 5) or (a << 4) or (p << 3) or (rst << 2) or (syn << 1) or (fin)).to_bytes(1, 'big')
    recv_window_len = recv_window.to_bytes(2, byteorder='big')
    checksum        = int(0).to_bytes(2, byteorder='big')
    urg_data_ptr    = int(0).to_bytes(2, byteorder='big')
    tcp_options     = int(0).to_bytes(4, byteorder='big')

    # Construct the TCP packet with an initial checksum of 0x0000.
    packet          = source_port_no + dest_port_no + \
                      sequence_no + \
                      ack_no + \
                      header_len + \
                      management_bits + \
                      recv_window_len + \
                      checksum + \
                      urg_data_ptr + \
                      tcp_options + \
                      data

    # Calculate the packet checksum and insert the calculated packet checksum.
    checksum_calc = cs.checksum(packet)
    packet[16] = checksum_calc[1]
    packet[17] = checksum_calc[0]

    return packet

##
# @fn       _parse_packet
# @brief    This private method is used to parse the fields in a packet received by a receiving process.
#
# @param    packet  - A byte array object containing packet data.
#
# @return   Returns the header, data, and checksum fields of the packet.
def _parse_packet(packet):
    source_port_no  = packet[0:2]
    dest_port_no    = packet[2:4]
    sequence_no     = packet[4:8]
    ack_no          = packet[8:12]
    header_len      = ((packet[12] >> 4) and 0xF)
    management_bits = packet[13]
    recv_window_len = packet[14:16]
    checksum        = packet[16:18]
    urg_data_ptr    = packet[18:20]
    tcp_options     = packet[20:24]
    data            = packet[24:-1]

    return source_port_no, dest_port_no, sequence_no, ack_no, header_len, management_bits, recv_window_len, checksum, urg_data_ptr, tcp_options, data



def get_source_port_number(packet):
    return int.from_bytes(packet[0:2], 'big')

def get_destination_port_number(packet):
    return int.from_bytes(packet[2:4], 'big')

def get_sequence_number(packet):
    return int.from_bytes(packet[4:8], 'big')

def get_ack_number(packet):
    return int.from_bytes(packet[8:12], 'big')

def get_header_len(packet):
    return ((int.from_bytes(packet[12]) >> 4) and 0xF)

def get_receive_window_len(packet):
    return int.from_bytes(packet[14:16], 'big')

def get_checksum(packet):
    return int.from_bytes(packet[16:18], 'big')

def get_data(packet):
    return packet[24:-1]

def is_ack(packet):
    if (int.from_bytes(packet[13], 'big') and 0b0001_0000) == 0:
        return False
    else:
        return True