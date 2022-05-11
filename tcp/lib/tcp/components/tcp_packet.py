from . import checksum as cslib

##
# @class    Packet
# @brief    Class used to encapsulate the TCP packet structure and provide an interface
#           for providing access to values within the TCP packet on demand.
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
class TCP_Packet:
    ##
    # @fn       __init__
    # @brief    Class constructor for the TCP_Packet class.
    #
    # @param    src_port    Integer value representing the source port from which the packet is being sent.
    # @param    dst_port    Integer value representing the destination port to which the packet will be sent.
    # @param    seq_no      Integer value representing the packet sequence number.
    # @param    ack_no      Integer value representing the packet acknowledgement number.
    # @param    rcv_window  Integer value representing the size of the receive window in the TCP connection.
    # @param    data        Bytes object representing the data that will be contained in the packet.
    # @param    cwr         (optional) TCP managements bits CWR-bit value.
    # @param    ece         (optional) TCP managements bits ECE-bit value.
    # @param    urg         (optional) TCP managements bits URG-bit value.
    # @param    ack         (optional) TCP managements bits ACK-bit value.
    # @param    psh         (optional) TCP managements bits PSH-bit value.
    # @param    rst         (optional) TCP managements bits RST-bit value.
    # @param    syn         (optional) TCP managements bits SYN-bit value.
    # @param    fin         (optional) TCP managements bits FIN-bit value.
    #
    # @return   None.
    def __init__(self, src_port, dst_port, seq_no, ack_no, rcv_window, data, cwr=0, ece=0, urg=0, ack=0, psh=0, rst=0, syn=0, fin=0):
        self._src_port      = bytearray(src_port.to_bytes(2, byteorder='big'))
        self._dst_port      = bytearray(dst_port.to_bytes(2, byteorder='big'))
        self._seq_no        = bytearray(seq_no.to_bytes(4, byteorder='big'))
        self._ack_no        = bytearray(ack_no.to_bytes(4, byteorder='big'))
        self._header_len    = bytearray(int((24 & 0xF) << 4).to_bytes(1, byteorder='big'))
        self._mgmt_bits     = bytearray(int((cwr << 7) | (ece << 6) | (urg << 5) | (ack << 4) | (psh << 3) | (rst << 2) | (syn << 1) | (fin)).to_bytes(1, 'big'))
        self._rcv_window    = bytearray(rcv_window.to_bytes(2, byteorder='big'))
        self._checksum      = bytearray(int(0).to_bytes(2, byteorder='big'))
        self._urg_data_ptr  = bytearray(int(0).to_bytes(2, byteorder='big'))
        self._options       = bytearray(int(0).to_bytes(4, byteorder='big'))
        self._data          = data

        # Construct the TCP packet based on the provided input data.
        if self._data is None:
            self._packet =  self._src_port     + \
                            self._dst_port     + \
                            self._seq_no       + \
                            self._ack_no       + \
                            self._header_len   + \
                            self._mgmt_bits    + \
                            self._rcv_window   + \
                            self._checksum     + \
                            self._urg_data_ptr + \
                            self._options
        else:
            self._packet =  self._src_port     + \
                            self._dst_port     + \
                            self._seq_no       + \
                            self._ack_no       + \
                            self._header_len   + \
                            self._mgmt_bits    + \
                            self._rcv_window   + \
                            self._checksum     + \
                            self._urg_data_ptr + \
                            self._options      + \
                            self._data
        cs = bytearray(cslib.checksum(self._packet))  #TODO: Insert checksum library.
        self._packet[16:18] = cs
        self._checksum      = cs
        return

    ##
    # @fn       is_valid
    # @brief    Validates the checksum of the packet.
    #
    # @param    None.
    #
    # @return   Returns True if the checksum is valid, and returns False if the checksum is invalid.
    def is_valid(self):
        cs         = self._checksum
        pkt        = self._packet
        pkt[16:18] = bytearray(int(0).to_bytes(2, byteorder='big'))
        if cs == bytearray(cslib.checksum(pkt)):
            return True
        else:
            return False

    ## 
    # @fn       _recalculate_checksum
    # @brief    Private method used to recalculate the packet checksum when a value is changed using a setter method.
    #
    # @param    None.
    #
    # @return   None.
    def _recalculate_checksum(self):
        self._checksum = int(0).to_bytes(2, byteorder='big')
        
        if self._data is None:
            self._packet =  self._src_port     + \
                            self._dst_port     + \
                            self._seq_no       + \
                            self._ack_no       + \
                            self._header_len   + \
                            self._mgmt_bits    + \
                            self._rcv_window   + \
                            self._checksum     + \
                            self._urg_data_ptr + \
                            self._options
        else:
            self._packet =  self._src_port     + \
                            self._dst_port     + \
                            self._seq_no       + \
                            self._ack_no       + \
                            self._header_len   + \
                            self._mgmt_bits    + \
                            self._rcv_window   + \
                            self._checksum     + \
                            self._urg_data_ptr + \
                            self._options      + \
                            self._data

        cs = bytearray(cslib.checksum(self._packet))
        self._packet[16:18] = cs
        self._checksum      = cs

    # self._packet getter and setter properties.
    @property
    def packet(self):        
        return self._packet

    @packet.setter
    def packet(self, packet):
        self._packet        = bytearray(packet)
        self._src_port      = self._packet[0:2]
        self._dst_port      = self._packet[2:4]
        self._seq_no        = self._packet[4:8]
        self._ack_no        = self._packet[8:12]
        self._header_len    = self._packet[12].to_bytes(1, 'big')
        self._mgmt_bits     = self._packet[13].to_bytes(1, 'big')
        self._rcv_window    = self._packet[14:16]
        self._checksum      = self._packet[16:18]
        self._urg_data_ptr  = self._packet[18:20]
        self._options       = self._packet[20:25]

        if len(packet) < 25:
            self._data = None
        else:
            self._data = self._packet[24:]
        
    # self._src_port getter and setter properties.
    @property
    def src_port(self):
        return int.from_bytes(self._src_port, 'big')

    @src_port.setter
    def src_port(self, port_no):
        self._src_port = port_no.to_bytes(2, byteorder='big')
        self._recalculate_checksum()

    # self._dst_port getter and setter properties.
    @property
    def dst_port(self):
        return int.from_bytes(self._dst_port, 'big')

    @dst_port.setter
    def dst_port(self, port_no):
        self._dst_port = port_no.to_bytes(2, byteorder='big')
        self._recalculate_checksum()

    # self._seq_no getter and setter properties.
    @property
    def seq_no(self):
        return int.from_bytes(self._seq_no, 'big')

    @seq_no.setter
    def seq_no(self, seq_no):
        self._seq_no = seq_no.to_bytes(4, byteorder='big')
        self._recalculate_checksum()

    # self._ack_no getter and setter properties.
    @property
    def ack_no(self):
        return int.from_bytes(self._ack_no, 'big')

    @ack_no.setter
    def ack_no(self, ack_no):
        self._ack_no = ack_no.to_bytes(4, byteorder='big')
        self._recalculate_checksum()

    # self._header_len getter property.
    @property
    def header_len(self):
        return ((int.from_bytes(self._header_len, 'big') >> 4) & 0xF)

    # self._rcv_window getter and setter properties.
    @property
    def rcv_window(self):
        return int.from_bytes(self._rcv_window, 'big')

    @rcv_window.setter
    def rcv_window(self, rcv_window):
        self._rcv_window = rcv_window.to_bytes(2, byteorder='big')
        self._recalculate_checksum()

    # self._checksum getter and setter properties.
    @property
    def checksum(self):
        return self._checksum

    @checksum.setter
    def checksum(self, checksum):
        self._checksum = checksum
        self._recalculate_checksum()

    # self._data getter and setter properties.
    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._data = data

        if len(self._packet) > 24:
            self._packet = self._packet[0:24]

        if self._data is None:
            self._packet = self._packet[0:24]
        else:
            self._packet += self._data

        self._recalculate_checksum()

    # TCP management bit getter and setter properties.
    @property
    def mgmt_cwr(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b1000_0000) >> 7)

    @mgmt_cwr.setter
    def mgmt_cwr(self, cwr):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b0111_1111) | ((cwr & 0b1) << 7)).to_bytes(1, 'big')
        self._recalculate_checksum()

    @property
    def mgmt_ece(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b0100_0000) >> 6)

    @mgmt_ece.setter
    def mgmt_ece(self, ece):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b1011_1111) | ((ece & 0b1) << 6)).to_bytes(1, 'big')
        self._recalculate_checksum()

    @property
    def mgmt_urg(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b0010_0000) >> 5)

    @mgmt_urg.setter
    def mgmt_urg(self, urg):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b1101_1111) | ((urg & 0b1) << 5)).to_bytes(1, 'big')
        self._recalculate_checksum()

    @property
    def mgmt_ack(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b0001_0000) >> 4)

    @mgmt_ack.setter
    def mgmt_ack(self, ack):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b1110_1111) | ((ack & 0b1) << 4)).to_bytes(1, 'big')
        self._recalculate_checksum()

    @property
    def mgmt_psh(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b0000_1000) >> 3)

    @mgmt_psh.setter
    def mgmt_psh(self, psh):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b1111_0111) | ((psh & 0b1) << 3)).to_bytes(1, 'big')
        self._recalculate_checksum()

    @property
    def mgmt_rst(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b0000_0100) >> 2)

    @mgmt_rst.setter
    def mgmt_rst(self, rst):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b1111_1011) | ((rst & 0b1) << 2)).to_bytes(1, 'big')
        self._recalculate_checksum()

    @property
    def mgmt_syn(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b0000_0010) >> 1)

    @mgmt_syn.setter
    def mgmt_syn(self, syn):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b1111_1101) | ((syn & 0b1) << 1)).to_bytes(1, 'big')
        self._recalculate_checksum()

    @property
    def mgmt_fin(self):
        return ((int.from_bytes(self._mgmt_bits, 'big') & 0b0000_0001) >> 0)

    @mgmt_fin.setter
    def mgmt_fin(self, fin):
        self._mgmt_bits = ((int.from_bytes(self._mgmt_bits, 'big') & 0b1111_1110) | ((fin & 0b1) << 0)).to_bytes(1, 'big')
        self._recalculate_checksum()

if __name__ == "__main__":
    data = bytearray(10)
    packet = TCP_Packet(50000, 52000, 0, 0, 500, data, syn=1)
    # print(packet.is_valid())
    packet2 = TCP_Packet(53000, 54000, 0, 0, 500, None, syn=1)
    print(type(packet2.mgmt_ack))
    packet2.mgmt_ack = 1
    print(type(packet2.mgmt_ack))
