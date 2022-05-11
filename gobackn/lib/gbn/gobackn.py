import socket
import threading
from time import time
from .components.checksum import *
from .components.fault_injection import *

DEBUG = False

class GoBackN:
    ACK = 0x00

    def __init__(self, send_address, send_port, recv_address, recv_port, window_size, mss=500,corruption=0, corruption_option=[1, 2, 3], loss=0, loss_option=[1, 2, 3], timeout=None):
        # Public Parameters
        self.base           = 0             ## Base index of the sending window used by GBN and SR protocols.
        self.window_size    = window_size   ## Sending window size used by GBN and SR protocols.
        self.send_address   = send_address  ## Address of the sending socket.
        self.recv_address   = recv_address  ## Address of the receiving socket.
        self.send_port      = send_port     ## Port used for sending data.
        self.recv_port      = recv_port     ## Port used for receiving data.

        # Public Parameters (Debug)
        self.corruption         = corruption        ## Packet corruption percentage used for debug.
        self.corruption_option  = corruption_option ## List of selected debug options. 1=No Packet Corruption, 2=ACK Packet Corruption, 3=Data Packet Corruption.
        self.loss               = loss              ## Packet loss percentage used for debug.
        self.loss_option        = loss_option       ## List of selected debug options. 1=No Packet Loss, 2=ACK Packet Loss, 3=Data Packet Loss.
        self.timeout            = timeout           ## Time in seconds before a connection is considered to have experienced a timeout.

        # Private Parameters
        self._seqnum             = 0
        self._ack_pending_timers = []
        self._ack_pending_buffer = []
        for i in range(self.window_size):
            self._ack_pending_buffer.append(i)

        # Sockets
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   ## Sending socket.
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   ## Receiving socket.
        self.recv_sock.bind((self.recv_address, self.recv_port))
        
        # Threads and Locks
        self._base_l        = threading.Lock()
        self._send_l        = threading.Lock()
        self._ack_pending_l = threading.Lock()

        # Flags
        self._send_complete_f    = False
        return

    ##
    # @fn       send
    # @brief    Public data send method that initiates threads used for sending data to the receiving process,
    #           and receiving ACKs from the receiving process.
    #
    # @param    data    - ByteArray object containing packet data.
    #
    # @return   None.
    def send(self, data):
        self._send_complete_f = False
        send_t      = threading.Thread(target=self._send, args=(data,)) # Sending thread.
        recv_ack_t  = threading.Thread(target=self._recv_ack)           # ACK receiving thread.

        if DEBUG:
            print(f"GBN: Starting ACK Receiving Process.")
        recv_ack_t.start()

        if DEBUG:
            print(f"GBN: Starting Sending Process.")
        send_t.start()

        send_t.join()
        recv_ack_t.join()
        return

    ##
    # @fn       recv
    # @brief    This method receives data from a receiving host and returns it to the application layer.
    #
    # @param    None.
    #
    # @return   None.
    def recv(self):
        data_buffer     = []
        total_packets   = 0xFFFF_FFFF
        
        # Loop used to monitor the remaining amount of data left to receive from a sending host.
        while self.base < total_packets:
            packet, address         = self.recv_sock.recvfrom(1024)
            header, packet_cnt, rcvd_data, cs  = self._parse_packet(packet)
            header                  = int.from_bytes(header, 'big')         # Sequence number.
            cs                      = int.from_bytes(cs, 'big')             # Packet checksum.

            # Verify the integrity of the received packet.
            if verify_checksum(packet) and ((not ((packet_corrupted(self.corruption)) and (3 in self.corruption_option))) or (1 in self.corruption_option)):
                total_packets = int.from_bytes(packet_cnt, 'big')  # Total number of packets in the transfer.

                # When the data packet's sequence number is equal to the base number, buffer the data,
                # increment the base number to request the next packet, and send the ACK for the packet.
                if header == self.base:
                    if DEBUG:
                        print(f"GBN: Buffering data {header}")
                    data_buffer.append(rcvd_data)
                    self.base += 1
                
                self._send_ack(self.base, total_packets)
            else:
                if DEBUG:
                    print(f"GBN: Checksum Invalid.")
                continue

        if DEBUG:
            print(f"GBN: Receive complete. (base = {self.base}, total_packets = {total_packets})")
        return data_buffer

    ##
    # @fn       _send
    # @brief    This method sends data to a receiving host and creates a timeout process that is used to monitor
    #           if the packet will need to be resent.
    #
    # @param    data    - ByteArray object containing packet data.
    #
    # @return   None.
    def _send(self, data):
        self.base   = 0
        self.seqnum = 0

        while True:
            # Calculate the end of the data send window based on the current base value, and the configured 
            # window size. The window end is limited to a max value based on the total amount of data that 
            # is being sent to the receiving host.
            self._base_l.acquire()
            window_end = min((self.base + self.window_size), len(data))
            self._base_l.release()

            if self._send_complete_f:
                if DEBUG:
                    print("GBN: Connection closed by remote host.")
                break
            
            # Sequence used to monitor the sending window based on the end point of the window. When the base
            # packet of the sending window has been properly ACK'd, the sequence will add a new packet to the 
            # sending window.
            while self.seqnum < window_end:
                packet = self._add_header(data[self.seqnum], self.seqnum, len(data))

                if DEBUG: 
                    print(f"GBN: Sending Packet {self.seqnum}/{len(data) - 1}")
                else:
                    print(f"GBN: Sending Packet {self.seqnum}/{len(data) - 1}", end="\r")

                # Send the packet to the receiving host.
                if packet_lost(self.loss) and (3 in self.loss_option) and (not 1 in self.loss_option):
                    pass
                else:
                    self._send_l.acquire()
                    self.send_sock.sendto(packet, (self.send_address, self.send_port))
                    self._send_l.release()

                # Start the timeout monitor for the data send. When that packet's timeout is reached, the 
                # timeout process resends the packet and restarts the timer.
                self._ack_pending_l.acquire()
                if self.seqnum >= (len(self._ack_pending_timers) - 1):
                    self._ack_pending_timers.append(threading.Timer(self.timeout, self._timeout, (self.seqnum, 0,))) 
                else:
                    self._ack_pending_timers[self.seqnum] = threading.Timer(self.timeout, self._timeout, (self.seqnum, 0,))
                try:
                    self._ack_pending_timers[self.seqnum].start()
                except:
                    pass
                self._ack_pending_l.release()

                self.seqnum += 1

            # When the base value is equal to the the length of the data packet, this indicates
            # that the entire data packet has been recieved by the remote host.
            self._base_l.acquire()
            if self.base == len(data):
                break
            self._base_l.release()


        if DEBUG:
            print(f"GBN: Data transfer complete.")
        self._send_complete_f = True
        return

    ##
    # @fn       _recv_ack
    # @brief    This method receives ACK messages from the receiving process and sets the base value used by
    #           the _send method based on the ACK messages received.
    #
    # @param    None.
    #
    # @return   None.
    def _recv_ack(self):
        self.recv_sock.settimeout(30)   # Timeout used in the event that the receiving host has stopped sending data.

        while True:
            # Passively receive ACKs sent by the receiving host, and pass the ACKs
            # to be processed and buffered.
            try:
                packet, address = self.recv_sock.recvfrom(1024)
            except:
                if self._send_complete_f:
                    return
                else:
                    continue

            header, packet_cnt, rcvd_data, cs  = self._parse_packet(packet)
            header                  = int.from_bytes(header, 'big')     # Sequence number.
            total_packets           = int.from_bytes(packet_cnt, 'big')
            rcvd_data               = int.from_bytes(rcvd_data, 'big')  # Packet data.
            cs                      = int.from_bytes(cs, 'big')         # Packet checksum.
            
            # If the checkusm is invalid for the received packet, discard the received packet
            # and wait to receive more ACKs from the receiving host.
            if (not verify_checksum(packet)) or (packet_corrupted(self.corruption) and (2 in self.corruption_option) and (not 1 in self.corruption_option)) and (header != total_packets):
                if DEBUG:
                    print(f"GBN: Checksum invalid.")
                continue
            else:
                total_data = int.from_bytes(packet_cnt, 'big') # Total number of packets in the transfer.

            # Stop the timeout process associated with the received ACK.
            self._base_l.acquire()
            while (header > self.base):
                
                self._ack_pending_l.acquire()
                if DEBUG:
                    print(f"GBN: ACK{header} received.")  
                try:
                    self._ack_pending_timers[self.base].cancel()
                except:
                    pass
                self._ack_pending_l.release()
            
                # Update the base value based on the sequence number of the received ACK.
                self.base += 1
            self._base_l.release()

            # If the send process is complete, exit the ACK reveiving process.
            if self.base >= total_data:
                break
            if self._send_complete_f:
                break
            
        return

    ##
    # @fn       _timeout
    # @brief    This method is used by the timeout monitor and is called when a timeout occurs waiting
    #           for an ACK to be received from the receiving host. The data pakcet is then resent to the 
    #           receiving host. Monitors the number of packet resends, and declares the connection closed
    #           by the remote host once a packet has been sent without being ACK'd 100 times.
    #
    # @param    seqnum  - Sequence number of the timed out packet.
    # @param    retry   - integer representing the current send retry value.
    #
    # @return   None.
    def _timeout(self, seqnum, retry):
        # Increment the retry count, and exiting on the 100th retry.
        retry_cnt = retry + 1
        if retry_cnt >= 100:
            self._send_complete_f = True
            return

        if DEBUG:
            print(f"GBN: ACK{seqnum} receive timed out. Resending window (base = {self.base}), (retry = {retry}).")

        # Stop all currently running timers to prevent previous timeouts from occuring.
        self._ack_pending_l.acquire()
        for timer in self._ack_pending_timers[self.base:]:
            try:
                timer.cancel()
            except:
                continue
        self._ack_pending_l.release()

        # Reset the sequence number to point to the start of the transmit window.
        self._base_l.acquire()
        self.seqnum = self.base
        self._base_l.release()

        return

    ##
    # @fn       _send_ack
    # @brief    This method sends an "ACK" message to a receiving process on a networked system.
    #
    # @param    None.
    #
    # @return   None.
    def _send_ack(self, state, total_packets):
        # Introduce simulated packet loss. In the event of packet loss, skip the ACK/NAK response process.
        if DEBUG:
            print(f"GBN: Sending ACK{state}/{total_packets}")
        else:
            print(f"GBN: Sending ACK{state}/{total_packets}", end="\r")

        if (packet_lost(self.loss) and (2 in self.loss_option)) and (state != total_packets):
            return

        packet = self._add_header(self.ACK.to_bytes(1, 'big'), state, total_packets)
        self.send_sock.sendto(packet, (self.send_address, self.send_port))
        return

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
    # |    Byte    | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | 
    # |           0|       State Number [31:24]    | Header
    # |           1|       State Number [23:16]    | Header
    # |           2|       State Number [15:8]     | Header
    # |           3|       State Number [7:0]      | Header
    # |           4|       Packet Count [31:24]    | Total # of Packets in Transfer
    # |           5|       Packet Count [23:16]    | Total # of Packets in Transfer
    # |           6|       Packet Count [15:8]     | Total # of Packets in Transfer
    # |           7|       Packet Count [7:0]      | Total # of Packets in Transfer
    # |           8|              Data             |
    # |         ...|              Data             |
    # |         N-2|              Data             |  
    # |         N-1|         Checksum[15:8]        | Checksum
    # |           N|         Checksum[7:0]         | Checksum
    def _add_header(self, packet, state, transfer_size):        
        header   = state.to_bytes(4, byteorder='big')                   # FSM State.
        header   = header + transfer_size.to_bytes(4, byteorder='big')  # Number of total packets in the transfer.
        cs       = checksum(header + packet)                         # Checksum calculation.

        return header + packet + cs

    ##
    # @fn       _parse_packet
    # @brief    This private method is used to parse the fields in a packet received by a receiving process.
    #
    # @param    packet  - A byte array object containing packet data.
    #
    # @return   Returns the header, data, and checksum fields of the packet.
    def _parse_packet(self, packet):
        header          = packet[0:4]                  # Extract the header bytes.
        total_packets   = packet[4:8]                  # Extract the total number of packets in the transfer.
        data            = packet[8:(len(packet) - 2)]  # Extract the packet application data.
        cs              = packet[-2:]                  # Extract the packet checksum bytes.
        return header, total_packets, data, cs