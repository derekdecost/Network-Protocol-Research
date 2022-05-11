import socket
import threading
import time
from .components.fault_injection import *
from .components.tcp_packet import *
import random

DEBUG = True

class WildCard:
    def __eq__(self, anything):
        return True

class TCP:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, mss, send_window=65535, recv_window=65535, corruption=0, loss=0, debug_option=1):
        # Public Parameters

        # Private Parameters (Input Paramters)
        self._src_ip        = src_ip
        self._src_port      = src_port
        self._dst_ip        = dst_ip
        self._dst_port      = dst_port
        self._mss           = mss
        self._corruption    = corruption
        self._loss          = loss
        self._debug_option  = debug_option

        # Private Parameters (Network Transfer Control)
        self._base                  = 0
        self._seq_no                = 0
        self._window_size           = send_window
        self._recv_window           = recv_window
        self._recv_buffer           = []
        self._client_isn            = 0
        self._server_isn            = 0
        self._ack_pending_timers    = []
        self._data                  = None

        # Private Parameters - Congestion Control
        self._cwnd            = mss     # Base size of the congestion window.
        self._cwnd_factor     = 1       # Multipler used to scale the congestion window size based on the number of received ACKs.
        self._ssthresh        = None    # Threshold value used to track the max value of cwnd, after which congestion avoidance should be used.

        # Private Parameters - Dynamic Timeout
        self._timeout       = 1
        self._estimated_rtt = 0
        self._dev_rtt       = 0

        # Sockets
        self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # Sending socket.
        self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # Receiving socket.
        self._recv_sock.bind((self._src_ip, self._src_port))

        # Threads and Locks
        self._base_l        = threading.Lock()
        self._seq_no_l      = threading.Lock()
        self._cwnd_l        = threading.Lock()
        self._recv_buffer_l = threading.Lock()
        self._recv_window_l = threading.Lock()
        self._ack_pending_l = threading.Lock()

        # Flags
        self._send_complete_f       = threading.Event()
        self._receive_complete_f    = threading.Event()
        self._slow_start_f          = threading.Event()
        self._slow_start_f.set()

        return

    ##
    # @fn       connect
    # @brief    Public method used to perform the 3-way handshake between a client and server host. For this method to
    #           operate successfully, a server process must already be running.
    #
    # @param    None.
    #
    # @return   None.
    def connect(self):
        tcp_syn_packet          = TCP_Packet(self._src_port, self._dst_port, self._client_isn, self._server_isn, self._recv_window, None, syn=1)        # Packet used to encapsulate packets sent by the client in the 3-way handshake.
        tcp_syn_ack_packet      = TCP_Packet(self._src_port, self._dst_port, self._client_isn, self._server_isn, self._recv_window, None, ack=1, syn=1) # Packet used to process the packets sent by the server in the 3-way handshake.
        self._client_isn        = random.randrange(0, 0xFFFF)   # Generate the client isn.
        tcp_syn_packet.seq_no   = self._client_isn              # Assign the server isn to the response packet sequence number.
        tcp_syn_packet.ack_no   = self._server_isn              # Increment the ACK number of the response packet.
        
        while True:
            # Send the initial SYN packet to start the syncronization between the client and server.
            if DEBUG:
                print(f"TCP: (connect) Sending SYN-ACK packet. (seq_no = {tcp_syn_packet.seq_no}, ack_no = {tcp_syn_ack_packet.ack_no})")
            if (packet_lost(self._loss)) and (self._debug_option == 4):
                pass
            else:
                self._send_sock.sendto(tcp_syn_packet.packet, (self._dst_ip, self._dst_port))

            # Wait for the server to respond with a SYN-ACK packet containing the server isn.
            try:
                self._recv_sock.settimeout(self._timeout)
                packet, _ = self._recv_sock.recvfrom(1024)
            except:
                if DEBUG:
                    print(f"TCP: (connect) Server SYN-ACK response receive timed out, resending client SYN packet.")
                continue
            else:
                tcp_syn_ack_packet.packet = packet

            # Extract the isn numbers from the packet sent by the server and exit the connection establishment process.
            if (tcp_syn_ack_packet.is_valid()) and (tcp_syn_ack_packet.mgmt_syn == 1) and (tcp_syn_ack_packet.mgmt_ack == 1):
                if DEBUG:
                    print(f"TCP: (connect) SYN-ACK packet received from client. (seq_no = {tcp_syn_ack_packet.seq_no}, ack_no = {tcp_syn_ack_packet.ack_no})")
                self._server_isn        = tcp_syn_ack_packet.seq_no
                tcp_syn_packet.seq_no   = self._client_isn              
                tcp_syn_packet.ack_no   = self._server_isn
                self._send_sock.sendto(tcp_syn_packet.packet, (self._dst_ip, self._dst_port))
                break
            else:
                continue
        return

    ##
    # @fn       close
    # @brief    Public method used to close the connection between a client and server process. This method will signal 
    #           receiving process on the server to exit and return data in it's data buffer to the upper level.
    #
    # @param    None.
    #
    # @return   None.
    def close(self):
        tcp_ack_packet = TCP_Packet(0, 0, 0, 0, 0, None)
        tcp_fin_packet = TCP_Packet(self._src_port, self._dst_port, 0, 0, self._recv_window, None, fin=1)

        tcp_fin_packet.seq_no = self._seq_no + self._client_isn
        tcp_fin_packet.ack_no = self._base   + self._server_isn

        # Send the initial FIN packet and wait for the ACK response from the server.
        while True:
            # Send the data packet, with optional debug to simulate packet loss
            if DEBUG:
                print(f"TCP: Sending FIN packet.")
            if (packet_lost(self._loss)) and (self._debug_option == 5):
                pass
            else:
                self._send_sock.sendto(tcp_fin_packet.packet, (self._dst_ip, self._dst_port))

            # Configure the timeout of the receive socket, causing the initial FIN packet to be resent when the timeout occurs.
            try:
                self._recv_sock.settimeout(self._timeout)
                packet, _ = self._recv_sock.recvfrom(1024)    #TODO: Find programmatic way to determine the number of bytes to receive from the responding host.
            except:
                continue
            else:
                tcp_ack_packet.packet = packet
        
            # Verify the integrity of the packet, discarding the packet in the event that 
            # the data is corrupted.
            if (not tcp_ack_packet.is_valid()) or (packet_corrupted(self._loss) and self._debug_option == 2):
                if DEBUG:
                    print(f"TCP: (recv_ack) Packet does not have a valid checksum.")
                continue
            
            # If the client receives an ACK packet in response
            if (tcp_ack_packet.mgmt_ack == 1) and (tcp_ack_packet.mgmt_fin == 1):
                self._base = tcp_ack_packet.ack_no - self._server_isn
                tcp_ack_packet = TCP_Packet(self._src_port, self._dst_port, self._base + self._client_isn, self._base + self._server_isn, self._recv_window, None, ack=1, fin=1)
                self._send_sock.sendto(tcp_ack_packet.packet, (self._dst_ip, self._dst_port))
                break
            
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
        send_t      = threading.Thread(target=self._send, args=(data,)) # Sending thread.
        recv_ack_t  = threading.Thread(target=self._recv_ack)           # ACK receiving thread.

        if DEBUG:
            print(f"TCP: Starting ACK Receiving Process.")
        recv_ack_t.start()

        if DEBUG:
            print(f"TCP: Starting Sending Process.")
        send_t.start()

        send_t.join()
        recv_ack_t.join()
        return

    ##
    # @fn       recv
    # @brief    Public data receive method that initiates threads used for receiving data from the sending
    #           process, and assembling data from the data buffer.
    #
    # @param    None.
    #
    # @return   None.
    def recv(self):
        process_recv_buffer_t = threading.Thread(target=self._process_recv_buffer)
        recv_data_t = threading.Thread(target=self._recv_data)
        
        process_recv_buffer_t.start()
        recv_data_t.start()

        process_recv_buffer_t.join()
        recv_data_t.join()
        return self._data

    ##
    # @fn       send
    # @brief    Public data send method that initiates threads used for sending data to the receiving process,
    #           and receiving ACKs from the receiving process.
    #
    # @param    data    - ByteArray object containing packet data.
    #
    # @return   None.
    def _send(self, data):
        wildcard        = WildCard()
        tcp_data_packet = TCP_Packet(self._src_port, self._dst_port, 0, 0, self._mss, None)

        while True:
            # Calculate the end of the transmission window based on the base value of the 
            # transfer, and the size of the receive window received from the receiving host.
            self._base_l.acquire()
            self._recv_window_l.acquire()
            window_end = min(int(self._base + (self._cwnd_factor * self._cwnd)), (self._base + self._recv_window), len(data))
            self._base_l.release()
            self._recv_window_l.release()

            self._seq_no_l.acquire()
            while self._seq_no < window_end:  
                if DEBUG:
                    print(f"TCP: Sender Status     (wend = {window_end}, seq = {self._seq_no}, base = {self._base}, cwnd = {int(self._cwnd_factor * self._cwnd)})")

                # Extract the bytes of data based on the size of the transfer window, and 
                # the current sequence number of the transfer window.
                # Insert the sequence and ACK numbers used in the transfer control along with
                # the syn numbers received in the handshaking process.
                self._base_l.acquire()
                tcp_data_packet.data   = data[self._seq_no:(self._seq_no + min(self._mss, (len(data) - self._seq_no)))] #TODO: Add receive window size to min function call.
                tcp_data_packet.seq_no = self._seq_no + self._client_isn
                tcp_data_packet.ack_no = self._base   + self._server_isn
                self._base_l.release()

                # Transfer the data and increment the sequence number based on the size 
                # of the transferred data.
                if DEBUG:
                    print(f"TCP: Sending data: {self._seq_no}/{len(data)}")

                # Send the data packet, with optional debug to simulate packet loss
                if (packet_lost(self._loss)) and (self._debug_option == 5):
                    pass
                else:
                    self._send_sock.sendto(tcp_data_packet.packet, (self._dst_ip, self._dst_port))

                self._ack_pending_l.acquire()
                if not [wildcard, self._seq_no, wildcard] in self._ack_pending_timers:
                    self._ack_pending_timers.append([threading.Timer(self._timeout, self._timeout_handle, (self._seq_no,)), self._seq_no, time.time()])
                else:
                    self._ack_pending_timers[self._ack_pending_timers.index([wildcard, self._seq_no, wildcard])] = [threading.Timer(self._timeout, self._timeout_handle, (self._seq_no,)), self._seq_no, time.time()]
                self._ack_pending_timers[self._ack_pending_timers.index([wildcard, self._seq_no, wildcard])][0].start()
                self._ack_pending_l.release()

                self._seq_no += len(tcp_data_packet.data)
            self._seq_no_l.release()

            # If the data has been completely sent to the receiving host, set the send complete flag, signalling
            # the recv_ack process to exit.
            if self._base >= len(data):
                self._send_complete_f.set()
                break
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
        self._recv_sock.settimeout(1)
        last_recvd_ack = 0
        ack_recv_cnt   = 0
        wildcard       = WildCard()
        tcp_ack_packet = TCP_Packet(0, 0, 0, 0, 0, None)

        while not self._send_complete_f.is_set():
            try:
                packet, _ = self._recv_sock.recvfrom(1024)    #TODO: Find programmatic way to determine the number of bytes to receive from the responding host.
            except:
                if self._send_complete_f.is_set():
                    self._send_complete_f.clear()
                    return
                else:
                    continue
            else:
                tcp_ack_packet.packet = packet

            # Verify the integrity of the packet, discarding the packet in the event that 
            # the data is corrupted.
            if (not tcp_ack_packet.is_valid()) or (packet_corrupted(self._loss) and self._debug_option == 2):
                if DEBUG:
                    print(f"TCP: (recv_ack) Packet does not have a valid checksum.")
                continue

            # If the packet contains a HIGH ACK bit, perform data transfer actions based on the ACK and sequence number.
            if tcp_ack_packet.mgmt_ack == 1:
                if DEBUG:
                    print(f"TCP: ACK received      (seq no. = {tcp_ack_packet.seq_no}, ack no. = {tcp_ack_packet.ack_no}, recv window = {tcp_ack_packet.rcv_window})")
                
                # Fast retransmit checker.
                if tcp_ack_packet.ack_no == last_recvd_ack:
                    ack_recv_cnt      += 1

                    # If the transmission is in the slow start phase, exponentially increase the
                    # congestion window, if the transmission is in the congestion avoidance phase,
                    # slowly increment the congestion window size.
                    if self._slow_start_f.is_set():
                        self._cwnd_l.acquire()
                        self._cwnd_factor += 1
                        self._cwnd_l.release()

                        # If the slow-start threshold has been set, and the congestion window size
                        # exceeds the slow-start threshold, enter the congestion avoidance phase.
                        if not self._ssthresh is None:
                            if (self._cwnd_factor * self._cwnd) >= self._ssthresh:
                                if DEBUG:
                                    print(f"TCP: SS-Threshold exceeded, entering congestion avoidance state.")
                                self._slow_start_f.clear()
                    else:
                        self._cwnd_l.acquire()
                        self._cwnd_factor += self._mss / (self._cwnd_factor * self._cwnd)
                        self._cwnd_l.release()

                    if DEBUG:
                        print(f"TCP: Duplicate ACK{tcp_ack_packet.ack_no} received {ack_recv_cnt} times")
                    if ack_recv_cnt >= 3:
                        if DEBUG:
                            print(f"TCP: Fast retransmit event occured.")
                        self._fast_retransmit()
                    continue
                else:
                    last_recvd_ack = tcp_ack_packet.ack_no
                    ack_recv_cnt   = 0

                # Iterate over each timeout timer, stopping timers with sequence numbers 
                # less than the ACK number of the ACK packet received, and removing them 
                # from the queue.
                self._ack_pending_l.acquire()
                # try:
                for timer in self._ack_pending_timers[(self._ack_pending_timers.index([wildcard, self._base, wildcard])):]:
                    if (tcp_ack_packet.ack_no - self._server_isn) > timer[1]:
                        timer[0].cancel()

                        # Calculate the timeout value based on the sample RTT.
                        self._estimated_rtt = (0.875 * self._estimated_rtt) + (0.125 * (time.time() - timer[2]))
                        self._dev_rtt       = (0.75 * self._dev_rtt) + (0.25 * abs((time.time() - timer[2]) - self._estimated_rtt))
                        self._timeout       = self._estimated_rtt + (4 * self._dev_rtt)
                        if DEBUG:
                            print(f"TCP: Timeout set to {self._timeout}s.")
                    else:
                        break
                # except:
                #     pass
                self._ack_pending_l.release()

                # In the event that the ACK number received is larger than the base value,
                # set the base value equal to the ACK number, incrementing the data transfer
                # window, and increase the size of the congestion window.
                self._base_l.acquire()
                self._recv_window_l.acquire()
                if (tcp_ack_packet.ack_no - self._server_isn) > self._base:
                    # If the transmission is in the slow start phase, exponentially increase the
                    # congestion window, if the transmission is in the congestion avoidance phase,
                    # slowly increment the congestion window size.
                    if self._slow_start_f.is_set():
                        self._cwnd_l.acquire()
                        self._cwnd_factor += ((tcp_ack_packet.ack_no - self._server_isn) - self._base) / self._cwnd
                        self._cwnd_l.release()

                        # If the slow-start threshold has been set, and the congestion window size
                        # exceeds the slow-start threshold, enter the congestion avoidance phase.
                        if not self._ssthresh is None:
                            if (self._cwnd_factor * self._cwnd) >= self._ssthresh:
                                if DEBUG:
                                    print(f"TCP: SS-Threshold exceeded, entering congestion avoidance state.")
                                self._slow_start_f.clear()
                    else:
                        self._cwnd_l.acquire()
                        self._cwnd_factor += self._mss / (self._cwnd_factor * self._cwnd)
                        self._cwnd_l.release()

                    self._base         = tcp_ack_packet.ack_no - self._server_isn
                self._recv_window = tcp_ack_packet.rcv_window
                self._base_l.release()
                self._recv_window_l.release()
        return

    ##
    # @fn       _recv_data
    # @brief    This method receives incoming data and adds the received data to the data buffer to 
    #           be processed by the _process_recv_buffer thread.
    #
    # @param    None.
    #
    # @return   None.
    def _recv_data(self):
        tcp_data_packet     = TCP_Packet(0, 0, 0, 0, 0, None)
        tcp_syn_ack_packet  = TCP_Packet(self._src_port, self._dst_port, self._client_isn, self._server_isn, self._recv_window, None, ack=1, syn=1)
        tcp_fin_ack_packet  = TCP_Packet(self._src_port, self._dst_port, self._client_isn, self._server_isn, self._recv_window, None, ack=1, fin=1)

        while True:
            # Received the data and create a Packet object out of the raw received 
            # data.
            try:
                packet, _ = self._recv_sock.recvfrom(10000 + tcp_data_packet.header_len)
            except:
                continue

            tcp_data_packet        = TCP_Packet(0, 0, 0, 0, 0, None)
            tcp_data_packet.packet = bytearray(packet)

            # If the receiver receives a packet containing a set FIN bit, start the closing process.
            if (tcp_data_packet.is_valid()) and (tcp_data_packet.mgmt_fin == 1):
                if DEBUG:
                    print(f"TCP: FIN packet received.")
                tcp_fin_ack_packet.ack_no     = self._base
                tcp_fin_ack_packet.seq_no     = tcp_data_packet.seq_no
                tcp_fin_ack_packet.rcv_window = self._recv_window

                # Wait for the ACK packet from the client.
                while True:
                    # Send out the packet, with optional debug to simulate ACK packet loss.
                    if (packet_lost(self._loss)) and (self._debug_option == 4):
                        pass
                    else:
                        self._send_sock.sendto(tcp_fin_ack_packet.packet, (self._dst_ip, self._dst_port))

                    try:
                        self._recv_sock.settimeout(1)
                        packet, _ = self._recv_sock.recvfrom(10000 + tcp_data_packet.header_len)
                    except:
                        if DEBUG:
                            print("TCP: FIN-ACK timeout reached, connection closed by remote host.")
                        break
                    else:
                        tcp_data_packet.packet = packet

                    if (tcp_data_packet.is_valid()) and (tcp_data_packet.mgmt_fin == 1) and (tcp_data_packet.mgmt_ack == 1):
                        if DEBUG:
                            print("TCP: FIN-ACK packet received from client, closing connection.")
                        break
                    else:
                        continue

                self._receive_complete_f.set()
                return

            if (tcp_data_packet.is_valid()) and (tcp_data_packet.mgmt_syn == 1) and (tcp_data_packet.mgmt_ack == 0):
                if DEBUG:
                    print(f"TCP: SYN packet received. (syn_seq_no = {tcp_data_packet.seq_no})")
                # Extract the client_isn number from the SYN packet sent by the client, and
                # generate the server_isn number.
                self._client_isn = tcp_data_packet.seq_no           # Extract client isn.
                self._server_isn = random.randrange(0, 0xFFFF) # Generate sever isn.
                tcp_syn_ack_packet.seq_no = self._server_isn        # Assign the server isn to the response packet sequence number.
                tcp_syn_ack_packet.ack_no = self._client_isn + 1    # Increment the ACK number of the response packet.

                # while True:
                # Send out the packet, with optional debug to simulate ACK packet loss.
                if DEBUG:
                    print(f"TCP: (recv) Sending SYN-ACK packet. (seq_no = {tcp_syn_ack_packet.seq_no}, ack_no = {tcp_syn_ack_packet.ack_no})")
                if (packet_lost(self._loss)) and (self._debug_option == 4):
                    pass
                else:
                    self._send_sock.sendto(tcp_syn_ack_packet.packet, (self._dst_ip, self._dst_port))

                # Wait for the client to respond with a SYN-ACK packet.
                try:
                    self._recv_sock.settimeout(self._timeout)
                    packet, _ = self._recv_sock.recvfrom(10000 + tcp_data_packet.header_len)
                except:
                    if DEBUG:
                        print(f"TCP: (recv) Client SYN-ACK response receive timed out, resending server SYN-ACK packet.")
                    continue
                else:
                    tcp_data_packet.packet = packet

                if (tcp_data_packet.is_valid()) and (tcp_data_packet.mgmt_syn == 0) and (tcp_data_packet.mgmt_ack == 1):
                    if DEBUG:
                        print(f"TCP: (recv) SYN-ACK packet received from client. (seq_no = {tcp_data_packet.seq_no}, ack_no = {tcp_data_packet.ack_no})")
                    self._client_isn = tcp_data_packet.seq_no
                    self._server_isn = tcp_data_packet.ack_no
                else:
                    continue
                continue
                
            # Add the unprocessed data to the data buffer to queue the received
            # data for processing.
            self._recv_buffer_l.acquire()
            self._recv_buffer.append(tcp_data_packet)

            # Decrement the recv_window size based on the size packet.
            self._recv_window_l.acquire()
            self._recv_window = max((self._recv_window - len(tcp_data_packet.packet)), 1)
            if DEBUG:
                print(f"TCP: Buffering Packet  (seq no. = {tcp_data_packet.seq_no}, ack no. = {tcp_data_packet.ack_no}, recv window = {self._recv_window})")
            self._recv_window_l.release()
            self._recv_buffer_l.release()

    ##
    # @fn       _process_recv_buffer
    # @brief    This method monitors the data buffer for new data, and processes the data based on the contents of the packet.
    #
    # @param    None.
    #
    # @return   None.
    def _process_recv_buffer(self):
        data_buffer         = bytearray()
        tcp_ack_packet      = TCP_Packet(self._src_port, self._dst_port, self._client_isn, self._server_isn, self._mss, None, ack=1)
        tcp_fin_ack_packet  = TCP_Packet(self._src_port, self._dst_port, self._client_isn, self._server_isn, self._mss, None, ack=1, fin=1)

        while not self._receive_complete_f.is_set():
            self._recv_buffer_l.acquire()
            if len(self._recv_buffer) > 0:
                # Remove the queued packet from the buffer.
                tcp_data_packet = self._recv_buffer.pop(0)

                # Increment the receive window size based on the length of the received
                # packet.
                self._recv_window_l.acquire()
                self._recv_window             = min((self._recv_window + len(tcp_data_packet.packet)), 0xFFFF)
                tcp_ack_packet.rcv_window     = self._recv_window
                tcp_fin_ack_packet.rcv_window = self._recv_window
                self._recv_window_l.release()
            else:
                self._recv_buffer_l.release()
                continue
            self._recv_buffer_l.release()

            # If the packet taken from the queue is invalid, discard it,
            # and continue to the next packet in the queue.
            if (not tcp_data_packet.is_valid()) or ((packet_corrupted(self._loss) and self._debug_option == 3)):
                if DEBUG:
                    print(f"TCP: Packet checksum is invalid.")
                continue
            else:
                if DEBUG:
                    print(f"TCP: Processing packet (seq no. = {tcp_data_packet.seq_no}, ack no. = {tcp_data_packet.ack_no})")

            # If the received packet has a sequence number that matches the 
            # base value in the receive process, extract the packet data and
            # add it to the buffer that will be passed to the application layer.
            if (tcp_data_packet.seq_no - self._client_isn) == self._base:
                if not tcp_data_packet.data is None:
                    # Add the packet data to the buffer that will be passed
                    # to the application layer.
                    data_buffer += tcp_data_packet.data

                    # Increase the base value based on the number of bytes 
                    # in the received data.
                    self._base            += len(tcp_data_packet.data)
                    tcp_ack_packet.ack_no  = (self._base + self._server_isn)
                    tcp_ack_packet.seq_no  = tcp_data_packet.seq_no
                else:
                    self._base += 1  
            
            if DEBUG:
                print(f"TCP: Sending ACK       (seq no. = {tcp_ack_packet.seq_no}, ack no. = {tcp_ack_packet.ack_no}, recv window = {self._recv_window})")
            
            # Send out the packet, with optional debug to simulate ACK packet loss.
            if (packet_lost(self._loss)) and (self._debug_option == 4):
                pass
            else:
                self._send_sock.sendto(tcp_ack_packet.packet, (self._dst_ip, self._dst_port))

        self._data = data_buffer
        return

    ##
    # @fn       _timeout_handle
    # @brief    This method is used by the timeout monitor and is called when a timeout occurs waiting
    #           for an ACK to be received from the receiving host. The data pakcet is then resent to the 
    #           receiving host.
    #
    # @param    seq_no  - Sequence number of the timed out packet.
    #
    # @return   None.
    def _timeout_handle(self, seq_no):
        wildcard = WildCard()

        # Stop all currently running timers to prevent previous timeouts from occuring.
        self._ack_pending_l.acquire()
        try:
            for timer in self._ack_pending_timers[(self._ack_pending_timers.index([wildcard, self._base, wildcard])):]:
                try:
                    timer[0].cancel()
                except:
                    continue
        except:
            pass
        self._ack_pending_l.release()

        self._ssthresh = (self._cwnd_factor * self._cwnd) / 2    # Assign the ssthresh value.

        self._cwnd_l.acquire()
        self._cwnd_factor = 1                                       # Reset the congestion window to 1 MSS.
        self._cwnd_l.release()
        
        self._seq_no_l.acquire()
        self._seq_no = self._base                              # Reset the sequence number to be equal to the base value.
        self._seq_no_l.release()

        self._slow_start_f.set()
        
        return

    ##
    # @fn       _fast_retransmit
    # @brief    This method controls the fast retransmit operation by setting the congestion window
    #           value and resetting the sequence number to be equal to the base value.
    #
    # @param    None.
    #
    # @return   None.
    def _fast_retransmit(self):   
        self._cwnd_l.acquire()
        self._cwnd_factor = self._cwnd_factor / 2   # Reduce the size of the transmission window by half.
        self._cwnd_l.release()

        self._seq_no_l.acquire()
        self._seq_no = self._base                   # Reset the sequence number to be equal to the base value.
        self._seq_no_l.release()
        return
    
