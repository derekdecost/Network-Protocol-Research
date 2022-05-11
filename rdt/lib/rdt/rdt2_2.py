#!/usr/bin/env python3
from random import randrange
import socket

##
# @class    RDT2_2
# @brief    This class implements the RDT 2.2 process to send and receive data to 
#           and from a process on a networked system.
#
# @param    send_address    - Address used by the sending socket.
# @param    send_port       - Port used by the sending socket.
# @param    recv_address    - Address used by the receiving socket.
# @param    recv_port       - Port used by the receiving socket.
# @param    packet_size     - Number of bytes in each packet that will be sent and received.
#
# @return   None.
class RDT2_2:
    ACK  = 0x00
    NAK  = 0xFF

    ##
    # @fn       __init__
    # @brief    Constructor for the RDT2_2 class.
    def __init__(self, send_address, send_port, recv_address, recv_port, packet_size=1024, corruption=0, option=[1, 2, 3]):
        self._state       = 0               ## State used for packet retransmission, can be 0 or 1.
        self._prev_state  = 1               ## Previous state of the FSM used for packet retransmission, can be 0 or 1.
        self._header_size = 3               ## Number of bytes contained in the packet header.

        self.send_address = send_address    ## Address of the sending socket.
        self.recv_address = recv_address    ## Address of the receiving socket.
        self.send_port    = send_port       ## Port used for sending data.
        self.recv_port    = recv_port       ## Port used for receiving data.
        self.packet_size  = packet_size     ## Number of bytes in each packet.
        self.corruption   = corruption      ## Packet corruption percentage used for debug.
        self.option       = option          ## List of selected debug options. 1=No Packet Loss, 2=ACK Packet Loss, 3=Data Packet Loss.

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   ## Sending socket.
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   ## Receiving socket.
        self.recv_sock.bind((self.recv_address, self.recv_port))
        return

    ##
    # @fn       send
    # @brief    This method sends the number of packets to receive, and the packets of
    #           of data to a receiving process.
    #
    # @param    packets     - A list object of binary-formatted data that will be sent
    #                         to a receveiving process.
    #
    # @return   None.
    def send(self, packets):
        packet_idx = 0

        # Gets the number of packets to send based on the length of the packet list
        # and sends that value to the receiving side.
        while True: 
            print(f"RDT2.2: Sending packet count = {len(packets)}")
            self.send_sock.sendto(self._add_header(len(packets).to_bytes(1024, 'big'), self._state), (self.send_address, self.send_port))

            # Waits to receive and ACK from the receiving end of the data transfer.
            # If a NAK is received, the packet count will be retransmitted.
            ack, state = self._recv_ack()
            if ack:
                if state != self._state:
                    print("RDT2.2: FSM State Did Not Match.")
                    continue

                self._change_state()
                break        
        
        # Iterate over the packet list and send each packet to the receiving end.
        while packet_idx < len(packets):
            print(f"RDT2.2: Sending packet {packet_idx}/{len(packets) - 1} to receiving process")
            self.send_sock.sendto(self._add_header(packets[packet_idx], self._state), (self.send_address, self.send_port))

            # For the purpose of data collection, the final ACK of transaction will
            # not be corrupted, preventing the client from being locked into a loop
            # due to there being no timeouts implemented in RDT2.2.
            #TODO: Remove when timeouts are added in phase 4.
            if packet_idx == (len(packets) - 1):
                self.corruption = 0

            # Waits to receive and ACK from the receiving end of the data transfer.
            # If a NAK is received, the packet count will not be increased, and the 
            # current packet will be retransmitted.
            ack, state = self._recv_ack()
            if ack:
                if state != self._state:
                    print("RDT2.2: FSM State Did Not Match.")
                    continue

                self._change_state()
                packet_idx += 1
        
        self._reset()
    
    ##
    # @fn       recv
    # @brief    This method receives the number of packets to receive from a sending process
    #           and receives each data packet from a sending process.
    #
    # @param    None.
    #
    # @return   Returns a list object of binary formatted data. Each element of the list 
    #           contains packet_size number of bytes.
    def recv(self):
        packet_data = []
        packet_idx = 0
        
        # Receive the number of bytes of data to receive.
        while True:
            print("RDT2.2: Receiving packet count from sending process")

            packet, address        = self.recv_sock.recvfrom(1024 + self._header_size)
            header, data, checksum = self._parse_packet(packet)
            data                   = int.from_bytes(data, 'big')
            checksum               = int.from_bytes(checksum, 'big')

            # Validate the checksum of the packet.
            if ((not ((self._corrupted()) and (3 in self.option))) or (1 in self.option)) and self._verify_checksum(packet): 
                # Check if the state of the sending process matches the state of the sending process.
                # In the event that the FSM states of the sending and receiving processes do not match,
                # send an ACK with the current FSM state of the receiving process and skip the state 
                # changing and packet data collection process.
                if (header == self._state): 
                    # Get the number of bytes to receive from the sending process.
                    packet_cnt = data
                    print(f"RDT2.2: Packets to receive from sending process = {packet_cnt} packets")
                    self._send_ack(self._state)
                    self._change_state()
                    break
                else:
                    #NOTE: This state should NEVER occur for the initial send.
                    print("RDT2.2: Packet with Mismatched State Received.")
                    self._send_ack(self._prev_state)
            else:
                print("RDT2.2: Corrupted Packet Received.")
                self._send_ack(self._prev_state)            

        # Receive the number of packets indicated by the sending process.
        while packet_idx < packet_cnt:
            print(f"RDT2.2: Receiving packet {packet_idx}/{packet_cnt - 1} from sending process")

            packet, address        = self.recv_sock.recvfrom(self.packet_size + self._header_size)
            header, data, checksum = self._parse_packet(packet)
            checksum               = int.from_bytes(checksum, 'big')

            # Validate the checksum of the packet.
            if ((not ((self._corrupted()) and (3 in self.option))) or (1 in self.option)) and self._verify_checksum(packet):
                # Check if the state of the sending process matches the state of the sending process.
                # In the event that the FSM states of the sending and receiving processes do not match,
                # send an ACK with the current FSM state of the receiving process and skip the state 
                # changing and packet data collection process.
                if (header == self._state):
                    # Add the received packet to the packet list.
                    print(f"RDT2.2: Packet {packet_idx} Received.")
                    packet_data.append(data)
                    packet_idx += 1
                    self._send_ack(self._state)
                    self._change_state()
                else:
                    print("RDT2.2: Packet with Mismatched State Received.")
                    self._send_ack(self._prev_state)
            else:
                print("RDT2.2: Corrupted Packet Received.")
                self._send_ack(self._prev_state)  

        self._reset()
        return packet_data

    ##
    # @fn       _send_ack
    # @brief    This method sends an "ACK" message to a receiving process on a networked system.
    #
    # @param    None.
    #
    # @return   None.
    def _send_ack(self, state):
        print(f"RDT2.2: Sending ACK{state}")
        packet = self._add_header(self.ACK.to_bytes(1, 'big'), state)
        self.send_sock.sendto(packet, (self.send_address, self.send_port))
        return

    ##
    # @fn       _send_nack
    # @brief    This method sends an "NAK" message to a receiving process on a networked system.
    #
    # @param    None.
    #
    # @return   None.
    def _send_nak(self, state):
        print(f"RDT2.2: Sending NAK{state}")
        packet = self._add_header(self.NAK.to_bytes(1, 'big'), state)
        self.send_sock.sendto(packet, (self.send_address, self.send_port))
        return

    ##
    # @fn       _recv_ack
    # @brief    This method waits to receive an "ACK" or "NACK" message from a sending process 
    #           on a networked system.
    #
    # @param    None.
    #
    # @return   Returns a value of True in the event of receiving and "ACK" message, or returns a
    #           value of False in the event of receiving a "NACK" message. 
    def _recv_ack(self):
        msg = None

        # Receive the response message from a responding process.
        while msg is None:
            msg, address = self.recv_sock.recvfrom(1024)

        # Extract the data from the ACK/NACK packet.
        header, data, checksum = self._parse_packet(msg)

        # Validate the checksum of the packet.
        if ((not ((self._corrupted()) and (2 in self.option))) or (1 in self.option)) and self._verify_checksum(msg):
            # Check the state and ACK/NAK status of received response packet.
            if (header == self._state) and (int.from_bytes(data, 'big') == self.ACK): 
                print("RDT2.2: ACK Received")
                return True, header
            elif (header != self._state) and (int.from_bytes(data, 'big') == self.ACK):
                print("RDT2.2: ACK with Unmatched State Received.")
                return True, header
            else:
                print("RDT2.2: Non-ACK Response Packet Received.")
                return False, header
        else:
            print("RDT2.2: Corrupted Packet Received.")
            return False, header

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
    # |           0|       State Number (0, 1)     | Header
    # |           1|              Data             |
    # |         ...|              Data             |
    # |         N-2|              Data             |  
    # |         N-1|         Checksum[15:8]        | Checksum
    # |           N|         Checksum[7:0]         | Checksum
    def _add_header(self, packet, state):        
        header   = state.to_bytes(1, byteorder='big') # FSM State.
        checksum = self._checksum(header + packet)          # Checksum calculation.

        return header + packet + checksum

    ##
    # @fn       _parse_packet
    # @brief    This private method is used to parse the fields in a packet received by a receiving process.
    #
    # @param    packet  - A byte array object containing packet data.
    #
    # @return   Returns the header, data, and checksum fields of the packet.
    def _parse_packet(self, packet):
        header   = packet[0]                    # Extract the header bytes.
        data     = packet[1:(len(packet) - 2)]  # Extract the packet application data.
        checksum = packet[-2:]                  # Extract the packet checksum bytes.
        return header, data, checksum
    
    ##
    # @fn       _change_state
    #
    # @brief    This private method is used to toggle the state of the RDT2.2 process between
    #           state 0 and state 1.
    #
    # @param    None.
    #
    # @return   None.
    def _change_state(self):
        self._prev_state = self._state
        self._state      = self._state ^ 1
        return

    ##
    # @fn       _corrupted
    #
    # @brief    This private method is used for debugging the RDT2.2 implementation by introducing 
    #           "packet corruption" to the ACK/NAK and packet receiving steps.
    #
    # @param    None.
    #
    # @return   None.
    #
    # @note     The probability of a packet being corrupted is determined when the RDT2.2 class is 
    #           declared using the "corruption" optional parameter.
    def _corrupted(self):
        if self.corruption >= randrange(1, 101):
            return True
        else:
            return False

    ##
    # @fn       _reset
    #
    # @brief    This private method is used for resetting the RDT2.2 FSM to it's inital state to
    #           avoid a receiving and sending process starting in different states in the RDT2.2 FSM.
    #
    # @param    None.
    #
    # @return   None.
    def _reset(self):
        print("RDT2.2: Process State Reset.")
        self._state = 0

    ##
    # @fn       _checksum
    #
    # @brief    This private method calculates the checksum value of a packet that is used to validate 
    #           the integrity of the data within the packet.
    #
    # @param    packet  - Data packet formatted as bytes.
    #
    # @return   Returns a checksum value as a bytes object.
    def _checksum(self, packet):
        sum_ = 0
        k = 16

        # Divide a packet into 2 bytes (16 bits) and calculate the sum of a packet
        for i in range(0, len(packet), 2):
            sum_ += int.from_bytes(packet[i:i + 2], 'big')
    
        sum_ = bin(sum_)[2:]  # Change to binary
    
        # Add the overflow bits
        while len(sum_) != k:
            if len(sum_) > k:
                x = len(sum_) - k
                sum_ = bin(int(sum_[0:x], 2) + int(sum_[x:], 2))[2:]
            if len(sum_) < k:
                sum_ = '0' * (k - len(sum_)) + sum_
    
        # Calculate the complement of sum_
        checksum = ''
        for i in sum_:
            if i == '1':
                checksum += '0'
            else:
                checksum += '1'
    
        # Convert 8 bits into 1 byte
        checksum = bytes(int(checksum[i: i + 8], 2) for i in range(0, len(checksum), 8))
        return checksum

    def _verify_checksum(self, packet):
        packet_data = packet[:-2]                   # Extract the data and header without the checksum.
        packet_cs   = packet[-2:]                   # Extract the original checksum.
        checksum    = self._checksum(packet_data)   # Recalculate the checksum to check against the original checksum.

        # Check if the two checksum values match and return a status.
        if packet_cs == checksum:
            return True
        else:
            return False



        

