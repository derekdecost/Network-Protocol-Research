#!/usr/bin/env python3
import socket

##
# @class    RDT1_0
# @brief    This class implements the RDT 1.0 process to send and receive data to 
#           and from a process on a networked system.
#
# @param    send_address    - Address used by the sending socket.
# @param    send_port       - Port used by the sending socket.
# @param    recv_address    - Address used by the receiving socket.
# @param    recv_port       - Port used by the receiving socket.
# @param    packet_size     - Number of bytes in each packet that will be sent and received.
#
# @return   None.
class RDT1_0:
    ##
    # @fn       __init__
    # @brief    Constructor for the RDT1_0 class.
    def __init__(self, send_address, send_port, recv_address, recv_port, packet_size=1024):
        self.send_address = send_address    ## Address of the sending socket.
        self.recv_address = recv_address    ## Address of the receiving socket.
        self.send_port    = send_port       ## Port used for sending data.
        self.recv_port    = recv_port       ## Port used for receiving data.
        self.packet_size  = packet_size     ## Number of bytes in each packet.

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
            self.send_sock.sendto(f"{len(packets)}".encode(), (self.send_address, self.send_port))

            # Waits to receive and ACK from the receiving end of the data transfer.
            # If a NACK is received, the packet count will be retransmitted.
            if self._recv_ack():
                break        
        
        # Iterate over the packet list and send each packet to the receiving end.
        while packet_idx < len(packets):
            self.send_sock.sendto(packets[packet_idx], (self.send_address, self.send_port))

            # Waits to receive and ACK from the receiving end of the data transfer.
            # If a NACK is received, the packet count will not be increased, and the 
            # current packet will be retransmitted.
            if self._recv_ack():
                packet_idx += 1
    
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
            data, address = self.recv_sock.recvfrom(1024)
            packet_cnt = int(data.decode())

            #TODO: find scenario in which to send a NACK.
            self._send_ack()
            break

        # Receive the number of packets indicated by the sending process.
        while packet_idx < packet_cnt:
            data, address = self.recv_sock.recvfrom(self.packet_size)

            #TODO: find scenario in which to send a NACK.
            self._send_ack()

            # Add the received packet to the packet list.
            packet_data.append(data)
            packet_idx += 1

        return packet_data
    
    ##
    # @fn       _send_ack
    # @brief    This method sends an "ACK" message to a receiving process on a networked system.
    #
    # @param    None.
    #
    # @return   None.
    def _send_ack(self):
        packet = "ACK".encode()
        self.send_sock.sendto(packet, (self.send_address, self.send_port))
        return

    ##
    # @fn       _send_nack
    # @brief    This method sends an "NACK" message to a receiving process on a networked system.
    #
    # @param    None.
    #
    # @return   None.
    def _send_nack(self):
        packet = "NACK".encode()
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
        #TODO: Create a scheme for using timeouts.
        msg = None

        # Receive the response message from a responding process.
        while msg is None:
            data, address = self.recv_sock.recvfrom(1024)
            msg = data.decode()

        if msg == "ACK":
            return True
        elif msg == "NACK":
            return False
        #TODO: Create a scheme for when a responding system sends a message that isn't "ACK" or "NACK"
        #      such as a corrupt message.
        return True

    

