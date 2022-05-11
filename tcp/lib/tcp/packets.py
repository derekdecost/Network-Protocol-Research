#!/usr/bin/env python3
import os

##
# @class    Packets
# @brief    This class contains data and methods related to packet operations.
#
# @param    None.
#
# @return   None.
class Packets:
    ##
    # @fn       file2packets
    # @brief    This method opens a specified file in the binary format and creates a list
    #           of byte objects with a packet size specified by the user.
    # 
    # @param    file        - File that will be turned into a list of binary-format byte objects.
    # @param    packet_size - Indicates the number of bytes in each packet in the packet list 
    #                         returned by the function. For example a packet_size value of 1024 
    #                         will generate a list of packets, with each packet containing 1024 
    #                         bytes of data.
    # 
    # @return   Stores a list of packets in the Packets.data member, with each packet containing a 
    #           number of bytes specified by the packet_size parameter. 
    def file2packets(file, packet_size):
        packets = []

        # Open the file as binary data.
        with open(file, "rb") as data:
            # Read data in packet_size sized packets and create
            # a list of packets until there is no data left to be
            # read from the source file.
            packet = data.read(packet_size)
            while packet:
                packets.append(packet)          # List type
                packet = data.read(packet_size) # Byte type
            
        return packets
 
    ##
    # @fn       packets2file
    # @brief    This method creates a file using a list of binary-formatted packets.
    #
    # @param    path        - Path to the location that the file will be created in.
    # @param    packets     - List of binary-formatted data that will form the contents of the file.
    #
    # @return   None.
    def packets2file(path, packets):
        # Run this version if the operating system is Windows based.
        bmp = bytes(packets)
        if os.name == "nt":
            with open(f"{path}", "wb") as data:
                # Iterate over each packet in the list of packets 
                # and construct a file from its contents.
                for packet in bmp:
                    data.write(packet.to_bytes(1, 'big'))

        # Run this version in all other cases. Should cover all TA operating systems.
        else:
            with open(f"{path}", "wb") as data:
                # Iterate over each packet in the list of packets 
                # and construct a file from its contents.
                for packet in bmp:
                    data.write(packet.to_bytes(1, 'big'))

        return
