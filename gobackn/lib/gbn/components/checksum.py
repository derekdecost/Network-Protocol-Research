#!/usr/bin/env python3

##
# @fn       checksum
#
# @brief    This function calculates the checksum value of a packet that is used to validate 
#           the integrity of the data within the packet.
#
# @param    packet  - Data packet formatted as bytes.
#
# @return   Returns a checksum value as a bytes object.
def checksum(packet):
    sum_    = 0
    cs_size = 16

    # Divide a packet into 2 bytes (16 bits) and calculate the sum of a packet
    for i in range(0, len(packet), 2):
        sum_ += int.from_bytes(packet[i:i + 2], 'big')

    sum_ = bin(sum_)[2:]  # Change to binary

    # Add the overflow bits
    while len(sum_) != cs_size:
        if len(sum_) > cs_size:
            x = len(sum_) - cs_size
            sum_ = bin(int(sum_[0:x], 2) + int(sum_[x:], 2))[2:]
        if len(sum_) < cs_size:
            sum_ = '0' * (cs_size - len(sum_)) + sum_

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

##
# @fn       verify_checksum
#
# @brief    This function is used to extract the packet checksum and verify the data integrity 
#           of the data packet.
#
# @param    packet  - Data packet formatted as bytes that contains a header and checksum.
#
# @ return  Returns a True value if the checksum value is correct.
#           Returns a False value if the checksum value is incorrect.
def verify_checksum(packet):
    # cs = checksum(packet)
    # print(f"verify_checksum {cs}")
    # # Check if the two checksum values match and return a status.
    # if cs == int(0).to_bytes(2, 'big'):
    #     return True
    # else:
    #     return False
    packet_data = packet[:-2]                   # Extract the data and header without the checksum.
    packet_cs   = packet[-2:]                   # Extract the original checksum.
    cs          = checksum(packet_data)   # Recalculate the checksum to check against the original checksum.

    # Check if the two checksum values match and return a status.
    if packet_cs == cs:
        return True
    else:
        return False

if __name__ == "__main__":
    '\x00\x00\x00\t\x00\x03\xb0\x00\x00O\xf3'
    packet = int(0x12345678).to_bytes(4, 'big')
    cs = checksum(packet)
    print(cs)
    verify = checksum(packet + cs)
    print(verify)