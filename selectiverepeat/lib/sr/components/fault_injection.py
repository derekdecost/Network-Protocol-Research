#!/usr/bin/env python3
from random import randrange

##
# @fn       _corrupted
#
# @brief    This private method is used for debugging the RDT3.0 implementation by introducing 
#           "packet corruption" to the ACK/NAK and packet receiving steps.
#
# @param    None.
#
# @return   None.
#
# @note     The probability of a packet being corrupted is determined when the RDT3.0 class is 
#           declared using the "corruption" optional parameter.
def packet_corrupted(percentage):
    if percentage >= randrange(1, 101):
        return True
    else:
        return False

##
# @fn       _packet_lost
#
# @brief    This private method is used for debugging the RDT3.0 implementation by introducing 
#           "packet loss" to the ACK/NAK and packet receiving steps.
#
# @param    None.
#
# @return   None.
#
# @note     The probability of a packet being corrupted is determined when the RDT3.0 class is 
#           declared using the "loss" optional parameter.
def packet_lost(percentage):
    if percentage >= randrange(1, 101):
        return True
    else:
        return False