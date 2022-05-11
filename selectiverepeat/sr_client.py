import os
from lib.packets import *
from lib.sr.selectiverepeat import SelectiveRepeat

def main(option, error, timeout, window):
    if option == 1:
        rdtclient = SelectiveRepeat("127.0.0.1", 50040, "127.0.0.1", 50060, window, timeout=timeout, corruption=error, corruption_option=[1], loss=error, loss_option=[1])
    elif option == 2:
        rdtclient = SelectiveRepeat("127.0.0.1", 50040, "127.0.0.1", 50060, window, timeout=timeout, corruption=error, corruption_option=[2], loss=error, loss_option=[1])
    elif option == 3:
        rdtclient = SelectiveRepeat("127.0.0.1", 50040, "127.0.0.1", 50060, window, timeout=timeout, corruption=error, corruption_option=[3], loss=error, loss_option=[1])
    elif option == 4:
        rdtclient = SelectiveRepeat("127.0.0.1", 50040, "127.0.0.1", 50060, window, timeout=timeout, corruption=error, corruption_option=[1], loss=error, loss_option=[2])
    elif option == 5:
        rdtclient = SelectiveRepeat("127.0.0.1", 50040, "127.0.0.1", 50060, window, timeout=timeout, corruption=error, corruption_option=[1], loss=error, loss_option=[3])
    # rdtclient = SelectiveRepeat("127.0.0.1", 50040, "127.0.0.1", 50060, 10, timeout=0.05, corruption=20, corruption_option=[1, 2, 3], loss=20, loss_option=[1, 2, 3])
    # Run this version if the operating system is Windows based.
    if os.name == "nt":
        packets = Packets.file2packets("client_data\\test.bmp", 1000)
    # Run this version in all other cases. Should cover all TA operating systems.
    else:
        packets = Packets.file2packets("client_data/test.bmp", 1000)

    print("Sending data...")
    rdtclient.send(packets)
    print("\nSending complete.")
    
    