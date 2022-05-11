import os
from lib.packets import *
from lib.rdt.rdt3_0 import *

if __name__ == "__main__":
    rdtclient = RDT3_0("127.0.0.1", 50020, "127.0.0.1", 50000, 1024, corruption=0, corruption_option=[1], loss=0, loss_option=[1], timeout=0.05)

    # Run this version if the operating system is Windows based.
    if os.name == "nt":
        packets = Packets.file2packets("client_data\\test.bmp", 1024)
    # Run this version in all other cases. Should cover all TA operating systems.
    else:
        packets = Packets.file2packets("client_data/test.bmp", 1024)

    print("Sending data...")
    rdtclient.send(packets)
    print("Sending complete.")
    
    
