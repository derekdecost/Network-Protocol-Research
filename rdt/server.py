#!/usr/bin/env python3
from datetime import datetime
from lib.packets import *
from lib.rdt.rdt3_0 import *

if __name__ == "__main__":
    bmp         = None
    time_trials = []
    total_time  = 0
    path_name   = "server_data"
    rdtserver   = RDT3_0("127.0.0.1", 50000, "127.0.0.1", 50020, corruption=0, corruption_option=[1], loss=0, loss_option=[1])
    
    print("Receiving data...")
    start = datetime.now()
    while bmp is None:
        bmp = rdtserver.recv()
        Packets.packets2file(path_name, bmp)
    bmp = None
    end = datetime.now()
    time_trials.append(end - start)
    print("\nReceiving complete.")

    print(f"\nTrial Time: {time_trials[0]}")
    