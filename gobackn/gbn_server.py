#!/usr/bin/env python3
from datetime import datetime
from lib.packets import *
from lib.gbn.gobackn import GoBackN

def main(option, error, timeout, window):
    bmp         = None
    total_time  = 0
    path_name   = "server_data"

    if option == 1:
        rdtserver   = GoBackN("127.0.0.1", 50060, "127.0.0.1", 50040, window, timeout=timeout, corruption=error, corruption_option=[1], loss=error, loss_option=[1])
    if option == 2:
        rdtserver   = GoBackN("127.0.0.1", 50060, "127.0.0.1", 50040, window, timeout=timeout, corruption=error, corruption_option=[2], loss=error, loss_option=[1])
    if option == 3:
        rdtserver   = GoBackN("127.0.0.1", 50060, "127.0.0.1", 50040, window, timeout=timeout, corruption=error, corruption_option=[3], loss=error, loss_option=[1])
    if option == 4:
        rdtserver   = GoBackN("127.0.0.1", 50060, "127.0.0.1", 50040, window, timeout=timeout, corruption=error, corruption_option=[1], loss=error, loss_option=[2])
    if option == 5:
        rdtserver   = GoBackN("127.0.0.1", 50060, "127.0.0.1", 50040, window, timeout=timeout, corruption=error, corruption_option=[1], loss=error, loss_option=[3])
    # rdtserver   = GoBackN("127.0.0.1", 50060, "127.0.0.1", 50040, 100, timeout=0.075, corruption=20, corruption_option=[1, 2, 3], loss=20, loss_option=[1, 2, 3])
    print("Receiving data...")
    start = datetime.now()
    while bmp is None:
        bmp = rdtserver.recv()
        Packets.packets2file(path_name, bmp)
    bmp = None
    end = datetime.now()
    time_trials = (end - start)
    print("Receiving complete.")
    print("\nTrial Time")
    print(f"{time_trials}")
    