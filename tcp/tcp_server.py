import os
from datetime import datetime
from lib.tcp.packets import *
from lib.tcp.tcp import TCP

def main(option, error):
    if option == 1:
        tcp_server  = TCP("127.0.0.1", 54000, "127.0.0.1", 55000, 5000, loss=error, debug_option=1)
    elif option == 2:
        tcp_server  = TCP("127.0.0.1", 54000, "127.0.0.1", 55000, 5000, loss=error, debug_option=2)
    elif option == 3:
        tcp_server  = TCP("127.0.0.1", 54000, "127.0.0.1", 55000, 5000, loss=error, debug_option=3)
    elif option == 4:
        tcp_server  = TCP("127.0.0.1", 54000, "127.0.0.1", 55000, 5000, loss=error, debug_option=4)
    elif option == 5:
        tcp_server  = TCP("127.0.0.1", 54000, "127.0.0.1", 55000, 5000, loss=error, debug_option=5)

    print("Receiving data...")
    start = datetime.now()
    data = tcp_server.recv()

    if os.name == "nt":
        Packets.packets2file("server_data\\test.bmp", data)
    else:
        Packets.packets2file("server_data/test.bmp", data)

    end = datetime.now()
    time_trials = (end - start)
    print("Receiving process complete.")
    print("\nTrial Time")
    print(f"{time_trials}")

if __name__ == "__main__":
    option = 5
    error  = 50
    main(option, error)

