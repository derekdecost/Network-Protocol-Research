import os
import threading
from lib.tcp.packets import *
from lib.tcp.tcp import TCP

def main(option, error):
    # Run this version if the operating system is Windows based.
    if os.name == "nt":
        data = Packets.file2packets("client_data\\test.bmp", 1)
    # Run this version in all other cases. Should cover all TA operating systems.
    else:
        data = Packets.file2packets("client_data/test.bmp", 1)
    print("Sending data...")
    data        = bytearray(b''.join(data))
    
    if option == 1:
        tcp_client  = TCP("127.0.0.1", 55000, "127.0.0.1", 54000, 5000, loss=error, debug_option=1)
    elif option == 2:
        tcp_client  = TCP("127.0.0.1", 55000, "127.0.0.1", 54000, 5000, loss=error, debug_option=2)
    elif option == 3:
        tcp_client  = TCP("127.0.0.1", 55000, "127.0.0.1", 54000, 5000, loss=error, debug_option=3)
    elif option == 4:
        tcp_client  = TCP("127.0.0.1", 55000, "127.0.0.1", 54000, 5000, loss=error, debug_option=4)
    elif option == 5:
        tcp_client  = TCP("127.0.0.1", 55000, "127.0.0.1", 54000, 5000, loss=error, debug_option=5)

    tcp_client.connect()
    tcp_client.send(data)
    tcp_client.close()
    print("Sending process complete.")

if __name__ == "__main__":
    option = 5
    error  = 50
    main(option, error)
