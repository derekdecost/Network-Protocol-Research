import threading
import sr_client
import sr_server

if __name__ == "__main__":
    option  = 5     # Debug option outlined in homework document.
    timeout = 0.5   # Timeout duration.
    error   = 50    # Percentage of encountering an error, covers loss and corruption.
    window  = 10    # Transfer window size.

    server_t = threading.Thread(target=sr_server.main, args=(option, error, timeout, window,))
    client_t = threading.Thread(target=sr_client.main, args=(option, error, timeout, window,))

    server_t.start()
    client_t.start()

    server_t.join()
    client_t.join()