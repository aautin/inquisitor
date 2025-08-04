import os
import ftplib
import time

def connect_to_ftp():
    server_ip = os.getenv('SERVER_IP')
    server_port = int(os.getenv('SERVER_PORT', 21))

    print(f"[CLIENT] Attempting to connect to FTP server at {server_ip}:{server_port}", flush=True)

    try:
        # Connect to FTP server
        ftp = ftplib.FTP()
        ftp.connect(server_ip, server_port)
        ftp.login()

        print(f"[CLIENT] Connected to FTP server, current directory: {ftp.pwd()}", flush=True)

        files = ftp.nlst()
        print(f"[CLIENT] Files available: {files}", flush=True)

        ftp.quit()
        print(f"[CLIENT] Disconnected.\n", flush=True)
        
    except Exception as e:
        print(f"[CLIENT] Error connecting to FTP server: {e}", flush=True)

if __name__ == "__main__":
    while True:
        connect_to_ftp()
        time.sleep(5)
