import os
import ftplib
import time

import ftplib
import time
import subprocess

def connect_to_ftp():
    while True:
        try:
            # Create FTP connection
            ftp = ftplib.FTP()
            ftp.connect('172.20.0.4', 21, timeout=10)
            ftp.login()  # Anonymous login
            
            print(f"[CLIENT] ✓ FTP connection successful to {ftp.getwelcome()}")
            
            # List directory (generates more IP traffic)
            files = ftp.nlst()
            print(f"[CLIENT] Directory listing: {files}")
            
            ftp.quit()
            print(f"[CLIENT] FTP connection closed")
            
        except Exception as e:
            print(f"[CLIENT] FTP connection failed: {e}")
        
        time.sleep(8)  # Try every 8 seconds

if __name__ == "__main__":
    while True:
        connect_to_ftp()
        time.sleep(5)
