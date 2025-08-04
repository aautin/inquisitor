from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import os

class CustomFTPHandler(FTPHandler):
    def on_connect(self):
        print(f"Client connected: {self.remote_ip}:{self.remote_port}")

    def on_disconnect(self):
        print(f"Client disconnected: {self.remote_ip}:{self.remote_port}")

    def on_login(self, username):
        print(f"User logged in: {username}")

    def on_login_failed(self, username, password):
        print(f"Failed login attempt: {username}")

FTPHandler = CustomFTPHandler
def main():
    # Create an authorizer
    authorizer = DummyAuthorizer()
    # Add an anonymous user (read-only access)
    authorizer.add_anonymous("/tmp")
    
    # Create a handler
    handler = FTPHandler
    handler.authorizer = authorizer
    
    # Create and start the server
    server_address = (os.getenv("SERVER_IP_ACCESSIBILITY"), int(os.getenv("SERVER_PORT")))
    ftp_server = FTPServer(server_address, handler)

    print(f"Starting FTP server on port {os.getenv('SERVER_PORT')}...")
    ftp_server.serve_forever()

if __name__ == "__main__":
    main()