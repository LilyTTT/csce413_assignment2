#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import time
import paramiko
import threading
import socket

from logger import create_logger

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 22
HOST_KEY = paramiko.RSAKey.generate(2048)


class HoneypotSsh(paramiko.ServerInterface):
    def __init__(self):
        self.attempts = 0
        self.logger = logging.getLogger("Honeypot")
        
    def check_auth_password(self, username, password):
        self.attempts += 1
        self.logger.warning(
            f"SSH login attempt | user='{username}' password='{password}'"
        )
        if self.attempts >= 3:
            return paramiko.AUTH_FAILED
        
        return paramiko.AUTH_FAILED

def setup_logging():
    logger = create_logger()
    logger.info("Logger initiazlied")
    
def impersonate(client, addr):
    ip, port = addr
    logger=logging.getLogger("Honeypot")
    logger.info(f"Connection from {ip}:{port}")

    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    # open ssh banner (grabbed from secret SSH)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13"

    server = HoneypotSsh()

    try:
        transport.start_server(server=server)

        # paramiko will handle the disconnection
        while transport.is_active():
            time.sleep(0.1)

        transport.close()

    except Exception as e:
        logger.error(f"Error handling {ip}: {e}")
    finally:
        transport.close()
        logger.info(f"Connection closed for {ip}")

def run_honeypot():
    logger = logging.getLogger("Honeypot")
    logger.info(f"Starting SSH honeypot on port {LISTEN_PORT}")
    
    # listening for suspicious activities on port 2222...
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((LISTEN_HOST, LISTEN_PORT))
        server.listen(100)

        # accept connection & start acting like a SSH server
        while True:
            conn, addr = server.accept()
            threading.Thread(
                target=impersonate,
                args=(conn, addr),
                daemon=True,
            ).start()


if __name__ == "__main__":
    setup_logging()
    run_honeypot()
