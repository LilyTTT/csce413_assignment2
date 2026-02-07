#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import subprocess
import socket
import threading
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
CHAIN = "INPUT"

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def run_iptables(args):
    args_str = [str(a) for a in args]
    logging.info("iptables %s", " ".join(args))
    subprocess.run(["iptables"] + args_str, check=True)


def install_knock_rules(sequence, window_seconds, protected_port):
    """
    Install iptables rules implementing a port-knocking sequence
    using the recent module.
    """
    
    # # flush existing rules
    run_iptables(["-F"])
    run_iptables(["-X"])

    # build knock sequence
    for i, port in enumerate(sequence):
        current = f"KNOCK{i + 1}"

        if i == 0:
            # first knock
            run_iptables([
                "-A", CHAIN,
                "-p", "tcp",
                "--dport", str(port),
                "-m", "recent",
                "--name", current,
                "--set",
                "-j", "DROP",
            ])
        else:
            previous = f"KNOCK{i}"
            run_iptables([
                "-A", CHAIN,
                "-p", "tcp",
                "--dport", str(port),
                "-m", "recent",
                "--name", previous,
                "--rcheck",
                "--seconds", str(int(window_seconds)),
                "-m", "recent",
                "--name", current,
                "--set",
                "-j", "DROP",
            ])

    # allow protected port if sequence completed
    final_list = f"KNOCK{len(sequence)}"
    run_iptables([
        "-A", CHAIN,
        "-p", "tcp",
        "--dport", str(protected_port),
        "-m", "recent",
        "--name", final_list,
        "--rcheck",
        "--seconds", str(int(window_seconds)),
        "-j", "ACCEPT",
    ])

    # default deny for protected port
    run_iptables([
        "-A", CHAIN,
        "-p", "tcp",
        "--dport", str(protected_port),
        "-j", "DROP",
    ])

def listen_on_port(port):
    # open expected ports
    logger = logging.getLogger("KnockServer")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(1)
    
    while True:
        conn, addr = server.accept()
        logger.info(f"Recived knock from {addr} on port {port}")
        conn.close()

def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)
    logger.info("Implemented")

    install_knock_rules(sequence, window_seconds, protected_port)

    for port in sequence:
        threading.Thread(target=listen_on_port, args=(port,), daemon=True).start()
    while True:
        time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
