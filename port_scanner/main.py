#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import sys
import argparse


def scan_port(target, port, timeout=1):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
        string: banner if found, None otherwise
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex returns 0 if there's no error and connection is successful
        if sock.connect_ex((target, port)) != 0:
            return False, None

        # try to receive banner
        try:
            banner = sock.recv(4096).decode(errors="ignore").strip()
            if banner:
                return True, banner
        except socket.timeout:
            pass

        return True, None

    except OSError:
        return False, None

    finally:
        if sock:
            sock.close()


def scan_range(target, start_port, end_port, max_workers):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number
        max_workers (int): max # of workers used for multithreading

    Returns:
        list: List of open ports
    """
    open_ports = []
    banners = {}  # port -> banner

    total = end_port - start_port + 1
    completed = 0

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, target, port): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            completed += 1
            port = futures[future]

            if completed % 100 == 0 or completed == total:
                print(
                    f"\r[*] Scanning ports: {completed}/{total}",
                    end="",
                    flush=True
                )

            try:
                is_open, banner = future.result()

                if is_open:
                    open_ports.append(port)
                    if banner:
                        banners[port] = banner

            except Exception:
                pass

    return sorted(open_ports), banners

def parse_ports(port_range: str):
    """Port parsing helper function"""
    try:
        start, end = map(int, port_range.split("-"))
        if start < 1 or end > 65535 or start > end:
            raise ValueError
        return start, end
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Ports must be in the format START-END (e.g. 1-1024)"
    )
        
def parse_targets(targets: str):
    """
    Parse targets input.
    Supports:
      - Single IP / hostname (e.g. 172.20.0.10)
      - IP range (e.g. 172.20.0.10-172.20.0.40)
    """
    if "-" not in targets:
        return [targets]

    try:
        start_ip, end_ip = targets.split("-")

        start_parts = list(map(int, start_ip.split(".")))
        end_parts = list(map(int, end_ip.split(".")))

        if start_parts[:3] != end_parts[:3]:
            raise ValueError("IP range must be in the same /24")

        start = start_parts[3]
        end = end_parts[3]

        if start > end or not (0 <= start <= 255 and 0 <= end <= 255):
            raise ValueError

        base = ".".join(map(str, start_parts[:3]))
        return [f"{base}.{i}" for i in range(start, end + 1)]

    except Exception:
        raise argparse.ArgumentTypeError(
            "Targets must be a single IP or range like 172.20.0.10-172.20.0.40"
        )


def main():
    """Main function"""

    # Example usage (you should improve this):
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner.main <target> <ports> <worker>")
        print("Example: python3 port_scanner.main --targets 172.20.0.10-172.20.0.22 --ports 1-65535 --worker 300")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Port scanner"
    )

    parser.add_argument(
        "--targets",
        required=True,
        type=parse_targets,
    )


    parser.add_argument(
        "--ports",
        default="1-1024",
        type=parse_ports,
    )
    
    parser.add_argument(
        "--worker",
        type=int,
        default=100,
        required=False,
    )

    args = parser.parse_args()

    targets = args.targets
    start_port, end_port = args.ports
    worker_count = args.worker
    
    for target in targets:
        try:
            open_ports, banners = scan_range(target, start_port, end_port, worker_count)
        except Exception as e:
            print(f"[!] Error scanning {target}: {e}")
            continue

        print("\n[+] Scan complete!")

        if open_ports:
            print(f"[+] Found {len(open_ports)} open ports on {target}:")
            for port in open_ports:
                print(f"    Port {port}: open")
                if port in banners:
                    print(f"        Banner: {banners[port]}")
        else:
            print(f"[-] No open ports found on {target}.")

if __name__ == "__main__":
    main()
