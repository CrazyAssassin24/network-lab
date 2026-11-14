"""
server.py - Simulated RFC 951 BOOTP Server using UDP Socket Programming
"""

import socket
import json
import argparse
import sys
import os
import time
from typing import Dict, Any

from bootp import (
    BootpPacket,
    BOOTREQUEST,
    BOOTREPLY,
    HTYPE_ETHERNET,
    HLEN_ETHERNET,
    pack_vendor_options,
)

DEFAULT_SERVER_PORT = 6767
DEFAULT_CLIENT_PORT = 6868
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "hosts.json")


class BootpServer:
    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        port: int = DEFAULT_SERVER_PORT,
        client_port: int = DEFAULT_CLIENT_PORT,
        config_path: str = DEFAULT_CONFIG_PATH,
        broadcast_mode: bool = False,
    ):
        self.bind_ip = bind_ip
        self.port = port
        self.client_port = client_port
        self.config_path = config_path
        self.broadcast_mode = broadcast_mode
        self.config = self.load_config()
        self.running = False
        self.sock: socket.socket | None = None

    def load_config(self) -> Dict[str, Any]:
        """Loads MAC to IP mapping from hosts.json."""
        if not os.path.exists(self.config_path):
            print(f"[!] Warning: Config file '{self.config_path}' not found. Using fallback table.")
            return {
                "server_config": {
                    "server_name": "bootp-srv-default.lab.local",
                    "server_ip": "192.168.10.1",
                    "default_subnet_mask": "255.255.255.0",
                    "default_router": "192.168.10.1",
                    "default_dns": ["1.1.1.1"],
                    "domain": "lab.local",
                },
                "hosts": {},
            }
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Normalize all MAC keys to lower case
                if "hosts" in data:
                    data["hosts"] = {k.lower(): v for k, v in data["hosts"].items()}
                return data
        except Exception as e:
            print(f"[!] Failed to parse configuration file: {e}")
            sys.exit(1)

    def start(self):
        """Starts the BOOTP UDP server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow address reuse and broadcast
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            self.sock.bind((self.bind_ip, self.port))
        except OSError as e:
            print(f"[ERROR] Could not bind to {self.bind_ip}:{self.port} - {e}")
            print("Tip: If using port 67, administrative/root privileges may be required.")
            return

        self.running = True
        print("=" * 66)
        print("                BOOTP SERVER STARTED")
        print("=" * 66)
        print(f"[*] Bound to        : {self.bind_ip}:{self.port}")
        print(f"[*] Client Port     : {self.client_port}")
        print(f"[*] Config Database : {self.config_path}")
        print(f"[*] Loaded Hosts    : {len(self.config.get('hosts', {}))} static mapping(s)")
        print(f"[*] Broadcast Mode  : {'ENABLED' if self.broadcast_mode else 'DIRECT / HYBRID'}")
        print("-" * 66)
        for mac, info in self.config.get("hosts", {}).items():
            print(f"    - {mac.upper()} -> {info.get('ip')} ({info.get('hostname', 'unknown')})")
        print("-" * 66)
        print("[*] Waiting for incoming BOOTREQUEST datagrams... (Ctrl+C to stop)\n")

        try:
            while self.running:
                try:
                    data, client_addr = self.sock.recvfrom(1024)
                except OSError:
                    if not self.running:
                        break
                    raise
                self.handle_packet(data, client_addr)
        except KeyboardInterrupt:
            print("\n[*] Stopping BOOTP Server...")
        finally:
            self.close()

    def handle_packet(self, data: bytes, client_addr: tuple):
        """Process incoming UDP datagram."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] >>> Received {len(data)} bytes from {client_addr[0]}:{client_addr[1]}")

        try:
            request = BootpPacket.unpack(data)
        except Exception as e:
            print(f"[!] Malformed packet discarded: {e}")
            return

        if request.op != BOOTREQUEST:
            print(f"[!] Ignored non-BOOTREQUEST packet (op={request.op})")
            return

        print(f"[*] Parsed BOOTREQUEST:")
        print(f"    - Transaction ID (xid) : 0x{request.xid:08X}")
        print(f"    - Client MAC (chaddr)  : {request.chaddr.upper()}")
        print(f"    - Client IP (ciaddr)   : {request.ciaddr}")
        print(f"    - Elapsed Seconds      : {request.secs}s")

        client_mac = request.chaddr.lower()
        hosts = self.config.get("hosts", {})
        server_cfg = self.config.get("server_config", {})

        if client_mac not in hosts:
            print(f"[!] LOOKUP FAILED: No static lease found for MAC {client_mac.upper()}.")
            print("[*] RFC 951 policy: Server silently ignores unconfigured clients.\n")
            return

        # Lookup succeeded: prepare BOOTREPLY
        host_info = hosts[client_mac]
        assigned_ip = host_info.get("ip", "0.0.0.0")
        boot_file = host_info.get("bootfile", "pxelinux.0")
        server_ip = server_cfg.get("server_ip", "192.168.10.1")
        server_name = server_cfg.get("server_name", "bootp-srv")
        subnet_mask = host_info.get("subnet_mask", server_cfg.get("default_subnet_mask", "255.255.255.0"))
        router = host_info.get("router", server_cfg.get("default_router", "192.168.10.1"))
        dns = host_info.get("dns", server_cfg.get("default_dns", ["1.1.1.1"]))
        hostname = host_info.get("hostname", "")
        domain = server_cfg.get("domain", "lab.local")

        print(f"[+] LOOKUP SUCCESS: Client recognized as '{hostname}'")
        print(f"    - Assigned IP (yiaddr) : {assigned_ip}")
        print(f"    - Boot File (file)     : {boot_file}")
        print(f"    - Subnet Mask          : {subnet_mask}")
        print(f"    - Router / Gateway     : {router}")

        # Build RFC 1048 vendor options
        vendor_dict = {
            "subnet_mask": subnet_mask,
            "router": router,
            "dns": dns,
            "hostname": hostname,
            "domain": domain,
        }
        vend_bytes = pack_vendor_options(vendor_dict)

        # Assemble BOOTREPLY packet
        reply = BootpPacket(
            op=BOOTREPLY,
            htype=request.htype,
            hlen=request.hlen,
            hops=request.hops,
            xid=request.xid,        # Echo back matching transaction ID
            secs=0,
            flags=request.flags,
            ciaddr=request.ciaddr,
            yiaddr=assigned_ip,     # "Your" client IP
            siaddr=server_ip,       # Next server IP (TFTP / boot server)
            giaddr=request.giaddr,
            chaddr=request.chaddr,  # Client hardware address
            sname=server_name,
            file=boot_file,
            vend=vend_bytes,
        )

        reply_bytes = reply.pack()

        # Determine destination address:
        # If broadcast mode or client asked for broadcast, send to broadcast address.
        # Otherwise, send directly to client's sender address or client_port.
        if self.broadcast_mode:
            dest_target = ("<broadcast>", self.client_port)
        else:
            # Send back to the client IP and port that initiated the request
            dest_target = (client_addr[0], client_addr[1])

        print(f"[*] Sending BOOTREPLY to {dest_target[0]}:{dest_target[1]} ({len(reply_bytes)} bytes)...")
        try:
            self.sock.sendto(reply_bytes, dest_target)
            print("[+] BOOTREPLY successfully sent.")
        except Exception as e:
            print(f"[!] Error sending reply: {e}")

    def close(self):
        self.running = False
        if self.sock:
            s = self.sock
            self.sock = None
            try:
                s.close()
            except Exception:
                pass
            print("[*] Server socket closed.")


def main():
    parser = argparse.ArgumentParser(description="Simulated BOOTP Server (RFC 951)")
    parser.add_argument("--ip", default="0.0.0.0", help="IP address to bind server (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT, help=f"Server UDP port (default: {DEFAULT_SERVER_PORT})")
    parser.add_argument("--client-port", type=int, default=DEFAULT_CLIENT_PORT, help=f"Target client UDP port for replies (default: {DEFAULT_CLIENT_PORT})")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Path to hosts.json config (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--broadcast", action="store_true", help="Send replies via UDP broadcast (255.255.255.255)")

    args = parser.parse_args()
    server = BootpServer(
        bind_ip=args.ip,
        port=args.port,
        client_port=args.client_port,
        config_path=args.config,
        broadcast_mode=args.broadcast,
    )
    server.start()


if __name__ == "__main__":
    main()
