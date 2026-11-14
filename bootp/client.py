"""
client.py - Simulated RFC 951 BOOTP Client using UDP Socket Programming
"""

import socket
import argparse
import random
import time
import uuid
import sys
from typing import Optional

from bootp import (
    BootpPacket,
    BOOTREQUEST,
    BOOTREPLY,
    HTYPE_ETHERNET,
    HLEN_ETHERNET,
    RFC1048_MAGIC_COOKIE,
    OPT_END,
)

DEFAULT_SERVER_PORT = 6767
DEFAULT_CLIENT_PORT = 6868


def get_default_mac() -> str:
    """Retrieve host MAC address formatted as aa:bb:cc:dd:ee:ff."""
    mac_num = uuid.getnode()
    mac_bytes = [(mac_num >> (8 * i)) & 0xFF for i in reversed(range(6))]
    return ":".join(f"{b:02x}" for b in mac_bytes)


class BootpClient:
    def __init__(
        self,
        server_ip: str = "127.0.0.1",
        server_port: int = DEFAULT_SERVER_PORT,
        client_port: int = DEFAULT_CLIENT_PORT,
        mac_address: Optional[str] = None,
        broadcast: bool = False,
        timeout: float = 3.0,
        max_retries: int = 3,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port
        self.mac = (mac_address or get_default_mac()).lower()
        self.broadcast = broadcast
        self.timeout = timeout
        self.max_retries = max_retries

    def run(self) -> Optional[BootpPacket]:
        """
        Executes the BOOTP state machine:
          1. Generates 32-bit transaction ID (xid).
          2. Sends BOOTREQUEST datagram.
          3. Retransmits with exponential backoff on timeout.
          4. Verifies incoming BOOTREPLY (xid and chaddr matching).
        """
        # Generate random 32-bit transaction ID
        xid = random.getrandbits(32)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # In non-broadcast local testing, bind to client_port or let OS pick ephemeral port
        try:
            sock.bind(("0.0.0.0", self.client_port))
        except OSError:
            # If default client port is busy or privileged, bind to an ephemeral port
            sock.bind(("0.0.0.0", 0))

        actual_client_ip, actual_client_port = sock.getsockname()

        print("=" * 66)
        print("                BOOTP CLIENT INITIATED")
        print("=" * 66)
        print(f"[*] Client Hardware (MAC) : {self.mac.upper()}")
        print(f"[*] Bound Local Socket    : {actual_client_ip}:{actual_client_port}")
        print(f"[*] Transaction ID (xid)  : 0x{xid:08X} ({xid})")
        print(f"[*] Target Destination    : {'255.255.255.255' if self.broadcast else self.server_ip}:{self.server_port}")
        print("=" * 66)

        start_time = time.time()
        current_timeout = self.timeout
        dest_host = "<broadcast>" if self.broadcast else self.server_ip

        for attempt in range(1, self.max_retries + 1):
            elapsed_secs = int(time.time() - start_time)

            # Build BOOTREQUEST
            # Minimal RFC 1048 cookie in vendor area to declare compatibility
            vend_cookie = RFC1048_MAGIC_COOKIE + bytes([OPT_END])

            request = BootpPacket(
                op=BOOTREQUEST,
                htype=HTYPE_ETHERNET,
                hlen=HLEN_ETHERNET,
                hops=0,
                xid=xid,
                secs=elapsed_secs,
                flags=0x8000 if self.broadcast else 0,  # 0x8000 = broadcast flag (RFC 1542)
                ciaddr="0.0.0.0",  # Client does not know its IP yet
                yiaddr="0.0.0.0",
                siaddr="0.0.0.0",
                giaddr="0.0.0.0",
                chaddr=self.mac,
                sname="",
                file="",
                vend=vend_cookie,
            )

            packet_bytes = request.pack()

            print(f"\n[Attempt {attempt}/{self.max_retries}] Sending BOOTREQUEST ({len(packet_bytes)} bytes) to {dest_host}:{self.server_port}...")
            sock.sendto(packet_bytes, (dest_host, self.server_port))

            sock.settimeout(current_timeout)
            print(f"[*] Listening for BOOTREPLY (timeout={current_timeout:.1f}s)...")

            wait_start = time.time()
            while time.time() - wait_start < current_timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    print(f"[-] Timed out waiting for reply.")
                    break
                except Exception as e:
                    print(f"[!] Socket error: {e}")
                    break

                try:
                    reply = BootpPacket.unpack(data)
                except Exception as e:
                    print(f"[!] Discarded malformed datagram from {addr}: {e}")
                    continue

                # Verify message type
                if reply.op != BOOTREPLY:
                    print(f"[!] Ignored non-BOOTREPLY packet (op={reply.op}) from {addr}")
                    continue

                # Verify transaction ID
                if reply.xid != xid:
                    print(f"[!] Ignored reply with mismatched xid: expected 0x{xid:08X}, got 0x{reply.xid:08X}")
                    continue

                # Verify MAC address
                if reply.chaddr.lower() != self.mac.lower():
                    print(f"[!] Ignored reply intended for different MAC: {reply.chaddr}")
                    continue

                # Successfully received valid BOOTREPLY
                print(f"\n[+] SUCCESS! Valid BOOTREPLY received from {addr[0]}:{addr[1]}")
                self.print_lease(reply)
                sock.close()
                return reply

            # Exponential backoff with small random jitter
            current_timeout = (current_timeout * 2) + random.uniform(0.1, 0.5)

        print("\n[-] EXHAUSTED: No BOOTP response received after maximum retries.")
        print("    Possible causes:")
        print("    1. Server is not running.")
        print("    2. Client MAC address is not registered in the server's hosts table.")
        print("    3. Firewall or UDP packet drop.")
        sock.close()
        return None

    def print_lease(self, reply: BootpPacket):
        """Displays network configuration obtained from the BOOTP server."""
        opts = reply.get_vendor_options()
        print("\n" + "=" * 66)
        print("           BOOTP NETWORK CONFIGURATION LEASE")
        print("=" * 66)
        print(f"  Assigned Client IP (yiaddr) : {reply.yiaddr}")
        print(f"  Subnet Mask                 : {opts.get('subnet_mask', 'N/A')}")
        print(f"  Default Gateway / Router    : {opts.get('router', 'N/A')}")
        dns_servers = opts.get("dns", [])
        if isinstance(dns_servers, list):
            dns_str = ", ".join(dns_servers)
        else:
            dns_str = str(dns_servers) if dns_servers else "N/A"
        print(f"  DNS Servers                 : {dns_str}")
        print(f"  Domain Name                 : {opts.get('domain', 'N/A')}")
        print(f"  Assigned Hostname           : {opts.get('hostname', 'N/A')}")
        print(f"  Next Server IP (siaddr)     : {reply.siaddr}")
        print(f"  Server Hostname (sname)     : {reply.sname or 'N/A'}")
        print(f"  Boot File (file)            : {reply.file or 'N/A'}")
        print("=" * 66)
        print("[*] Client simulated network stack successfully configured!")
        if reply.file:
            print(f"[*] Next step in diskless boot: Initiate TFTP transfer for '{reply.file}' from {reply.siaddr}")
        print("=" * 66 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Simulated BOOTP Client (RFC 951)")
    parser.add_argument("--server", default="127.0.0.1", help="Target server IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT, help=f"Server UDP port (default: {DEFAULT_SERVER_PORT})")
    parser.add_argument("--client-port", type=int, default=DEFAULT_CLIENT_PORT, help=f"Client UDP bind port (default: {DEFAULT_CLIENT_PORT})")
    parser.add_argument("--mac", default=None, help="Client MAC address (default: actual hardware MAC)")
    parser.add_argument("--broadcast", action="store_true", help="Send request to 255.255.255.255")
    parser.add_argument("--timeout", type=float, default=2.5, help="Initial reply timeout in seconds (default: 2.5)")
    parser.add_argument("--retries", type=int, default=3, help="Max retransmission attempts (default: 3)")

    args = parser.parse_args()

    client = BootpClient(
        server_ip=args.server,
        server_port=args.port,
        client_port=args.client_port,
        mac_address=args.mac,
        broadcast=args.broadcast,
        timeout=args.timeout,
        max_retries=args.retries,
    )
    result = client.run()
    if not result:
        sys.exit(1)


if __name__ == "__main__":
    main()
