"""
simulate_lab.py - Automated End-to-End Simulation of BOOTP Lab
Demonstrates registered client lease acquisition, diskless bootfile lookup,
unregistered MAC rejection/timeout, and exponential backoff.
"""

import threading
import time
import sys
import os

from server import BootpServer, DEFAULT_SERVER_PORT, DEFAULT_CLIENT_PORT
from client import BootpClient
from bootp import BootpPacket, BOOTREQUEST, BOOTREPLY


def test_packet_integrity():
    """Unit test for 300-byte packet packing and unpacking."""
    print("\n" + "=" * 70)
    print(" [STAGE 1] Testing BOOTP Packet Struct Binary Integrity")
    print("=" * 70)

    original = BootpPacket(
        op=BOOTREQUEST,
        xid=0x12345678,
        secs=5,
        ciaddr="0.0.0.0",
        yiaddr="192.168.1.50",
        siaddr="192.168.1.1",
        chaddr="00:11:22:33:44:55",
        sname="tftp-server.lab",
        file="bootloader.bin",
    )
    original.set_vendor_options({
        "subnet_mask": "255.255.255.0",
        "router": "192.168.1.1",
        "dns": ["8.8.8.8", "1.1.1.1"],
    })

    raw = original.pack()
    assert len(raw) == 300, f"Expected 300 bytes, got {len(raw)}"

    unpacked = BootpPacket.unpack(raw)
    assert unpacked.op == original.op
    assert unpacked.xid == original.xid
    assert unpacked.chaddr.lower() == original.chaddr.lower()
    assert unpacked.yiaddr == original.yiaddr
    assert unpacked.sname == original.sname
    assert unpacked.file == original.file

    opts = unpacked.get_vendor_options()
    assert opts.get("subnet_mask") == "255.255.255.0"
    assert opts.get("router") == "192.168.1.1"
    assert "8.8.8.8" in opts.get("dns", [])

    print(f"[+] Packet Struct test PASSED. Exact RFC 951 size: {len(raw)} bytes.")
    print(unpacked.summary())


def run_full_simulation():
    test_packet_integrity()

    print("\n" + "=" * 70)
    print(" [STAGE 2] Starting BOOTP Server Thread on 127.0.0.1:6767")
    print("=" * 70)

    server = BootpServer(
        bind_ip="127.0.0.1",
        port=DEFAULT_SERVER_PORT,
        client_port=DEFAULT_CLIENT_PORT,
        broadcast_mode=False,
    )
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)  # Allow socket to bind

    # -------------------------------------------------------------------
    # Scenario 1: Registered Workstation Client
    # -------------------------------------------------------------------
    print("\n" + "=" * 70)
    print(" [STAGE 3] Scenario 1: Registered Client ('00:11:22:33:44:55')")
    print("=" * 70)
    client1 = BootpClient(
        server_ip="127.0.0.1",
        server_port=DEFAULT_SERVER_PORT,
        client_port=DEFAULT_CLIENT_PORT,
        mac_address="00:11:22:33:44:55",
        timeout=1.5,
    )
    res1 = client1.run()
    assert res1 is not None, "Scenario 1 failed to acquire IP!"
    assert res1.yiaddr == "192.168.10.101"
    assert res1.file == "pxelinux.0"

    time.sleep(0.5)

    # -------------------------------------------------------------------
    # Scenario 2: Diskless Node Client requesting network boot kernel
    # -------------------------------------------------------------------
    print("\n" + "=" * 70)
    print(" [STAGE 4] Scenario 2: Diskless Node ('00:aa:bb:cc:dd:ee')")
    print("=" * 70)
    client2 = BootpClient(
        server_ip="127.0.0.1",
        server_port=DEFAULT_SERVER_PORT,
        client_port=DEFAULT_CLIENT_PORT + 1,
        mac_address="00:aa:bb:cc:dd:ee",
        timeout=1.5,
    )
    res2 = client2.run()
    assert res2 is not None, "Scenario 2 failed to acquire IP!"
    assert res2.yiaddr == "192.168.10.102"
    assert res2.file == "vmlinuz.x86_64"

    time.sleep(0.5)

    # -------------------------------------------------------------------
    # Scenario 3: Unknown / Unregistered Client MAC
    # -------------------------------------------------------------------
    print("\n" + "=" * 70)
    print(" [STAGE 5] Scenario 3: Unregistered Client ('fe:ed:fa:ce:ca:fe')")
    print("   (Testing RFC 951 static lease rejection & backoff timeout)")
    print("=" * 70)
    client3 = BootpClient(
        server_ip="127.0.0.1",
        server_port=DEFAULT_SERVER_PORT,
        client_port=DEFAULT_CLIENT_PORT + 2,
        mac_address="fe:ed:fa:ce:ca:fe",
        timeout=0.6,
        max_retries=2,
    )
    res3 = client3.run()
    assert res3 is None, "Unknown client should not have received an IP!"
    print("[+] Expected result verified: Server dropped unknown MAC and client timed out.")

    print("\n" + "=" * 70)
    print(" [FINISHED] All BOOTP Lab simulation test stages completed successfully!")
    print("=" * 70)
    server.close()


if __name__ == "__main__":
    run_full_simulation()
