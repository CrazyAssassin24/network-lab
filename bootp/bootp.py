"""
bootp.py - BOOTP Protocol Packet Definition and Helper Utilities
Compliant with RFC 951 (Bootstrap Protocol) and RFC 1048/1542 (Vendor Extensions).
"""

import struct
import socket
import binascii
from typing import Dict, Any, Optional

# BOOTP Operation Codes
BOOTREQUEST = 1
BOOTREPLY = 2

# Hardware types
HTYPE_ETHERNET = 1
HLEN_ETHERNET = 6

# RFC 1048 Magic Cookie for Vendor Options Area (99.130.83.99)
RFC1048_MAGIC_COOKIE = b"\x63\x82\x53\x63"

# Common Vendor Option Codes (RFC 1048 / RFC 1497 / RFC 2132)
OPT_PAD = 0
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN = 15
OPT_END = 255


def mac_str_to_bytes(mac_str: str) -> bytes:
    """Convert MAC string like '00:1A:2B:3C:4D:5E' or '00-1A-2B-3C-4D-5E' to 6 bytes."""
    cleaned = mac_str.replace(":", "").replace("-", "").strip()
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address format: '{mac_str}'")
    return binascii.unhexlify(cleaned)


def mac_bytes_to_str(mac_bytes: bytes) -> str:
    """Convert bytes to MAC string '00:1a:2b:3c:4d:5e'."""
    return ":".join(f"{b:02x}" for b in mac_bytes[:6])


def ip_str_to_bytes(ip_str: str) -> bytes:
    """Convert dotted IPv4 string like '192.168.1.1' to 4 bytes."""
    return socket.inet_aton(ip_str)


def ip_bytes_to_str(ip_bytes: bytes) -> str:
    """Convert 4 bytes to dotted IPv4 string."""
    return socket.inet_ntoa(ip_bytes[:4])


def pack_vendor_options(options: Dict[str, Any]) -> bytes:
    """
    Packs a dictionary of options into the 64-byte RFC 1048 vendor field.
    Supported options in dict:
      - 'subnet_mask': '255.255.255.0'
      - 'router': '192.168.1.1'
      - 'dns': ['8.8.8.8', '1.1.1.1'] or '8.8.8.8'
      - 'hostname': 'node-01'
      - 'domain': 'lab.local'
    """
    buf = bytearray(RFC1048_MAGIC_COOKIE)

    # Subnet Mask (Option 1)
    if "subnet_mask" in options and options["subnet_mask"]:
        mask_bytes = ip_str_to_bytes(options["subnet_mask"])
        buf += struct.pack("!BB4s", OPT_SUBNET_MASK, 4, mask_bytes)

    # Router / Gateway (Option 3)
    if "router" in options and options["router"]:
        router_bytes = ip_str_to_bytes(options["router"])
        buf += struct.pack("!BB4s", OPT_ROUTER, 4, router_bytes)

    # DNS Servers (Option 6)
    if "dns" in options and options["dns"]:
        dns_list = options["dns"] if isinstance(options["dns"], list) else [options["dns"]]
        dns_payload = b"".join(ip_str_to_bytes(ip) for ip in dns_list)
        buf += struct.pack(f"!BB{len(dns_payload)}s", OPT_DNS, len(dns_payload), dns_payload)

    # Hostname (Option 12)
    if "hostname" in options and options["hostname"]:
        host_bytes = options["hostname"].encode("ascii")[:32]
        buf += struct.pack(f"!BB{len(host_bytes)}s", OPT_HOSTNAME, len(host_bytes), host_bytes)

    # Domain (Option 15)
    if "domain" in options and options["domain"]:
        dom_bytes = options["domain"].encode("ascii")[:32]
        buf += struct.pack(f"!BB{len(dom_bytes)}s", OPT_DOMAIN, len(dom_bytes), dom_bytes)

    # End Option (Option 255)
    buf.append(OPT_END)

    # Pad with zeros to exactly 64 bytes
    if len(buf) > 64:
        raise ValueError(f"Vendor options exceed 64 bytes limit (size={len(buf)})")
    buf += b"\x00" * (64 - len(buf))
    return bytes(buf)


def unpack_vendor_options(vend_bytes: bytes) -> Dict[str, Any]:
    """Unpacks RFC 1048 vendor options from the 64-byte field."""
    options: Dict[str, Any] = {}
    if len(vend_bytes) < 4 or vend_bytes[:4] != RFC1048_MAGIC_COOKIE:
        # Not RFC 1048 compliant, or raw vendor data
        options["raw"] = vend_bytes
        return options

    options["rfc1048_compliant"] = True
    idx = 4
    length = len(vend_bytes)

    while idx < length:
        opt_code = vend_bytes[idx]
        if opt_code == OPT_END:
            break
        if opt_code == OPT_PAD:
            idx += 1
            continue

        if idx + 1 >= length:
            break
        opt_len = vend_bytes[idx + 1]
        idx += 2

        if idx + opt_len > length:
            break

        opt_data = vend_bytes[idx : idx + opt_len]
        idx += opt_len

        if opt_code == OPT_SUBNET_MASK and opt_len == 4:
            options["subnet_mask"] = ip_bytes_to_str(opt_data)
        elif opt_code == OPT_ROUTER and opt_len == 4:
            options["router"] = ip_bytes_to_str(opt_data)
        elif opt_code == OPT_DNS and opt_len % 4 == 0:
            dns_servers = [ip_bytes_to_str(opt_data[i : i + 4]) for i in range(0, opt_len, 4)]
            options["dns"] = dns_servers
        elif opt_code == OPT_HOSTNAME:
            options["hostname"] = opt_data.decode("ascii", errors="replace")
        elif opt_code == OPT_DOMAIN:
            options["domain"] = opt_data.decode("ascii", errors="replace")
        else:
            options[f"opt_{opt_code}"] = opt_data

    return options


class BootpPacket:
    """
    Represents an RFC 951 BOOTP Packet (300 bytes fixed size).

    Packet Format (300 octets total):
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
     +---------------+---------------+---------------+---------------+
     |                            xid (4)                            |
     +-------------------------------+-------------------------------+
     |           secs (2)            |           flags (2)           |
     +-------------------------------+-------------------------------+
     |                          ciaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          yiaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          siaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          giaddr  (4)                          |
     +-------------------------------+-------------------------------+
     |                          chaddr  (16)                         |
     +-------------------------------+-------------------------------+
     |                          sname   (64)                         |
     +-------------------------------+-------------------------------+
     |                          file    (128)                        |
     +-------------------------------+-------------------------------+
     |                          vend    (64)                         |
     +-------------------------------+-------------------------------+
    """

    # Struct format: 1B, 1B, 1B, 1B, 4s/1I, 2s/1H, 2s/1H, 4s, 4s, 4s, 4s, 16s, 64s, 128s, 64s
    STRUCT_FORMAT = "!BBBBIHH4s4s4s4s16s64s128s64s"
    PACKET_SIZE = struct.calcsize(STRUCT_FORMAT)  # exactly 300 bytes

    def __init__(
        self,
        op: int = BOOTREQUEST,
        htype: int = HTYPE_ETHERNET,
        hlen: int = HLEN_ETHERNET,
        hops: int = 0,
        xid: int = 0,
        secs: int = 0,
        flags: int = 0,
        ciaddr: str = "0.0.0.0",
        yiaddr: str = "0.0.0.0",
        siaddr: str = "0.0.0.0",
        giaddr: str = "0.0.0.0",
        chaddr: str = "00:00:00:00:00:00",
        sname: str = "",
        file: str = "",
        vend: bytes = b"\x00" * 64,
    ):
        self.op = op
        self.htype = htype
        self.hlen = hlen
        self.hops = hops
        self.xid = xid
        self.secs = secs
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr
        self.sname = sname
        self.file = file
        self.vend = vend if len(vend) == 64 else (vend + b"\x00" * 64)[:64]

    def pack(self) -> bytes:
        """Serializes the BootpPacket into 300 bytes binary data."""
        # Hardware address: pad to 16 bytes
        chaddr_raw = mac_str_to_bytes(self.chaddr)
        chaddr_padded = chaddr_raw.ljust(16, b"\x00")

        # Null-terminated / padded strings
        sname_bytes = self.sname.encode("ascii")[:63].ljust(64, b"\x00")
        file_bytes = self.file.encode("ascii")[:127].ljust(128, b"\x00")

        return struct.pack(
            self.STRUCT_FORMAT,
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            ip_str_to_bytes(self.ciaddr),
            ip_str_to_bytes(self.yiaddr),
            ip_str_to_bytes(self.siaddr),
            ip_str_to_bytes(self.giaddr),
            chaddr_padded,
            sname_bytes,
            file_bytes,
            self.vend,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "BootpPacket":
        """Deserializes 300 bytes of binary data into a BootpPacket."""
        if len(data) < cls.PACKET_SIZE:
            raise ValueError(
                f"Packet data too short: expected at least {cls.PACKET_SIZE} bytes, got {len(data)}"
            )

        # Unpack the fixed 300 bytes (ignore any extra trailing bytes)
        raw_fields = struct.unpack(cls.STRUCT_FORMAT, data[: cls.PACKET_SIZE])

        (
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr_raw,
            yiaddr_raw,
            siaddr_raw,
            giaddr_raw,
            chaddr_raw,
            sname_raw,
            file_raw,
            vend_raw,
        ) = raw_fields

        # Extract MAC address based on hlen
        mac_bytes = chaddr_raw[:hlen]
        mac_str = mac_bytes_to_str(mac_bytes)

        # Decode null-terminated strings
        sname_str = sname_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        file_str = file_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")

        return cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=ip_bytes_to_str(ciaddr_raw),
            yiaddr=ip_bytes_to_str(yiaddr_raw),
            siaddr=ip_bytes_to_str(siaddr_raw),
            giaddr=ip_bytes_to_str(giaddr_raw),
            chaddr=mac_str,
            sname=sname_str,
            file=file_str,
            vend=vend_raw,
        )

    def get_vendor_options(self) -> Dict[str, Any]:
        """Parses the vendor field and returns key-value options."""
        return unpack_vendor_options(self.vend)

    def set_vendor_options(self, options: Dict[str, Any]) -> None:
        """Sets the vendor field from an options dictionary."""
        self.vend = pack_vendor_options(options)

    def op_name(self) -> str:
        if self.op == BOOTREQUEST:
            return "BOOTREQUEST (1)"
        elif self.op == BOOTREPLY:
            return "BOOTREPLY (2)"
        return f"UNKNOWN ({self.op})"

    def summary(self) -> str:
        """Returns a formatted multi-line summary of packet fields."""
        opts = self.get_vendor_options()
        opts_desc = []
        if opts.get("subnet_mask"):
            opts_desc.append(f"SubnetMask: {opts['subnet_mask']}")
        if opts.get("router"):
            opts_desc.append(f"Router: {opts['router']}")
        if opts.get("dns"):
            dns_val = ", ".join(opts["dns"]) if isinstance(opts["dns"], list) else opts["dns"]
            opts_desc.append(f"DNS: {dns_val}")
        if opts.get("domain"):
            opts_desc.append(f"Domain: {opts['domain']}")

        vend_summary = " | ".join(opts_desc) if opts_desc else "(None/Raw)"

        lines = [
            f"+---------------------------------------------------------------+",
            f"| BOOTP Message: {self.op_name():<46} |",
            f"+---------------------------------------------------------------+",
            f"| Transaction ID (xid) : 0x{self.xid:08X} ({self.xid})",
            f"| Client Hardware (chaddr): {self.chaddr} (htype={self.htype}, hlen={self.hlen})",
            f"| Client IP (ciaddr)    : {self.ciaddr}",
            f"| 'Your' IP (yiaddr)    : {self.yiaddr}",
            f"| Next Server (siaddr)  : {self.siaddr}",
            f"| Gateway IP (giaddr)   : {self.giaddr}",
            f"| Server Name (sname)   : '{self.sname}'",
            f"| Boot File (file)      : '{self.file}'",
            f"| Vendor Options (vend) : {vend_summary}",
            f"+---------------------------------------------------------------+",
        ]
        return "\n".join(lines)
