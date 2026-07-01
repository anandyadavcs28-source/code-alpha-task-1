#!/usr/bin/env python3
"""Basic network packet sniffer built with Scapy.

Run with administrator/root privileges when capturing live traffic.
Only capture traffic on networks and machines where you have permission.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from textwrap import shorten

try:
    from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, conf, get_if_list, sniff
except ImportError as exc:  # pragma: no cover - depends on local environment
    raise SystemExit(
        "Scapy is required. Install it with: python -m pip install -r requirements.txt"
    ) from exc


PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def format_payload(data: bytes, max_bytes: int) -> str:
    """Return a compact hex + ASCII view of packet payload bytes."""
    if not data:
        return ""

    clipped = data[:max_bytes]
    hex_view = " ".join(f"{byte:02x}" for byte in clipped)
    ascii_view = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in clipped)
    suffix = " ..." if len(data) > max_bytes else ""
    return f"hex={hex_view}{suffix} | ascii={ascii_view}{suffix}"


def protocol_name(packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP):
        return PROTO_NAMES.get(packet[IP].proto, f"IP/{packet[IP].proto}")
    if packet.haslayer(IPv6):
        return f"IPv6/{packet[IPv6].nh}"
    return packet.lastlayer().name


def endpoint_summary(packet) -> tuple[str, str]:
    """Extract source and destination endpoint labels from common protocols."""
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    elif packet.haslayer(ARP):
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
    elif packet.haslayer(Ether):
        src = packet[Ether].src
        dst = packet[Ether].dst
    else:
        return "unknown", "unknown"

    if packet.haslayer(TCP):
        src = f"{src}:{packet[TCP].sport}"
        dst = f"{dst}:{packet[TCP].dport}"
    elif packet.haslayer(UDP):
        src = f"{src}:{packet[UDP].sport}"
        dst = f"{dst}:{packet[UDP].dport}"

    return src, dst


def packet_length(packet) -> int:
    try:
        return len(bytes(packet))
    except Exception:
        return len(packet)


def describe_flags(packet) -> str:
    if packet.haslayer(TCP):
        return f" flags={packet[TCP].sprintf('%TCP.flags%')}"
    return ""


def make_packet_handler(show_payload: bool, payload_bytes: int):
    def handle_packet(packet) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        src, dst = endpoint_summary(packet)
        proto = protocol_name(packet)
        length = packet_length(packet)
        flags = describe_flags(packet)

        print(f"[{timestamp}] {proto:<8} {src} -> {dst} len={length}{flags}")

        if show_payload and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            payload_text = format_payload(payload, payload_bytes)
            print(f"           payload {shorten(payload_text, width=180, placeholder=' ...')}")

    return handle_packet


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture packets and display source, destination, protocol, length, and payload details."
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to sniff on. Omit to use Scapy's default interface.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. Use 0 to capture until Ctrl+C.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="",
        help='Optional BPF filter, such as "tcp", "udp", "icmp", or "port 53".',
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=48,
        help="Maximum number of payload bytes to print per packet.",
    )
    parser.add_argument(
        "--no-payload",
        action="store_true",
        help="Hide raw payload previews.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Print available interfaces and exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        return 0

    iface = args.interface or conf.iface
    print("Basic Network Sniffer")
    print(f"Interface: {iface}")
    print(f"Filter: {args.filter or '(none)'}")
    print(f"Packet count: {args.count or 'until Ctrl+C'}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            count=args.count,
            prn=make_packet_handler(not args.no_payload, args.payload_bytes),
            store=False,
        )
    except PermissionError:
        print("Permission denied. Run this program as administrator/root.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        print("On Windows, install Npcap and run the terminal as Administrator.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCapture stopped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())