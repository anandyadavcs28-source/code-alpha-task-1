Basic Network Sniffer
A small Python packet sniffer that captures live network traffic with Scapy and prints useful packet details:

source and destination IPs or MAC addresses
TCP/UDP ports when available
protocol type
packet length
TCP flags
raw payload preview in hex and ASCII
Use this only on machines and networks where you have permission to inspect traffic.

Setup

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

On Windows, live capture usually also requires:

Npcap
an Administrator terminal
Usage

List interfaces:
python sniffer.py --list-interfaces


Capture 10 packets on the default interface:
python sniffer.py --count 10


Capture only TCP traffic:
python sniffer.py --filter "tcp"


Capture DNS traffic on a specific interface:
python sniffer.py --interface "Wi-Fi" --filter "port 53"


Hide payload previews:
python sniffer.py --no-payload


What To Look For
Each packet line shows how data flows from one endpoint to another:

[14:22:03] TCP      192.168.1.20:51522 -> 142.250.190.14:443 len=66 flags=S
That example means a TCP packet moved from local IP 192.168.1.20 and source port 51522 to remote IP 142.250.190.14 on HTTPS port 443.