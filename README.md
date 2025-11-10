# ARP Spoofing & DNS MITM Lab using Scapy
**Safety first:** Use ONLY inside an isolated, private lab network you control. Do **not** run on campus/corporate/public networks.

## Topology
- Attacker: Kali Linux with Python 3, Scapy, tcpdump/Wireshark (iface: eth0 example)
- Victim: Kali/Windows
- Gateway/Server: Ubuntu with simple web server and optional local DNS

Example addressing:
- Gateway/Server: 192.168.56.1
- Victim: 192.168.56.101
- Attacker: 192.168.56.102

## Quick Start (Attacker)
1) Install deps: python3 -m pip install -r requirements.txt
2) Enable IP forwarding: echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
3) Start demo web server: python3 scripts/simple_web.py --port 8080
4) Become MITM: sudo python3 scripts/arp_spoof.py --victim 192.168.56.101 --gateway 192.168.56.1 --iface eth0 --verbose
5) Capture: sudo tcpdump -i eth0 -w pcap_files/lab_capture.pcap
6) Parse PCAP: python3 scripts/traffic_interceptor.py --pcap pcap_files/lab_capture.pcap --out evidence/extract
7) DNS spoof: python3 scripts/dns_spoof.py --iface eth0 --spoof-ip 192.168.56.102 --targets config/targets.txt --verbose
Victim: browse http://example.com 

## Evidence to Collect(You will get them after running quick start)
- ARP tables before/after
- PCAPs in pcap_files
- Parser CSVs in evidence
- Two Wireshark screenshots with annotations
- DNS spoof PCAP + victim browser screenshotts
- webserver logs
