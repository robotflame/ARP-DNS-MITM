import argparse
from collections import Counter
import csv
from scapy.all import rdpcap, DNSQR, TCP, UDP, IP, IPv6, Raw

def parse_pcap(pcap_path, out_prefix):
    pkts = rdpcap(pcap_path)
    urls, dns_queries = [], []
    talkers, protos = Counter(), Counter()
    for p in pkts:
        if IP in p:
            talkers[p[IP].src] += 1
        elif IPv6 in p:
            talkers[p[IPv6].src] += 1
        if TCP in p:
            dport = p[TCP].dport
            if dport == 80 or (Raw in p and b'HTTP' in bytes(p[Raw])):
                protos['HTTP'] += 1
            elif dport == 443:
                protos['HTTPS'] += 1
            elif dport == 22:
                protos['SSH'] += 1
            elif dport == 21:
                protos['FTP'] += 1
            else:
                protos['TCP_OTHER'] += 1
        elif UDP in p:
            if p[UDP].dport == 53 or p[UDP].sport == 53:
                protos['DNS'] += 1
            else:
                protos['UDP_OTHER'] += 1
        if p.haslayer(DNSQR) and UDP in p:
            try:
                qname = p[DNSQR].qname.decode().rstrip('.')
                dns_queries.append(qname)
            except Exception:
                pass
        if Raw in p and TCP in p and (p[TCP].dport == 80 or p[TCP].sport == 80):
            data = bytes(p[Raw])
            try:
                header = data.split(b'\r\n\r\n', 1)[0]
                lines = header.split(b'\r\n')
                if lines:
                    req = lines[0].decode(errors='ignore')
                    if req.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ', 'OPTIONS ')):
                        host = ''
                        path = req.split(' ', 2)[1]
                        for line in lines[1:]:
                            if line.lower().startswith(b'host:'):
                                host = line.split(b':', 1)[1].strip().decode(errors='ignore')
                                break
                        if host:
                            urls.append(f'http://{host}{path}')
            except Exception:
                pass
    with open(out_prefix + '_urls.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['url']); [w.writerow([u]) for u in urls]
    with open(out_prefix + '_dns.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['qname']); [w.writerow([q]) for q in dns_queries]
    with open(out_prefix + '_talkers.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['ip', 'count']); [w.writerow([ip, cnt]) for ip, cnt in talkers.most_common()]
    with open(out_prefix + '_proto.csv', 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['protocol', 'count']); [w.writerow([proto, cnt]) for proto, cnt in protos.items()]
    print(f'[+] Wrote: {out_prefix}_urls.csv, {out_prefix}_dns.csv, {out_prefix}_talkers.csv, {out_prefix}_proto.csv')

def main():
    ap = argparse.ArgumentParser(description='Parse PCAP for URLs, DNS, talkers, and protocol counts.')
    ap.add_argument('--pcap', required=True, help='Path to PCAP file')
    ap.add_argument('--out', required=True, help='Output prefix, e.g., evidence/extract')
    args = ap.parse_args()
    parse_pcap(args.pcap, args.out)

if __name__ == '__main__':
    main()
