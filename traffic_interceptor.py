#!/usr/bin/env python3
from scapy.all import *
from collections import Counter
from datetime import datetime
import csv

def sniff_http_dns(interface="eth0", count=500):
    print(f"Sniffing {count} packets on {interface}...")

    packets = sniff(iface=interface,
                   filter="tcp port 80 or udp port 53",
                   count=count)
    return packets

def analyze_traffic(packets):
    urls = []
    dns_queries = []

    for p in packets:
        # Extract HTTP URLs
        if p.haslayer(TCP) and (p[TCP].dport == 80 or p[TCP].sport == 80):
            if p.haslayer(Raw):
                try:
                    payload = p[Raw].load.decode("utf-8", errors="ignore")
                    if "Host: " in payload and "GET" in payload:
                        host = payload.split("Host: ")[1].split("\r\n")[0]
                        path = payload.split("GET ")[1].split(" ")[0]
                        urls.append(f"http://{host}{path}")
                except: pass

        elif p.haslayer(DNSQR):
            try:
                query = p[DNSQR].qname.decode("utf-8").rstrip(".")
                dns_queries.append(query)
            except: pass

    return urls, dns_queries

def save_results(urls, dns_queries):
    """Save to CSV files"""
    timestamp = datetime.now().strftime("%H%M%S")

    with open(f"urls_{timestamp}.csv", "w") as f:
        f.write("URL\n")
        for url in set(urls):
            f.write(f"{url}\n")

    with open(f"dns_{timestamp}.csv", "w") as f:
        f.write("Query,Count\n")
        for query, count in Counter(dns_queries).most_common():
            f.write(f"{query},{count}\n")

    print(f"💾 Saved {len(set(urls))} URLs to urls_{timestamp}.csv")
    print(f"💾 Saved {len(set(dns_queries))} DNS queries to dns_{timestamp}.csv")


if __name__ == "__main__":
    packets = sniff_http_dns("eth0", 300)
    urls, dns_queries = analyze_traffic(packets)
    save_results(urls, dns_queries)

    print(f"\n Summary: {len(urls)} HTTP requests, {len(dns_queries)} DNS queries")
    print("Top 5 DNS:", Counter(dns_queries).most_common(5))