#!/usr/bin/env python3
"""
Windows WiFi MitM Detector
Scans for ARP/DNS spoofing & deauth attacks. 
Requires: Npcap (npcap.com), scapy, numpy
Run as Administrator: python wifi_mitm_detector_win.py
"""

import socket
import struct
import time
import threading
import numpy as np
from collections import defaultdict, Counter
from scapy.all import *
from datetime import datetime
import sys
import os

class WiFiMitMDetector:
    def __init__(self, interface=None):
        self.arp_cache = {}
        self.dns_cache = {}
        self.deauth_count = Counter()
        self.suspicious_pairs = defaultdict(list)
        self.running = False
        
        # Auto-detect WiFi interface on Windows
        if interface is None:
            self.interface = self.get_wifi_interface()
        else:
            self.interface = interface
            
        print(f"[+] Using interface: {self.interface}")
    
    def get_wifi_interface(self):
        """Auto-detect WiFi adapter on Windows"""
        interfaces = get_if_list()
        wifi_interfaces = [iface for iface in interfaces if 'Wi-Fi' in iface or 'Wireless' in iface or '802.11' in iface]
        
        if wifi_interfaces:
            print(f"[+] Found WiFi interfaces: {wifi_interfaces}")
            return wifi_interfaces[0]  # Use first WiFi interface
        else:
            print("[!] No WiFi interface found. Available: ", interfaces[:5])
            return interfaces[0]  # Fallback to first interface
    
    def is_arp_spoof(self, pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            sender_ip = pkt[ARP].psrc
            sender_mac = pkt[ARP].hwsrc
            
            if sender_ip in self.arp_cache:
                if self.arp_cache[sender_ip] != sender_mac:
                    return True, f"ARP SPOOF: {sender_ip} MAC changed {self.arp_cache[sender_ip]} -> {sender_mac}"
            self.arp_cache[sender_ip] = sender_mac
        return False, None
    
    def is_dns_spoof(self, pkt):
        if DNS in pkt:
            if pkt[DNS].qd:
                query = pkt[DNS].qd.qname.decode().lower()
            else:
                query = None
                
            if pkt.haslayer(DNSRR):
                resp_ip = pkt[DNSRR].rdata
                if query and resp_ip:
                    key = f"{query}:{resp_ip}"
                    if key in self.dns_cache:
                        self.suspicious_pairs[query].append(resp_ip)
                        if len(set(self.suspicious_pairs[query])) > 1:
                            return True, f"DNS SPOOF: {query} -> multiple IPs {self.suspicious_pairs[query]}"
                    self.dns_cache[key] = time.time()
        return False, None
    
    def is_deauth_flood(self, pkt):
        if pkt.haslayer(Dot11Deauth):
            bssid = pkt.addr3
            self.deauth_count[bssid] += 1
            if self.deauth_count[bssid] > 20:
                return True, f"DEAUTH FLOOD: {bssid} ({self.deauth_count[bssid]} pkts)"
        return False, None
    
    def print_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("="*70)
        print("  WiFi MitM Detector (Windows Edition) - ARP/DNS/Deauth Scanner")
        print("="*70)
        print(f"Interface: {self.interface}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
    
    def packet_handler(self, pkt):
        alerts = []
        
        arp_alert, arp_msg = self.is_arp_spoof(pkt)
        if arp_alert: alerts.append(f"[!] {arp_msg}")
        
        dns_alert, dns_msg = self.is_dns_spoof(pkt)
        if dns_alert: alerts.append(f"[!] {dns_msg}")
        
        deauth_alert, deauth_msg = self.is_deauth_flood(pkt)
        if deauth_alert: alerts.append(f"[!] {deauth_msg}")
        
        for alert in alerts:
            print(f"\n{alert}")
            print(f"    {datetime.now().strftime('%H:%M:%S')} | {getattr(pkt, 'src', 'N/A')} -> {getattr(pkt, 'dst', 'N/A')}")
    
    def stats_thread(self):
        while self.running:
            time.sleep(30)
            print(f"\n[*] STATS: {len(self.arp_cache)} IPs | {len(self.dns_cache)} DNS | Deauth: {dict(self.deauth_count.most_common(3))}")
    
    def run(self, duration=3600):
        self.running = True
        self.print_banner()
        
        stats_t = threading.Thread(target=self.stats_thread, daemon=True)
        stats_t.start()
        
        try:
            print(f"[*] Capturing on {self.interface} for {duration}s (Ctrl+C to stop)")
            # Windows: capture Ethernet + 802.11 frames
            sniff(iface=self.interface, prn=self.packet_handler, store=0, timeout=duration, 
                  filter="arp or udp port 53 or wlan")
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
        finally:
            self.running = False

if __name__ == "__main__":
    print("Windows WiFi MitM Detector - Authorized Pentest Tool")
    print("1. Install Npcap: https://npcap.com")
    print("2. pip install scapy numpy")
    print("3. Run as Administrator")
    
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    detector = WiFiMitMDetector(interface)
    detector.run()
