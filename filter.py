# -*- coding: utf-8 -*-
from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
import re

with open("rules.json") as f:
    RULES = json.load(f)

def http_filter(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(TCP) and scapy_packet[TCP].dport == 80:
        if scapy_packet.haslayer(Raw):
            payload = scapy_packet[Raw].load.decode(errors="ignore")

            if any(payload.startswith(m) for m in RULES["blocked_methods"]):
                print("[BLOCK] Method:", payload.split()[0])
                packet.drop()
                return

            for host in RULES["blocked_hosts"]:
                if re.search(rf"Host:\s*{host}", payload, re.IGNORECASE):
                    print("[BLOCK] Host:", host)
                    packet.drop()
                    return

            for uri in RULES["blocked_uris"]:
                if re.search(rf"GET\s+{uri}", payload):
                    print("[BLOCK] URI:", uri)
                    packet.drop()
                    return

            for agent in RULES["blocked_agents"]:
                if re.search(rf"User-Agent:.*{agent}", payload, re.IGNORECASE):
                    print("[BLOCK] User-Agent:", agent)
                    packet.drop()
                    return

            for cookie in RULES["blocked_cookies"]:
                if re.search(rf"Cookie:.*{cookie}", payload, re.IGNORECASE):
                    print("[BLOCK] Cookie:", cookie)
                    packet.drop()
                    return

    packet.accept()

def main():
    print("[START] HTTP filter running (queue 5)")
    nfqueue = NetfilterQueue()
    nfqueue.bind(5, http_filter)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("[STOP] Filter stopped")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
