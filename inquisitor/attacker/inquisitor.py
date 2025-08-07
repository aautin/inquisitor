from scapy.all import sniff, Ether, IP, IPv6, ARP
import sys
import os

# src_ip = "172.20.0.3"             # IP du client
# src_mac = "02:42:ac:14:00:03"     # MAC du client
# target_ip = "172.20.0.4"          # IP du serveur
# target_mac = "02:42:ac:14:00:04"  # MAC du serveur
# my_mac = "02:42:ac:14:00:02"      # MAC de l'attaquant
# arp_response_client_server = Ether(dst=target_mac, src=my_mac) / ARP(
#     op=2,                   # 2 = is-at (ARP reply)
#     psrc=spoofed_ip,        # IP usurpée (serveur)
#     hwsrc=my_mac,           # MAC de l'attaquant
#     pdst=victim_ip,         # IP de la victime (client)
#     hwdst=victim_mac        # MAC de la victime
# )

def print_packet(packet):
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
    else:
        src_mac = dst_mac = "N/A"

    if packet.haslayer(ARP):
        print("ARP PACKET")
        print(f"Source MAC: {src_mac}")
        print(f"Source IP: {packet[ARP].psrc}")
        print(f"Destination MAC: {dst_mac}")
        print(f"Destination IP: {packet[ARP].pdst}\n")
    elif packet.haslayer(IP):
        print("IPv4 PACKET")
        print(f"Source MAC: {src_mac}")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination MAC: {dst_mac}")
        print(f"Destination IP: {packet[IP].dst}\n")
    else:
        print("OTHER PACKET/FRAME")
        print(f"Source MAC: {src_mac}")
        print(f"Destination MAC: {dst_mac}")
    print("")
    sys.stdout.flush()

if __name__ == "__main__":
    iface = os.environ.get("IFACE", "eth0")
    sniff(iface=iface, prn=print_packet, store=0)
