#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef VICTIM_MAC
# define VICTIM_MAC ((unsigned char*)"\x02\x42\xac\x14\x00\x03")
#endif

// Global variables to store the arguments
char *g_src_ip;
char *g_src_mac;
char *g_target_ip;
char *g_target_mac;

void list_interfaces() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    printf("=== Available Network Interfaces ===\n");
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }
    
    for (device = alldevs; device != NULL; device = device->next) {
        printf("Interface: %s", device->name);
        if (device->description) {
            printf(" (%s)", device->description);
        }
        printf("\n");
        
        // Print addresses if available
        pcap_addr_t *addr;
        for (addr = device->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)addr->addr;
                printf("  IP: %s\n", inet_ntoa(sin->sin_addr));
            }
        }
    }
    
    pcap_freealldevs(alldevs);
    printf("=====================================\n");
}

char* getCurrentDate() {
    char* datebuf = malloc(40);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(datebuf, 40, "%Y-%m-%d %H:%M:%S", tm_info);
    return datebuf;
}

// Convert MAC string to bytes for comparison - FIXED VERSION
void mac_string_to_bytes(const char *mac_str, unsigned char *mac_bytes) {
    unsigned int temp[6];  // Use unsigned int temporaries
    
    sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
           &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]);
    
    // Copy to unsigned char array
    for (int i = 0; i < 6; i++) {
        mac_bytes[i] = (unsigned char)temp[i];
    }
}

// Print the MAC address in a human-readable format
void print_mac_address(const unsigned char* text, const unsigned char *mac) {
    printf("%s: ", text);
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", mac[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");
}

char* get_ip_src(const u_char *packet, const struct ether_header *eth_header) {
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        struct in_addr addr;
        addr.s_addr = ip_header->saddr;
        return inet_ntoa(addr);
    }
    char* unknown = malloc(strlen("Unknown") + 1);
    strcpy(unknown, "Unknown");
    return unknown;
}

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>

char* get_ip_dst(const u_char *packet, const struct ether_header *eth_header) {
    // Check if the Ethernet frame contains an IPv4 packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Cast the packet data to an IPv4 header
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));

        // Extract the destination IP address
        struct in_addr addr;
        addr.s_addr = ip_header->daddr;

        // Return the IP address as a string
        return strdup(inet_ntoa(addr)); // Use strdup to duplicate the string
    }

    // Return a constant string for non-IP packets
    return strdup("Unknown");
}

bool is_concerned_packet(const u_char *packet, const struct ether_header *eth_header)
{
    unsigned char src_mac_bytes[ETHER_ADDR_LEN];
    mac_string_to_bytes(g_src_mac, src_mac_bytes);
    unsigned char target_mac_bytes[ETHER_ADDR_LEN];
    mac_string_to_bytes(g_target_mac, target_mac_bytes);
    
    // Check MAC addresses (works for both ARP and IP packets)
    bool src_mac_involved = (memcmp(eth_header->ether_shost, src_mac_bytes, ETHER_ADDR_LEN) == 0 ||
                               memcmp(eth_header->ether_dhost, src_mac_bytes, ETHER_ADDR_LEN) == 0);
    
    bool target_mac_involved = (memcmp(eth_header->ether_shost, target_mac_bytes, ETHER_ADDR_LEN) == 0 ||
                               memcmp(eth_header->ether_dhost, target_mac_bytes, ETHER_ADDR_LEN) == 0);
    
    // For IP packets, also check IP addresses
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        
        uint32_t pkt_src_ip = ip_header->saddr;
        uint32_t pkt_dst_ip = ip_header->daddr;
        uint32_t arg_src_ip = inet_addr(g_src_ip);
        uint32_t arg_target_ip = inet_addr(g_target_ip);

        bool src_ip_involved = (pkt_src_ip == arg_src_ip || pkt_dst_ip == arg_src_ip);
        bool target_ip_involved = (pkt_src_ip == arg_target_ip || pkt_dst_ip == arg_target_ip);

        return src_mac_involved || target_mac_involved || src_ip_involved || target_ip_involved;
    }
    
    // For non-IP packets (like ARP), only check MAC addresses
    return src_mac_involved || target_mac_involved;
}

// Fixed packet handler signature - only 3 parameters as expected by pcap_loop
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    // if (!is_concerned_packet(packet, eth_header))
    //     return;

    char* date = getCurrentDate();
    printf("%s\n", date);
    free(date);

    printf("Length %d ||| Bytes %d\n", pkthdr->len, pkthdr->caplen);
    print_mac_address("Source MAC", eth_header->ether_shost);
    printf("Source IP: %s\n", get_ip_src(packet, eth_header));
    print_mac_address("Destination MAC", eth_header->ether_dhost);
    printf("Destination IP: %s\n", get_ip_dst(packet, eth_header));

    printf("Ethernet type: %hu (Other)\n\n", ntohs(eth_header->ether_type));
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <attacker_ip> <attacker_mac> <victim_ip> <victim_mac>\n", argv[0]);
        return 1;
    }

    // Store arguments in global variables
    g_src_ip = argv[1];
    g_src_mac = argv[2];
    g_target_ip = argv[3];
    g_target_mac = argv[4];

    char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    setbuf(stdout, NULL);

    printf("Attempting to open device: %s\n", dev);
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Successfully opened %s. Starting packet capture...\n", dev);
    printf("Monitoring packets for src : [MAC %s] [IP %s]\n", g_src_mac, g_src_ip);
    printf("Monitoring packets for target : [MAC %s] [IP %s]\n==========================\n\n", g_target_mac, g_target_ip);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
