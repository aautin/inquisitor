#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#ifndef VICTIM_MAC
# define VICTIM_MAC ((unsigned char*)"\x02\x42\xac\x14\x00\x03")
#endif

// Global variables to store the arguments
char *g_attacker_ip;
char *g_attacker_mac;
char *g_victim_ip;
char *g_victim_mac;

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

// Fixed packet handler signature - only 3 parameters as expected by pcap_loop
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    unsigned char victim_mac_bytes[ETHER_ADDR_LEN];
    mac_string_to_bytes(g_victim_mac, victim_mac_bytes);

    // Only process packets where victim is the source
    if (memcmp(eth_header->ether_shost, victim_mac_bytes, ETHER_ADDR_LEN) == 0)
        return;

    char* date = getCurrentDate();
    printf("%s\n", date);
    free(date);

    printf("Length %d ||| Bytes %d\n", pkthdr->len, pkthdr->caplen);
    printf("Destination MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", eth_header->ether_dhost[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");

    printf("Source MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", eth_header->ether_shost[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");

    printf("Ethernet type: %hu (Other)\n\n", ntohs(eth_header->ether_type));
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <attacker_ip> <attacker_mac> <victim_ip> <victim_mac>\n", argv[0]);
        return 1;
    }

    // Store arguments in global variables
    g_attacker_ip = argv[1];
    g_attacker_mac = argv[2];
    g_victim_ip = argv[3];
    g_victim_mac = argv[4];

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
    printf("Monitoring packets for victim MAC: %s\n==========================\n\n", g_victim_mac);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
