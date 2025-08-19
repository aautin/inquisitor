#include "utils.h"
#include "spoofer.h"

static void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes)
{
	state* s = (state*)user;

	// ARP (EtherType 0x0806)
	if (bytes[12] == 0x08 && bytes[13] == 0x06) { // ARP frame detected
		if (bytes[20] == 0x00 && bytes[21] == 0x01)
			printf("Not an ARP request.\n");
	}
	if (bytes[12] == 0x08 && bytes[13] == 0x00) { // IPv4 frame detected
		// IPv4 header starts at bytes[14]
		uint8_t ihl = bytes[14] & 0x0F; // Internet Header Length
		uint8_t protocol = bytes[23];   // Protocol field

		printf("IPv4 packet detected. Header length: %u, Protocol: %u\n", ihl, protocol);
	}
	else if (bytes[12] == 0x08 && bytes[13] == 0x00) { // IP frame detected
		printf("IP frame detected.\n");
	}
	printf("------------\n\n");
}

void listen_device(char const* name, char** addresses)
{
	pcap_t* pcap;
	if (set_pcap(&pcap, name) != 0)
		return;

	state* user;
	if (set_user(&user, addresses) != 0) {
		pcap_close(pcap);
		return ;
	}

	pthread_t	poisoner;
	pthread_create(&poisoner, NULL, spoofer, (void*) user);
	pthread_detach(poisoner);

	pcap_loop(pcap, 0, packet_handler, (u_char*) user);
	pcap_close(pcap);
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	if (argc != 5) {
		fprintf(stderr, "Usage: %s <source_ip> <source_mac> <target_ip> <target_mac>\n", argv[0]);
		return 1;
	}

	printf("source IP: %s\n", argv[1]);
	printf("source MAC: %s\n", argv[2]);
	printf("target IP: %s\n", argv[3]);
	printf("target MAC: %s\n", argv[4]);

	pcap_if_t *alldevsp;
	char error_buffer[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevsp, error_buffer) == -1) {
		printf("Error finding devices: %s\n", error_buffer);
		return 1;
	}

    for (pcap_if_t* d = alldevsp; true; d = d->next) {
		if (d == NULL) {
			printf("Device eth0 not found.\n");
			break;
		}

		if (strcmp(d->name, "eth0") == 0) {
			listen_device(d->name, &argv[1]);
			break;
		}
	}

	pcap_freealldevs(alldevsp);
	return 0;
}
