#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct s_state{
	char*	client_ip;
	char*	client_mac;
	char*	server_ip;
	char*	server_mac;

	int		counter;
	int		is_client_poisoned;
	int		is_target_poisoned;
}	state;

static void packet_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes)
{
	state* s = (state*)user;

	printf("Packet[%d] captured: %d bytes\n", s->counter++, h->len);
}

static int set_user(state** user, char** addresses)
{
	*user = malloc(sizeof(state));
	if (*user == NULL)
		return 1;
	
	(*user)->client_ip = addresses[0];
	(*user)->client_mac = addresses[1];
	(*user)->server_ip = addresses[2];
	(*user)->server_mac = addresses[3];

	(*user)->counter = 0;
	(*user)->is_client_poisoned = false;
	(*user)->is_target_poisoned = false;

	return 0;
}

void listen_device(char const* name, char** addresses)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_create(name, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Error creating pcap handle: %s\n", errbuf);
		return;
	}

	pcap_set_snaplen(pcap, 65535);
	pcap_set_promisc(pcap, 1);
	pcap_set_timeout(pcap, 1);
	pcap_set_immediate_mode(pcap, 1);

	if (pcap_activate(pcap) != 0) {
		fprintf(stderr, "Error activating pcap: %s\n", errbuf);
		pcap_close(pcap);
		return;
	}

	state* user;
	if (set_user(&user, addresses) != 0)
		fprintf(stderr, "Error during set_user()");
	else {
		printf("pcap_loop()\n");
		pcap_loop(pcap, 0, packet_handler, (u_char*) user);
	}

	pcap_close(pcap);
}

int main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <client_ip> <client_mac> <server_ip> <server_mac>\n", argv[0]);
		return 1;
	}

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("Client IP: %s\n", argv[1]);
	printf("Client MAC: %s\n", argv[2]);
	printf("Server IP: %s\n", argv[3]);
	printf("Server MAC: %s\n", argv[4]);

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
