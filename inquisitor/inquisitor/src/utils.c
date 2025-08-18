#include "utils.h"

char** split(const char* str, char delimiter)
{
	char** result = malloc(4 * sizeof(char*));
	int count = 0;
	const char* start = str;
	const char* end;

	while ((end = strchr(start, delimiter)) != NULL) {
		size_t len = end - start;
		result[count] = malloc(len + 1);
		strncpy(result[count], start, len);
		result[count][len] = '\0';
		start = end + 1;
		count++;
	}

	if (*start) {
		result[count] = strdup(start);
		count++;
	}

	result[count] = NULL;
	return result;
}

int set_user(state** user, char** addresses)
{
	*user = malloc(sizeof(state));
	if (*user == NULL)
		return 1;
	
	// MAC-address conversion into raw bytes
		for (int i = 0; i < 6; ++i) {
		sscanf(addresses[1] + 3 * i, "%2hhx", &((*user)->source_mac[i]));
		sscanf(addresses[3] + 3 * i, "%2hhx", &((*user)->target_mac[i]));
	}

	// MAC-address raw bytes print for debugging
	printf("Parsed source MAC: %d:%d:%d:%d:%d:%d\n",
		(*user)->source_mac[0], (*user)->source_mac[1], (*user)->source_mac[2],
		(*user)->source_mac[3], (*user)->source_mac[4], (*user)->source_mac[5]);
	printf("Parsed target MAC: %d:%d:%d:%d:%d:%d\n",
		(*user)->target_mac[0], (*user)->target_mac[1], (*user)->target_mac[2],
		(*user)->target_mac[3], (*user)->target_mac[4], (*user)->target_mac[5]);

	// IP-address conversion into raw bytes
	char** ip_source = split(addresses[0], '.');
	char** ip_target = split(addresses[2], '.');
	for (int i = 0; i < 4; ++i) {
		(*user)->source_ip[i] = atoi(ip_source[i]);
		(*user)->target_ip[i] = atoi(ip_target[i]);
	}

	// IP-address raw bytes print for debugging
	printf("Parsed source IP: %d.%d.%d.%d\n",
		(*user)->source_ip[0], (*user)->source_ip[1], (*user)->source_ip[2], (*user)->source_ip[3]);
	printf("Parsed target IP: %d.%d.%d.%d\n",
		(*user)->target_ip[0], (*user)->target_ip[1], (*user)->target_ip[2], (*user)->target_ip[3]);

	(*user)->counter = 0;
	(*user)->is_source_poisoned = false;
	(*user)->is_target_poisoned = false;

	return 0;
}

int set_pcap(pcap_t** pcap, char const* name)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	*pcap = pcap_create(name, errbuf);
	if (*pcap == NULL) {
		fprintf(stderr, "Error creating pcap handle: %s\n", errbuf);
		return 1;
	}

	pcap_set_snaplen(*pcap, 65535);
	pcap_set_promisc(*pcap, 1);
	pcap_set_timeout(*pcap, 1);
	pcap_set_immediate_mode(*pcap, 1);

	if (pcap_activate(*pcap) != 0) {
		fprintf(stderr, "Error activating pcap: %s\n", errbuf);
		pcap_close(*pcap);
		return 1;
	}

	return 0;
}

int get_arp_status(const u_char* bytes, char source_mac[6], char target_mac[6])
{
	// Check if the ARP frame is concerned with the source or target MAC addresses
	if ((strncmp(source_mac, (const char*)&bytes[22], 6) != 0 && strncmp(target_mac, (const char*)&bytes[32], 6) != 0))
		return 1;

	return 0;
}
