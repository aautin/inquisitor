#ifndef UTILS_H
# define UTILS_H

# include <stdbool.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <pthread.h>
# include <pcap.h>

typedef enum e_request_type {
	SRC_TO_TARGET,
	TARGET_TO_SRC,
	OTHER
}	request_type;

typedef enum e_poison {
	KEEP_GOING,
	STOP,
	RESTORE
}	poison_t;

typedef struct s_state{
	unsigned char	source_ip[4];
	unsigned char	source_mac[6];
	unsigned char	target_ip[4];
	unsigned char	target_mac[6];

	pthread_mutex_t	mutex;
	poison_t		status;

	int		is_source_poisoned;
	int		is_target_poisoned;
}	state;

char**	split(const char* str, char delimiter);
int		set_user(state** user, char** addresses);
int		set_pcap(pcap_t** pcap, const char* name);
int		get_arp_status(const u_char* bytes, char source_mac[6], char target_mac[6]);

#endif