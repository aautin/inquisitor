#include <unistd.h>
#include "spoofer.h"

void poison(state* s)
{
	// To be continued
}

void restore(state* s)
{
	// To be continued
}

void* spoofer(void* arg)
{
	state* s = (state*)arg;

	pthread_mutex_lock(&s->mutex);
	while (s->status == KEEP_GOING) {
		pthread_mutex_unlock(&s->mutex);

		poison(s);
		printf("Spoofing ARP packets...\n");
		usleep(200);

		pthread_mutex_lock(&s->mutex);
	}
	pthread_mutex_unlock(&s->mutex);

	pthread_mutex_lock(&s->mutex);
	while (s->status != RESTORE) {
		pthread_mutex_unlock(&s->mutex);

		usleep(1000);
		pthread_mutex_lock(&s->mutex);
	}
	pthread_mutex_unlock(&s->mutex);

	restore(s);
	
	return NULL;
}
