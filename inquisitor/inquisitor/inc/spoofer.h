#ifndef SPOOFER_H
# define SPOOFER_H

# include "utils.h"

void	poison(state* s);
void	restore(state* s);
void*	spoofer(void* arg);

#endif