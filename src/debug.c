/*
 * Copyright (c) 1995 Danny Gasparovski.
 * Portions copyright (c) 2000 Kelly Price.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "slirp.h"
#include "debug.h"              // merge with slirp.h


static	log_func_t	log_func = NULL;
FILE	*dfd = NULL;
#ifdef _DEBUG
int	dostats = 1;
#else
int	dostats = 0;
#endif
int	dbglvl = 0;


void
debug_init(char *file, int dbg)
{
    /* Close the old debugging file */
    if (dfd)
	fclose(dfd);

    /* Reset logger function. */
    log_func = NULL;

    dfd = fopen(file, "w");
    if (dfd != NULL) {
	dbglvl = dbg;

	fprintf(dfd, "Debugging Started level %i.\n", dbglvl);
	fflush(dfd);
    }
}


void
lprint(const char *fmt, ...)
{
    va_list args;
        
    va_start(args, fmt);

    if (log_func != NULL)
	(*log_func)(NULL, fmt, args);

    va_end(args);
}


/* Dump a packet in the same format as tcpdump -x */
#ifdef _DEBUG
void
dump_packet(void *dat, int n)
{
    uint8_t *pptr = (uint8_t *)dat;
    int j, k;

    n /= 16;
    n++;
    DEBUG_MISC((dfd, "PACKET DUMPED:\n"));
    for (j = 0; j < n; j++) {
	for(k = 0; k < 6; k++)
		DEBUG_MISC((dfd, "%02x ", *pptr++));
	DEBUG_MISC((dfd, "\n"));
	fflush(dfd);
    }
}
#endif


/* API: set logging output function to caller. */
void
slirp_debug(log_func_t func)
{
    log_func = func;

    /* Feedback to indicate logging is set up. */
    lprint("SLiRP: debug level %i\n", dbglvl);
}
