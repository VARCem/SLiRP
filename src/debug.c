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
#include "private.h"
#define HAVE_STDARG_H
#include "slirp.h"


static	log_func_t	log_func = NULL;
FILE			*dfd = NULL;
#ifdef _DEBUG
int			dostats = 1;
#else
int			dostats = 0;
#endif
int			dbglvl = 0;


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


_SLIRP_API void
debug_init(const char *fn, int level)
{
    /* Close the old debugging file */
    if (dfd != NULL)
	(void)fclose(dfd);

    /* Reset logger function. */
    log_func = NULL;

    dfd = fopen(fn, "w");
    if (dfd != NULL) {
	if (level != -1)
		dbglvl = level;

	fprintf(dfd, "SLiRP: debugging (level %i) started.\n", dbglvl);
	fflush(dfd);
    }
}


/* API: set logging output function to caller. */
_SLIRP_API void
slirp_debug(int level, log_func_t func)
{
    if (func != NULL)
	log_func = func;

    if (level != -1)
	dbglvl = level;

    /* Feedback to indicate logging is set up. */
    if (dbglvl > 0)
	lprint("SLiRP: debug level %i\n", dbglvl);
}
