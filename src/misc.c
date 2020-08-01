/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#ifdef _WIN32
# include <windows.h>
#else
# include <sys/ioctl.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
#endif
#include "private.h"
#include "slirp.h"


//#if SIZEOF_CHAR_P == 8
struct quehead_32 {
    uintptr_t qh_link;
    uintptr_t qh_rlink;
};


inline void
insque_32(void *a, void *b)
{
    register struct quehead_32 *el = (struct quehead_32 *) a;
    register struct quehead_32 *head = (struct quehead_32 *) b;

    el->qh_link = head->qh_link;
    head->qh_link = (uintptr_t)el;
    el->qh_rlink = (uintptr_t)head;
    ((struct quehead_32 *)(el->qh_link))->qh_rlink = (uintptr_t)el;
}


inline void
remque_32(void *a)
{
    register struct quehead_32 *el = (struct quehead_32 *) a;

    ((struct quehead_32 *)(el->qh_link))->qh_rlink = el->qh_rlink;
    ((struct quehead_32 *)(el->qh_rlink))->qh_link = el->qh_link;
    el->qh_rlink = 0;
}
//#endif /* SIZEOF_CHAR_P == 8 */


struct quehead {
    struct quehead *qh_link;
    struct quehead *qh_rlink;
};


void
insque(void *a, void *b)
{
    register struct quehead *el = (struct quehead *) a;
    register struct quehead *head = (struct quehead *) b;

    el->qh_link = head->qh_link;
    head->qh_link = (struct quehead *)el;
    el->qh_rlink = (struct quehead *)head;
    ((struct quehead *)(el->qh_link))->qh_rlink = (struct quehead *)el;
}


void
remque(void *a)
{
    register struct quehead *el = (struct quehead *) a;

    ((struct quehead *)(el->qh_link))->qh_rlink = el->qh_rlink;
    ((struct quehead *)(el->qh_rlink))->qh_link = el->qh_link;
    el->qh_rlink = NULL;
#if 0
    el->qh_link = NULL;	/* TCP FIN1 crashes if you do this.  Why ? */
#endif
}


#ifndef HAVE_STRERROR
/* For systems with no strerror. */
char *
SLIRPstrerror(int error)
{
    if (error < sys_nerr)
	return sys_errlist[error];

    return "Unknown error.";
}
#endif


/* Set fd blocking and non-blocking. */
void
fd_nonblock(int fd)
{
#if defined(USE_FIONBIO) && defined(FIONBIO)
    ioctlsockopt_t opt = 1;

    ioctlsocket(fd, FIONBIO, &opt);
#else
    int opt;
	
    opt = fcntl(fd, F_GETFL, 0);
    opt |= O_NONBLOCK;
    fcntl(fd, F_SETFL, opt);
#endif
}


void
fd_block(int fd)
{
#if defined(USE_FIONBIO) && defined(FIONBIO)
    ioctlsockopt_t opt = 0;

    ioctlsocket(fd, FIONBIO, &opt);
#else
    int opt;

    opt = fcntl(fd, F_GETFL, 0);
    opt &= ~O_NONBLOCK;
    fcntl(fd, F_SETFL, opt);
#endif
}
