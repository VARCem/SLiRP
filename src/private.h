/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */
#ifndef SLIRP_PRIVATE_H
# define SLIRP_PRIVATE_H

# include "config.h"


#define CTL_SPECIAL	"10.222.2.0"

//#define CTL_CMD	0
#define CTL_ROUTER	1
#define CTL_SERVER	2	/* handled BOOTP/DHCP and DNS */
//#define CTL_EXEC	4
//#define CTL_LOCAL	15


/* Define to 1 if you want KEEPALIVE timers */
#define DO_KEEPALIVE 0		/* tcp_timer.c */

#define MIN_MRU 128
#define MAX_MRU 16384


#ifdef _WIN32
# define _SLIRP_API __declspec(dllexport)
#else
# define _SLIRP_API  __attribute__((visibility("default")))
#endif


#define DBG_CALL	0x01
#define DBG_MISC	0x02
#define DBG_ERROR	0x04
#define DEBUG_DEFAULT	DBG_CALL|DBG_MISC|DBG_ERROR


#ifdef _DEBUG
# define DEBUG_CALL(x) \
	if (dbglvl & DBG_CALL) { \
		fprintf(dfd, "%s...\n", x); \
		fflush(dfd); \
	}
# define DEBUG_ARG(x, y) \
	if (dbglvl & DBG_CALL) { \
		fputc(' ', dfd); \
		fprintf(dfd, x, y); \
		fputc('\n', dfd); \
		fflush(dfd); \
	}
# define DEBUG_ARGS(x) \
	if (dbglvl & DBG_CALL) { \
		fprintf x ; \
		fflush(dfd); \
	}
# define DEBUG_MISC(x) \
	if (dbglvl & DBG_MISC) { \
		fprintf x ; \
		fflush(dfd); \
	}
# define DEBUG_ERROR(x) \
	if (dbglvl & DBG_ERROR) { \
		fprintf x ; \
		fflush(dfd); \
	}
#else
# define DEBUG_CALL(x)
# define DEBUG_ARG(x, y)
# define DEBUG_ARGS(x)
# define DEBUG_MISC(x)
# define DEBUG_ERROR(x)
#endif


/* Avoid conflicting with the libc insque() and remque(), which
   have different prototypes. */
#ifdef insque
# undef insque
#endif
#define insque slirp_insque
#ifdef remque
# undef remque
#endif
#define remque slirp_remque

#if SIZEOF_CHAR_P == 4
# define insque_32 insque
# define remque_32 remque
#else
# ifdef NEED_QUE32_INLINE
extern __inline void	insque_32(void *, void *);
extern __inline void	remque_32(void *);
# else
extern void		insque_32(void *, void *);
extern void		remque_32(void *);
# endif
#endif

#ifndef _WIN32
# define min(x,y) ((x) < (y) ? (x) : (y))
# define max(x,y) ((x) > (y) ? (x) : (y))
#endif


extern char	slirp_hostname[32];
extern char	slirp_domainname[128];

extern uint8_t	client_macaddr[6];
extern const uint8_t special_macaddr[];
extern int	link_up;
extern u_int	curtime;

extern FILE	*dfd;
extern int	dostats;
extern int	dbglvl;

#ifdef HAVE_SOCKET_H
extern fd_set	*global_readfds,
		*global_writefds,
		*global_xfds;
#endif

#ifdef HAVE_INADDR_H
extern struct in_addr our_addr;
extern struct in_addr loopback_addr;
extern struct in_addr dns_addr;

extern struct in_addr special_addr;
extern struct in_addr router_addr;
extern struct in_addr ctl_addr;
#endif

extern int towrite_max;
extern int so_options;
extern int tcp_keepintvl;

extern int do_echo;


/* Functions. */
extern void	lprint(const char *fmt, ...);
#ifdef _DEBUG
extern void	dump_packet(void *dat, int n);
#endif

#ifndef _MSC_VER
extern char	*strerror(int);
#endif

/* stats.c */
extern void	mbufstats(void);
extern void	sockstats(void);
extern void	ipstats(void);
extern void	icmpstats(void);
extern void	tcpstats(void);
extern void	udpstats(void);


#endif	/*SLIRP_PRIVATE_H*/
