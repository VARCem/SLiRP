#ifndef SLIRP_H
# define SLIRP_H

# include "config.h"


#define SLIRP_VERSION	"1.0.9"

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


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int		instance;
    int		link_up;

    /* poll.c */
    int		do_slowtimo;
    u_int	time_fasttimo,
		last_slowtimo;
} slirp_t;

typedef void (*log_func_t)(slirp_t *, const char *, ...);


extern char	slirp_hostname[32];
extern char	slirp_domainname[128];

extern uint8_t	client_macaddr[6];
extern const uint8_t special_macaddr[];
extern int	link_up;
extern u_int	curtime;

#ifdef HAVE_SOCKET_H
extern fd_set	*global_readfds, *global_writefds, *global_xfds;
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


/* stats.c */
extern void	mbufstats(void);
extern void	sockstats(void);
extern void	ipstats(void);
extern void	icmpstats(void);
extern void	tcpstats(void);
extern void	udpstats(void);

extern int	slirp_version(char *bufp, int max_len);

extern slirp_t	*slirp_init(void);
extern void	slirp_close(slirp_t *);

extern int	slirp_poll(slirp_t *slirp);

#ifdef USE_REDIR
extern int	slirp_redir(int is_udp, int host_port, 
			    struct in_addr guest_addr, int guest_port);
extern int	slirp_add_exec(int do_pty, const char *args,
			       int addr_low_byte, int guest_port);
#endif

extern int	slirp_can_output(void);
extern void	slirp_output(const uint8_t *pkt, int pkt_len);
extern void	slirp_input(const uint8_t *pkt, int pkt_len);

#ifdef __cplusplus
}
#endif


#endif
