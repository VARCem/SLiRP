/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */
#ifndef SLIRP_SOCKET_H
# define SLIRP_SOCKET_H


#define SO_EXPIRE	240000
#define SO_EXPIREFAST	10000


#define sbflush(sb)	sbdrop((sb),(sb)->sb_cc)
#define sbspace(sb)	((sb)->sb_datalen - (sb)->sb_cc)


struct sbuf {
    u_int	sb_cc;		/* actual chars in buffer */
    u_int	sb_datalen;	/* Length of data  */
    char	*sb_wptr;	/* write pointer. points to where the next
				 * bytes should be written in the sbuf */
    char	*sb_rptr;	/* read pointer. points to where the next
				 * byte should be read from the sbuf */
    char	*sb_data;	/* Actual data */
};


/*
 * Our socket structure
 */
struct SLIRPsocket {
    struct SLIRPsocket *so_next,
			*so_prev;      /* For a linked list of sockets */

    int s;                           /* The actual socket */

			/* XXX union these with not-yet-used sbuf params */
    struct SLIRPmbuf *so_m;	           /* Pointer to the original SYN packet,
				    * for non-blocking connect()'s, and
				    * PING reply's */
    struct tcpiphdr *so_ti;	   /* Pointer to the original ti within
				    * so_mconn, for non-blocking connections */
    int so_urgc;
    struct in_addr so_faddr;	   /* foreign host table entry */
    struct in_addr so_laddr;	   /* local host table entry */
    uint16_t so_fport;		   /* foreign port */
    uint16_t so_lport;		   /* local port */

    uint8_t	so_iptos;		/* Type of service */
    uint8_t	so_emu;			/* Is the socket emulated? */

    uint8_t	so_type;		/* Type of socket, UDP or TCP */
    int		so_state;		/* internal state flags SS_*, below */

    struct 	tcpcb *so_tcpcb;/* pointer to TCP protocol control block */
    u_int	so_expire;		/* When the socket will expire */

    int		so_queued;	/* Number of packets queued from this socket */
    int		so_nqueued;		/* Number of packets queued in a row
					 * Used to determine when to
					 * "downgrade" a session from fastq
					 * to batchq */

    struct sbuf	so_rcv;			/* Receive buffer */
    struct sbuf	so_snd;			/* Send buffer */
    void	*extra;			/* Extra pointer */
};


/*
 * Socket state bits. (peer means the host on the Internet,
 * local host means the host on the other end of the modem)
 */
#define SS_NOFDREF		0x001	/* No fd reference */

#define SS_ISFCONNECTING	0x002	/* Socket is connecting to peer (non-blocking connect()'s) */
#define SS_ISFCONNECTED		0x004	/* Socket is connected to peer */
#define SS_FCANTRCVMORE		0x008	/* Socket can't receive more from peer (for half-closes) */
#define SS_FCANTSENDMORE	0x010	/* Socket can't send more to peer (for half-closes) */
/* #define SS_ISFDISCONNECTED	0x020*/	/* Socket has disconnected from peer, in 2MSL state */
#define SS_FWDRAIN		0x040	/* We received a FIN, drain data and set SS_FCANTSENDMORE */

#define SS_CTL			0x080
#define SS_FACCEPTCONN		0x100	/* Socket is accepting connections from a host on the internet */
#define SS_FACCEPTONCE		0x200	/* If set, the SS_FACCEPTCONN socket will die after one accept */

extern struct SLIRPsocket tcb;


#if defined(DECLARE_IOVEC) && !defined(HAVE_READV)
struct iovec {
    char	*iov_base;
    size_t	iov_len;
};
#endif


extern void	sbfree(struct sbuf *);
extern void	sbdrop(struct sbuf *, int);
extern void	sbreserve(struct sbuf *, int);
extern void	sbappend(struct SLIRPsocket *, struct SLIRPmbuf *);
extern void	sbappendsb(struct sbuf *, struct SLIRPmbuf *);
extern void	sbcopy(struct sbuf *, int, int, char *);

extern void	so_init(void);
extern struct SLIRPsocket	*solookup(struct SLIRPsocket *,
					  struct in_addr, u_int,
					  struct in_addr, u_int);
extern struct SLIRPsocket	*socreate(void);
extern void	sofree(struct SLIRPsocket *);
extern int	soread(struct SLIRPsocket *);
extern void	sorecvoob(struct SLIRPsocket *);
extern int	sosendoob(struct SLIRPsocket *);
extern int	sowrite(struct SLIRPsocket *);
extern void	sorecvfrom(struct SLIRPsocket *);
extern int	sosendto(struct SLIRPsocket *, struct SLIRPmbuf *);
extern struct SLIRPsocket	*solisten(u_int, uint32_t, u_int, int);
extern void	sorwakeup(struct SLIRPsocket *);
extern void	sowwakeup(struct SLIRPsocket *);
extern void	soisfconnecting(register struct SLIRPsocket *);
extern void	soisfconnected(register struct SLIRPsocket *);
extern void	sofcantrcvmore(struct SLIRPsocket *);
extern void	sofcantsendmore(struct SLIRPsocket *);
extern void	soisfdisconnected(struct SLIRPsocket *);
extern void	sofwdrain(struct SLIRPsocket *);


#endif	/*SLIRP_SOCKET_H*/
