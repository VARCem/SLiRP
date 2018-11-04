/*
 * Copyright (c) 1982, 1986, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp_var.h	8.3 (Berkeley) 4/10/94
 * tcp_var.h,v 1.3 1994/08/21 05:27:39 paul Exp
 */

#ifndef _TCP_VAR_H_
#define _TCP_VAR_H_

#include "tcpip.h"
#include "tcp_timer.h"

#ifdef __amd64__
typedef uintptr_t tcpiphdrp_32;
#else
#if SIZEOF_CHAR_P == 4
 typedef struct tcpiphdr *tcpiphdrp_32;
#else
 typedef uint32_t tcpiphdrp_32;
#endif
#endif

/*
 * Tcp control block, one per tcp; fields:
 */
struct tcpcb {
	tcpiphdrp_32 seg_next;	/* sequencing queue */
	tcpiphdrp_32 seg_prev;
	short	t_state;		/* state of this connection */
	short	t_timer[TCPT_NTIMERS];	/* tcp timers */
	short	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	short	t_rxtcur;		/* current retransmit value */
	short	t_dupacks;		/* consecutive dup acks recd */
	uint16_t	t_maxseg;		/* maximum segment size */
	char	t_force;		/* 1 if forcing out a byte */
	uint16_t	t_flags;
#define	TF_ACKNOW	0x0001		/* ack peer immediately */
#define	TF_DELACK	0x0002		/* ack, but try to delay it */
#define	TF_NODELAY	0x0004		/* don't delay packets to coalesce */
#define	TF_NOOPT	0x0008		/* don't use tcp options */
#define	TF_SENTFIN	0x0010		/* have sent FIN */
#define	TF_REQ_SCALE	0x0020		/* have/will request window scaling */
#define	TF_RCVD_SCALE	0x0040		/* other side has requested scaling */
#define	TF_REQ_TSTMP	0x0080		/* have/will request timestamps */
#define	TF_RCVD_TSTMP	0x0100		/* a timestamp was received in SYN */
#define	TF_SACK_PERMIT	0x0200		/* other side said I could SACK */

	/* Make it static  for now */
/*	struct	tcpiphdr *t_template;	/ * skeletal packet for transmit */
	struct	tcpiphdr t_template;

	struct	SLIRPsocket *t_socket;		/* back pointer to socket */
/*
 * The following fields are used as in the protocol specification.
 * See RFC783, Dec. 1981, page 21.
 */
/* send sequence variables */
	tcp_seq	snd_una;		/* send unacknowledged */
	tcp_seq	snd_nxt;		/* send next */
	tcp_seq	snd_up;			/* send urgent pointer */
	tcp_seq	snd_wl1;		/* window update seg seq number */
	tcp_seq	snd_wl2;		/* window update seg ack number */
	tcp_seq	iss;			/* initial send sequence number */
	uint32_t snd_wnd;		/* send window */
/* receive sequence variables */
	uint32_t rcv_wnd;		/* receive window */
	tcp_seq	rcv_nxt;		/* receive next */
	tcp_seq	rcv_up;			/* receive urgent pointer */
	tcp_seq	irs;			/* initial receive sequence number */
/*
 * Additional variables for this implementation.
 */
/* receive variables */
	tcp_seq	rcv_adv;		/* advertised window */
/* retransmit variables */
	tcp_seq	snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
/* congestion control (for slow start, source quench, retransmit after loss) */
	uint32_t snd_cwnd;		/* congestion-controlled window */
	uint32_t snd_ssthresh;		/* snd_cwnd size threshold for
					 * for slow start exponential to
					 * linear switch
					 */
/*
 * transmit timing stuff.  See below for scale of srtt and rttvar.
 * "Variance" is actually smoothed difference.
 */
	short	t_idle;			/* inactivity time */
	short	t_rtt;			/* round trip time */
	tcp_seq	t_rtseq;		/* sequence number being timed */
	short	t_srtt;			/* smoothed round-trip time */
	short	t_rttvar;		/* variance in round-trip time */
	uint16_t	t_rttmin;		/* minimum rtt allowed */
	uint32_t max_sndwnd;		/* largest window peer has offered */

/* out-of-band data */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
#define	TCPOOB_HAVEDATA	0x01
#define	TCPOOB_HADDATA	0x02
	short	t_softerror;		/* possible error not yet reported */

/* RFC 1323 variables */
	u_char	snd_scale;		/* window scaling for send window */
	u_char	rcv_scale;		/* window scaling for recv window */
	u_char	request_r_scale;	/* pending window scaling */
	u_char	requested_s_scale;
	uint32_t	ts_recent;		/* timestamp echo data */
	uint32_t	ts_recent_age;		/* when last updated */
	tcp_seq	last_ack_sent;

};

#define	sototcpcb(so)	((so)->so_tcpcb)

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP_RTT_SCALE		8	/* multiplier for srtt; 3 bits frac. */
#define	TCP_RTT_SHIFT		3	/* shift for srtt; 3 bits frac. */
#define	TCP_RTTVAR_SCALE	4	/* multiplier for rttvar; 2 bits */
#define	TCP_RTTVAR_SHIFT	2	/* multiplier for rttvar; 2 bits */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This macro assumes that the value of TCP_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */
#define	TCP_REXMTVAL(tp) \
	(((tp)->t_srtt >> TCP_RTT_SHIFT) + (tp)->t_rttvar)

/* XXX
 * We want to avoid doing m_pullup on incoming packets but that
 * means avoiding dtom on the tcp reassembly code.  That in turn means
 * keeping an mbuf pointer in the reassembly queue (since we might
 * have a cluster).  As a quick hack, the source & destination
 * port numbers (which are no longer needed once we've located the
 * tcpcb) are overlayed with an mbuf pointer.
 */
#ifdef __amd64__
typedef uintptr_t mbufp_32;
#else
#if SIZEOF_CHAR_P == 4
typedef struct SLIRPmbuf *mbufp_32;
#else
typedef uint32_t mbufp_32;
#endif
#endif
#define REASS_MBUF(ti) (*(mbufp_32 *)&((ti)->ti_t))

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct tcpstat {
	uint32_t	tcps_connattempt;	/* connections initiated */
	uint32_t	tcps_accepts;		/* connections accepted */
	uint32_t	tcps_connects;		/* connections established */
	uint32_t	tcps_drops;		/* connections dropped */
	uint32_t	tcps_conndrops;		/* embryonic connections dropped */
	uint32_t	tcps_closed;		/* conn. closed (includes drops) */
	uint32_t	tcps_segstimed;		/* segs where we tried to get rtt */
	uint32_t	tcps_rttupdated;	/* times we succeeded */
	uint32_t	tcps_delack;		/* delayed acks sent */
	uint32_t	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	uint32_t	tcps_rexmttimeo;	/* retransmit timeouts */
	uint32_t	tcps_persisttimeo;	/* persist timeouts */
	uint32_t	tcps_keeptimeo;		/* keepalive timeouts */
	uint32_t	tcps_keepprobe;		/* keepalive probes sent */
	uint32_t	tcps_keepdrops;		/* connections dropped in keepalive */

	uint32_t	tcps_sndtotal;		/* total packets sent */
	uint32_t	tcps_sndpack;		/* data packets sent */
	uint32_t	tcps_sndbyte;		/* data bytes sent */
	uint32_t	tcps_sndrexmitpack;	/* data packets retransmitted */
	uint32_t	tcps_sndrexmitbyte;	/* data bytes retransmitted */
	uint32_t	tcps_sndacks;		/* ack-only packets sent */
	uint32_t	tcps_sndprobe;		/* window probes sent */
	uint32_t	tcps_sndurg;		/* packets sent with URG only */
	uint32_t	tcps_sndwinup;		/* window update-only packets sent */
	uint32_t	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	uint32_t	tcps_rcvtotal;		/* total packets received */
	uint32_t	tcps_rcvpack;		/* packets received in sequence */
	uint32_t	tcps_rcvbyte;		/* bytes received in sequence */
	uint32_t	tcps_rcvbadsum;		/* packets received with ccksum errs */
	uint32_t	tcps_rcvbadoff;		/* packets received with bad offset */
/*	uint32_t	tcps_rcvshort;	*/	/* packets received too short */
	uint32_t	tcps_rcvduppack;	/* duplicate-only packets received */
	uint32_t	tcps_rcvdupbyte;	/* duplicate-only bytes received */
	uint32_t	tcps_rcvpartduppack;	/* packets with some duplicate data */
	uint32_t	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	uint32_t	tcps_rcvoopack;		/* out-of-order packets received */
	uint32_t	tcps_rcvoobyte;		/* out-of-order bytes received */
	uint32_t	tcps_rcvpackafterwin;	/* packets with data after window */
	uint32_t	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
	uint32_t	tcps_rcvafterclose;	/* packets rcvd after "close" */
	uint32_t	tcps_rcvwinprobe;	/* rcvd window probe packets */
	uint32_t	tcps_rcvdupack;		/* rcvd duplicate acks */
	uint32_t	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
	uint32_t	tcps_rcvackpack;	/* rcvd ack packets */
	uint32_t	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
	uint32_t	tcps_rcvwinupd;		/* rcvd window update packets */
/*	uint32_t	tcps_pawsdrop;	*/	/* segments dropped due to PAWS */
	uint32_t	tcps_predack;		/* times hdr predict ok for acks */
	uint32_t	tcps_preddat;		/* times hdr predict ok for data pkts */
	uint32_t	tcps_socachemiss;	/* tcp_last_so misses */
	uint32_t	tcps_didnuttin;		/* Times tcp_output didn't do anything XXX */
};

extern struct	tcpstat tcpstat;	/* tcp statistics */
extern uint32_t	tcp_now;		/* for RFC 1323 timestamps */

#endif
