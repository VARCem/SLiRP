/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
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
 *	@(#)tcp_subr.c	8.1 (Berkeley) 6/10/93
 * tcp_subr.c,v 1.5 1994/10/08 22:39:58 phk Exp
 */
#ifdef _WIN32
# include <windows.h>
# ifdef _DEBUG
#  undef errno
#  define errno (WSAGetLastError())
# endif
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
# ifdef _DEBUG
#  include <errno.h>
# endif
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define HAVE_INADDR_H
#include "private.h"
#include "slirp.h"
#include "misc.h"
#include "socket.h"
#include "mbuf.h"
#include "if.h"
#include "ip.h"
#include "tcp.h"


/*
 * Changes and additions relating to SLiRP
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */


/* patchable/settable parameters for tcp */
int 	tcp_mssdflt = TCP_MSS;
int 	tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;
int	tcp_do_rfc1323 = 0;	/* Don't do rfc1323 performance enhancements */
int	tcp_rcvspace;	/* You may want to change this */
int	tcp_sndspace;	/* Keep small if you have an error prone link */


/* Set the socket's type of service field. */
static const struct tos_t tcptos[] = {
  { 0,	20,	IPTOS_THROUGHPUT,	0		},  /* ftp data */
  { 21,	21,	IPTOS_LOWDELAY,		EMU_FTP		},  /* ftp control */
  { 0,	23,	IPTOS_LOWDELAY,		0		},  /* telnet */
  { 0,	80,	IPTOS_THROUGHPUT,	0		},  /* WWW */
  { 0,	513,	IPTOS_LOWDELAY,		EMU_RLOGIN|EMU_NOCONNECT}, /* rlogin */
  { 0,	514,	IPTOS_LOWDELAY,		EMU_RSH|EMU_NOCONNECT},    /* shell */
  { 0,	544,	IPTOS_LOWDELAY,		EMU_KSH		},  /* kshell */
  { 0,	543,	IPTOS_LOWDELAY,		0		},  /* klogin */
  { 0,	6667,	IPTOS_THROUGHPUT,	EMU_IRC		},  /* IRC */
  { 0,	6668,	IPTOS_THROUGHPUT,	EMU_IRC		},  /* IRC undernet */
  { 0,	7070,	IPTOS_LOWDELAY,		EMU_REALAUDIO	},  /* RealAudio */
  { 0,	113,	IPTOS_LOWDELAY,		EMU_IDENT	},  /* identd */
  { 0,	0,	0, 0}
};

		
/* Return TOS according to the above table. */
uint8_t
tcp_tos(struct SLIRPsocket *so)
{
#ifdef USE_REDIR
    struct emu_t *emup;
#endif
    int i = 0;
	
    while (tcptos[i].tos) {
	if ((tcptos[i].fport && (ntohs(so->so_fport) == tcptos[i].fport)) ||
	    (tcptos[i].lport && (ntohs(so->so_lport) == tcptos[i].lport))) {
		so->so_emu = tcptos[i].emu;
		return tcptos[i].tos;
	}
	i++;
    }
	
#ifdef USE_REDIR
    /* Nope, lets see if there's a user-added one */
    for (emup = tcpemu; emup; emup = emup->next) {
	if ((emup->fport && (ntohs(so->so_fport) == emup->fport)) ||
	    (emup->lport && (ntohs(so->so_lport) == emup->lport))) {
		so->so_emu = emup->emu;
		return emup->tos;
	}
    }
#endif
	
    return 0;
}


/* TCP initialization. */
void
tcp_init(void)
{
    tcp_iss = 1;		/* wrong */
    tcb.so_next = tcb.so_prev = &tcb;

    /* tcp_rcvspace = our Window we advertise to the remote */
    tcp_rcvspace = TCP_RCVSPACE;
    tcp_sndspace = TCP_SNDSPACE;

    /* Make sure tcp_sndspace is at least 2*MSS */
    if (tcp_sndspace < (int)(2*(min(if_mtu, if_mru) - sizeof(struct tcpiphdr))))
	tcp_sndspace = (int)(2*(min(if_mtu, if_mru) - sizeof(struct tcpiphdr)));
}


/*
 * Create template to be used to send tcp packets on a connection.
 * Call after host entry created, fills
 * in a skeletal tcp/ip header, minimizing the amount of work
 * necessary when the connection is used.
 */
/* struct tcpiphdr * */
void
tcp_template(struct tcpcb *tp)
{
    struct SLIRPsocket *so = tp->t_socket;
    struct tcpiphdr *n = &tp->t_template;

    n->ti_next = n->ti_prev = 0;
    n->ti_x1 = 0;
    n->ti_pr = IPPROTO_TCP;
    n->ti_len = htons(sizeof (struct tcpiphdr) - sizeof (struct ip));
    n->ti_src = so->so_faddr;
    n->ti_dst = so->so_laddr;
    n->ti_sport = so->so_fport;
    n->ti_dport = so->so_lport;

    n->ti_seq = 0;
    n->ti_ack = 0;
    n->ti_x2 = 0;
    n->ti_off = 5;
    n->ti_flags = 0;
    n->ti_win = 0;
    n->ti_sum = 0;
    n->ti_urp = 0;
}


/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == 0, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection tp->t_template.  If flags are given
 * then we send a message back to the TCP which originated the
 * segment ti, and discard the SLIRPmbuf containing it and any other
 * attached SLIRPmbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 */
void
tcp_respond(struct tcpcb *tp, struct tcpiphdr *ti, struct SLIRPmbuf *m, tcp_seq ack, tcp_seq seq, int flags)
{
    register int tlen;
    int win = 0;

    DEBUG_CALL("tcp_respond");
    DEBUG_ARG("tp = %lx", (long)tp);
    DEBUG_ARG("ti = %lx", (long)ti);
    DEBUG_ARG("m = %lx", (long)m);
    DEBUG_ARG("ack = %u", ack);
    DEBUG_ARG("seq = %u", seq);
    DEBUG_ARG("flags = %x", flags);

    if (tp)
	win = sbspace(&tp->t_socket->so_rcv);
    if (m == 0) {
	if ((m = m_get()) == NULL)
		return;
#ifdef TCP_COMPAT_42
	tlen = 1;
#else
	tlen = 0;
#endif
	m->m_data += if_maxlinkhdr;
	*mtod(m, struct tcpiphdr *) = *ti;
	ti = mtod(m, struct tcpiphdr *);
	flags = TH_ACK;
    } else {
	/* 
	 * ti points into m so the next line is just making
	 * the SLIRPmbuf point to ti
	 */
	m->m_data = (SLIRPcaddr_t)ti;

	m->m_len = sizeof (struct tcpiphdr);
	tlen = 0;
#define xchg(a,b,type) { type t; t=a; a=b; b=t; }
	xchg(ti->ti_dst.s_addr, ti->ti_src.s_addr, uint32_t);
	xchg(ti->ti_dport, ti->ti_sport, uint16_t);
#undef xchg
    }
    ti->ti_len = htons((u_short)(sizeof (struct tcphdr) + tlen));
    tlen += sizeof (struct tcpiphdr);
    m->m_len = tlen;

    ti->ti_next = ti->ti_prev = 0;
    ti->ti_x1 = 0;
    ti->ti_seq = htonl(seq);
    ti->ti_ack = htonl(ack);
    ti->ti_x2 = 0;
    ti->ti_off = sizeof (struct tcphdr) >> 2;
    ti->ti_flags = flags;
    if (tp)
	ti->ti_win = htons((uint16_t) (win >> tp->rcv_scale));
    else
	ti->ti_win = htons((uint16_t)win);
    ti->ti_urp = 0;
    ti->ti_sum = 0;
    ti->ti_sum = cksum(m, tlen);
    ((struct ip *)ti)->ip_len = tlen;

    if (flags & TH_RST) 
	((struct ip *)ti)->ip_ttl = MAXTTL;
    else 
	((struct ip *)ti)->ip_ttl = ip_defttl;

    (void) ip_output((struct SLIRPsocket *)0, m);
}


/*
 * Create a new TCP control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.
 */
struct tcpcb *
tcp_newtcpcb(struct SLIRPsocket *so)
{
    struct tcpcb *tp;
	
    tp = (struct tcpcb *)malloc(sizeof(*tp));
    if (tp == NULL)
	return ((struct tcpcb *)0);

    memset((char *) tp, 0, sizeof(struct tcpcb));
    tp->seg_next = tp->seg_prev = (tcpiphdrp_32)tp;
    tp->t_maxseg = tcp_mssdflt;

    tp->t_flags = tcp_do_rfc1323 ? (TF_REQ_SCALE|TF_REQ_TSTMP) : 0;
    tp->t_socket = so;

    /*
     * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
     * rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
     * reasonable initial retransmit time.
     */
    tp->t_srtt = TCPTV_SRTTBASE;
    tp->t_rttvar = tcp_rttdflt * PR_SLOWHZ << 2;
    tp->t_rttmin = TCPTV_MIN;

    TCPT_RANGESET(tp->t_rxtcur, 
		  ((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
		  TCPTV_MIN, TCPTV_REXMTMAX);

    tp->snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
    tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
    tp->t_state = TCPS_CLOSED;

    so->so_tcpcb = tp;

    return (tp);
}


/*
 * Drop a TCP connection, reporting the specified error.
 * If connection is synchronized, then send a RST to peer.
 */
struct tcpcb *
tcp_drop(struct tcpcb *tp, int err) 
{
    DEBUG_CALL("tcp_drop");
    DEBUG_ARG("tp = %lx", (long)tp);
    DEBUG_ARG("errno = %d", errno);

    if (TCPS_HAVERCVDSYN(tp->t_state)) {
	tp->t_state = TCPS_CLOSED;
	(void) tcp_output(tp);
	tcpstat.tcps_drops++;
    } else
	tcpstat.tcps_conndrops++;

#if 0
    if (errno == ETIMEDOUT && tp->t_softerror)
	errno = tp->t_softerror;

    so->so_error = errno;
#endif

    return (tcp_close(tp));
}


/*
 * Close a TCP control block:
 *	discard all space held by the tcp
 *	discard internet protocol block
 *	wake up any sleepers
 */
struct tcpcb *
tcp_close(struct tcpcb *tp)
{
    struct tcpiphdr *t;
    struct SLIRPsocket *so = tp->t_socket;
    struct SLIRPmbuf *m;

    DEBUG_CALL("tcp_close");
    DEBUG_ARG("tp = %lx", (long )tp);

    /* free the reassembly queue, if any */
    t = (struct tcpiphdr *) tp->seg_next;
    while (t != (struct tcpiphdr *)tp) {
	t = (struct tcpiphdr *)t->ti_next;
	m = (struct SLIRPmbuf *) REASS_MBUF((struct tcpiphdr *)t->ti_prev);
	remque_32((struct tcpiphdr *) t->ti_prev);
	m_freem(m);
    }

    /* It's static */
#if 0
    if (tp->t_template)
	(void) m_free(dtom(tp->t_template));

    free(tp, M_PCB);
#endif
    free(tp);

    so->so_tcpcb = 0;
    soisfdisconnected(so);

    /* clobber input socket cache if we're closing the cached connection */
    if (so == tcp_last_so)
	tcp_last_so = &tcb;
    closesocket(so->s);

    sbfree(&so->so_rcv);
    sbfree(&so->so_snd);
    sofree(so);
    tcpstat.tcps_closed++;

    return ((struct tcpcb *)0);
}


void
tcp_drain(void)
{
    /* XXX */
}


/*
 * When a source quench is received, close congestion window
 * to one segment.  We will gradually open it again as we proceed.
 */
#ifdef notdef
void
tcp_quench(int i, int errno)
{
    struct tcpcb *tp = intotcpcb(inp);

    if (tp)
	tp->snd_cwnd = tp->t_maxseg;
}
#endif


/*
 * TCP protocol interface to socket abstraction.
 */

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
void
tcp_sockclosed(struct tcpcb *tp)
{

	DEBUG_CALL("tcp_sockclosed");
	DEBUG_ARG("tp = %lx", (long)tp);
	
	switch (tp->t_state) {

	case TCPS_CLOSED:
	case TCPS_LISTEN:
	case TCPS_SYN_SENT:
		tp->t_state = TCPS_CLOSED;
		tp = tcp_close(tp);
		break;

	case TCPS_SYN_RECEIVED:
	case TCPS_ESTABLISHED:
		tp->t_state = TCPS_FIN_WAIT_1;
		break;

	case TCPS_CLOSE_WAIT:
		tp->t_state = TCPS_LAST_ACK;
		break;
	}
/*	soisfdisconnecting(tp->t_socket); */
	if (tp && tp->t_state >= TCPS_FIN_WAIT_2)
		soisfdisconnected(tp->t_socket);
	if (tp)
		tcp_output(tp);
}

/* 
 * Connect to a host on the Internet
 * Called by tcp_input
 * Only do a connect, the tcp fields will be set in tcp_input
 * return 0 if there's a result of the connect,
 * else return -1 means we're still connecting
 * The return value is almost always -1 since the socket is
 * nonblocking.  Connect returns after the SYN is sent, and does 
 * not wait for ACK+SYN.
 */
int tcp_fconnect(struct SLIRPsocket *so)
{
  int ret=0;
  
  DEBUG_CALL("tcp_fconnect");
  DEBUG_ARG("so = %lx", (long )so);

  if( (ret=so->s=socket(AF_INET,SOCK_STREAM,0)) >= 0) {
    int opt, s=so->s;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    fd_nonblock(s);
    opt = 1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char *)&opt,sizeof(opt ));
    opt = 1;
    setsockopt(s,SOL_SOCKET,SO_OOBINLINE,(char *)&opt,sizeof(opt ));
    
    addr.sin_family = AF_INET;
    if ((so->so_faddr.s_addr & htonl(0xffffff00)) == special_addr.s_addr) {
      /* It's an alias */
      switch(ntohl(so->so_faddr.s_addr) & 0xff) {
      case CTL_SERVER:
	addr.sin_addr = dns_addr;
	break;
      case CTL_ROUTER:
      default:
	addr.sin_addr = loopback_addr;
	break;
      }
    } else
      addr.sin_addr = so->so_faddr;
    addr.sin_port = so->so_fport;
    
    DEBUG_MISC((dfd, " connect()ing, addr.sin_port=%d, "
		"addr.sin_addr.s_addr=%.16s\n", 
		ntohs(addr.sin_port), inet_ntoa(addr.sin_addr)));
    /* We don't care what port we get */
    ret = connect(s,(struct sockaddr *)&addr,sizeof (addr));
    
    /*
     * If it's not in progress, it failed, so we just return 0,
     * without clearing SS_NOFDREF
     */
    soisfconnecting(so);
  }

  return(ret);
}

/*
 * Accept the socket and connect to the local-host
 * 
 * We have a problem. The correct thing to do would be
 * to first connect to the local-host, and only if the
 * connection is accepted, then do an accept() here.
 * But, a) we need to know who's trying to connect 
 * to the socket to be able to SYN the local-host, and
 * b) we are already connected to the foreign host by
 * the time it gets to accept(), so... We simply accept
 * here and SYN the local-host.
 */ 
void
tcp_connect(struct SLIRPsocket *inso)
{
	struct SLIRPsocket *so;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct tcpcb *tp;
	int s, opt;

	DEBUG_CALL("tcp_connect");
	DEBUG_ARG("inso = %lx", (long)inso);
	
	/*
	 * If it's an SS_ACCEPTONCE socket, no need to socreate()
	 * another socket, just use the accept() socket.
	 */
	if (inso->so_state & SS_FACCEPTONCE) {
		/* FACCEPTONCE already have a tcpcb */
		so = inso;
	} else {
		if ((so = socreate()) == NULL) {
			/* If it failed, get rid of the pending connection */
			closesocket(accept(inso->s,(struct sockaddr *)&addr,&addrlen));
			return;
		}
		if (tcp_attach(so) < 0) {
			free(so); /* NOT sofree */
			return;
		}
		so->so_laddr = inso->so_laddr;
		so->so_lport = inso->so_lport;
	}
	
	(void) tcp_mss(sototcpcb(so), 0);

	if ((s = accept(inso->s,(struct sockaddr *)&addr,&addrlen)) < 0) {
		tcp_close(sototcpcb(so)); /* This will sofree() as well */
		return;
	}
	fd_nonblock(s);
	opt = 1;
	setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char *)&opt,sizeof(int));
	opt = 1;
	setsockopt(s,SOL_SOCKET,SO_OOBINLINE,(char *)&opt,sizeof(int));
	opt = 1;
	setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(char *)&opt,sizeof(int));
	
	so->so_fport = addr.sin_port;
	so->so_faddr = addr.sin_addr;
	/* Translate connections from localhost to the real hostname */
	if (so->so_faddr.s_addr == 0 || so->so_faddr.s_addr == loopback_addr.s_addr)
	   so->so_faddr = router_addr;
	
	/* Close the accept() socket, set right state */
	if (inso->so_state & SS_FACCEPTONCE) {
		closesocket(so->s); /* If we only accept once, close the accept() socket */
		so->so_state = SS_NOFDREF; /* Don't select it yet, even though we have an FD */
					   /* if it's not FACCEPTONCE, it's already NOFDREF */
	}
	so->s = s;
	
	so->so_iptos = tcp_tos(so);
	tp = sototcpcb(so);

	tcp_template(tp);
	
	/* Compute window scaling to request.  */
/*	while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
 *		(TCP_MAXWIN << tp->request_r_scale) < so->so_rcv.sb_hiwat)
 *		tp->request_r_scale++;
 */

/*	soisconnecting(so); */ /* NOFDREF used instead */
	tcpstat.tcps_connattempt++;
	
	tp->t_state = TCPS_SYN_SENT;
	tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
	tp->iss = tcp_iss; 
	tcp_iss += TCP_ISSINCR/2;
	tcp_sendseqinit(tp);
	tcp_output(tp);
}

/*
 * Attach a TCPCB to a socket.
 */
int
tcp_attach(struct SLIRPsocket *so)
{
	if ((so->so_tcpcb = tcp_newtcpcb(so)) == NULL)
	   return -1;
	
	insque(so, &tcb);

	return 0;
}


/*
 * Do misc. config of SLiRP while its running.
 * Return 0 if this connections is to be closed, 1 otherwise,
 * return 2 if this is a command-line connection
 */
int
tcp_ctl(struct SLIRPsocket *so)
{
	struct sbuf *sb = &so->so_snd;
#if 0
        struct SLIRPsocket *tmpso;
#endif
#ifdef USE_REDIR
 	struct ex_list *ex_ptr;
	int do_pty;
#endif
	int command;
	
	DEBUG_CALL("tcp_ctl");
	DEBUG_ARG("so = %lx", (long )so);
	
#if 0
	/*
	 * Check if they're authorised
	 */
	if (ctl_addr.s_addr && (ctl_addr.s_addr == -1 || (so->so_laddr.s_addr != ctl_addr.s_addr))) {
		sb->sb_cc = sprintf(sb->sb_wptr,"Error: Permission denied.\r\n");
		sb->sb_wptr += sb->sb_cc;
		return 0;
	}
#endif	
	command = (ntohl(so->so_faddr.s_addr) & 0xff);
	
	switch(command) {
	default: /* Check for exec's */
#ifdef USE_REDIR
		/*
		 * Check if it's pty_exec
		 */
		for (ex_ptr = exec_list; ex_ptr; ex_ptr = ex_ptr->ex_next) {
			if (ex_ptr->ex_fport == so->so_fport &&
			    command == ex_ptr->ex_addr) {
				do_pty = ex_ptr->ex_pty;
				goto do_exec;
			}
		}
#endif
		
		/*
		 * Nothing bound..
		 */
		/* tcp_fconnect(so); */
		
		/* FALLTHROUGH */
	case CTL_ROUTER:
	  sb->sb_cc = sprintf(sb->sb_wptr,
			      "Error: No application configured.\r\n");
	  sb->sb_wptr += sb->sb_cc;
	  return(0);

#ifdef USE_REDIR
	do_exec:
		DEBUG_MISC((dfd, " executing %s \n",ex_ptr->ex_exec));
		return(fork_exec(so, ex_ptr->ex_exec, do_pty));
#endif
		
#if 0
	case CTL_CMD:
	   for (tmpso = tcb.so_next; tmpso != &tcb; tmpso = tmpso->so_next) {
	     if (tmpso->so_emu == EMU_CTL && 
		 !(tmpso->so_tcpcb? 
		   (tmpso->so_tcpcb->t_state & (TCPS_TIME_WAIT|TCPS_LAST_ACK))
		   :0)) {
	       /* Ooops, control connection already active */
	       sb->sb_cc = sprintf(sb->sb_wptr,"Sorry, already connected.\r\n");
	       sb->sb_wptr += sb->sb_cc;
	       return 0;
	     }
	   }
	   so->so_emu = EMU_CTL;
	   ctl_password_ok = 0;
	   sb->sb_cc = sprintf(sb->sb_wptr, "Slirp command-line ready (type \"help\" for help).\r\nSlirp> ");
	   sb->sb_wptr += sb->sb_cc;
	   do_echo=-1;
	   return(2);
#endif
	}
}
