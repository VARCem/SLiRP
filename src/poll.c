#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#ifdef _WIN32
# include <windows.h>
# ifdef _MSC_VER
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
#else
# include <sys/ioctl.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
#endif
#include "slirp.h"
#include "debug.h"              // merge with slirp.h
#include "mbuf.h"
#include "if.h"
#include "socket.h"
#include "mbuf.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"


#define CONN_CANFSEND(so) (((so)->so_state & (SS_FCANTSENDMORE|SS_ISFCONNECTED)) == SS_ISFCONNECTED)
#define CONN_CANFRCV(so) (((so)->so_state & (SS_FCANTRCVMORE|SS_ISFCONNECTED)) == SS_ISFCONNECTED)
#define UPD_NFDS(x) if (nfds < (x)) nfds = (x)


u_int		curtime;
fd_set		*global_readfds,
		*global_writefds,
		*global_xfds;


/* curtime kept to an accuracy of 1ms */
static void
updtime(void)
{
#ifdef _WIN32
    struct _timeb tb;

    _ftime(&tb);
    curtime = (u_int)tb.time * (u_int)1000;
    curtime += (u_int)tb.millitm;
#else
    struct timeval tt;

    gettimeofday(&tt, 0);

    curtime = (u_int)tt.tv_sec * (u_int)1000;
    curtime += (u_int)tt.tv_usec / (u_int)1000;

    if ((tt.tv_usec % 1000) >= 500)
	curtime++;
#endif
}


static int
poll_fill(slirp_t *slirp, int *pnfds, fd_set *rfds, fd_set *wfds, fd_set *xfds)
{
    struct SLIRPsocket *so, *so_next;
    int nfds, tmo, tmp_time;

    /* fail safe */
    global_readfds = NULL;
    global_writefds = NULL;
    global_xfds = NULL;
    
    nfds = *pnfds;

    /* First, TCP sockets. */
    slirp->do_slowtimo = 0;
    if (slirp->link_up) {
	/* 
	 * *_slowtimo needs calling if there are IP fragments
	 * in the fragment queue, or there are TCP connections active
	 */
	slirp->do_slowtimo = ((tcb.so_next != &tcb) ||
	       ((struct ipasfrag *)&ipq != (struct ipasfrag *)ipq.next));

	for (so = tcb.so_next; (so != &tcb); so = so_next) {
		so_next = so->so_next;

		/* See if we need a tcp_fasttimo. */
		if (so->so_tcpcb != 0) {
			/* This is to prevent a common lockup. */
			if (slirp->time_fasttimo == 0 && so->so_tcpcb->t_flags & TF_DELACK)
				/* Flag when we want a fasttimo */
				slirp->time_fasttimo = curtime;
		}

		/*
		 * NOFDREF can include still connecting to local-host,
		 * newly socreated() sockets etc. Don't want to select
		 * these.
 		 */
		if (so->so_state & SS_NOFDREF || so->s == -1)
			continue;

		/* Set for reading sockets which are accepting. */
		if (so->so_state & SS_FACCEPTCONN) {
			FD_SET(so->s, rfds);
			UPD_NFDS(so->s);
			continue;
		}

		/* Set for writing sockets which are connecting. */
		if (so->so_state & SS_ISFCONNECTING) {
			FD_SET(so->s, wfds);
			UPD_NFDS(so->s);
			continue;
		}
		
		/*
		 * Set for writing if we are connected, can send more,
		 * and we have something to send.
		 */
		if (CONN_CANFSEND(so) && so->so_rcv.sb_cc) {
			FD_SET(so->s, wfds);
			UPD_NFDS(so->s);
		}
			
		/*
		 * Set for reading (and urgent data) if we are
		 * connected, can receive more, and we have room
		 * for it XXX /2 ?
		 */
		if (CONN_CANFRCV(so) && (so->so_snd.sb_cc < (so->so_snd.sb_datalen/2))) {
			FD_SET(so->s, rfds);
			FD_SET(so->s, xfds);
			UPD_NFDS(so->s);
		}
	}
		
	/* UDP sockets. */
	for (so = udb.so_next; so != &udb; so = so_next) {
		so_next = so->so_next;

		/* See if it's timed out. */
		if (so->so_expire) {
			if (so->so_expire <= curtime) {
				udp_detach(so);
				continue;
			} else
				slirp->do_slowtimo = 1; /* Let socket expire */
		}

		/*
		 * When UDP packets are received from over the
		 * link, they're sendto()'d straight away, so
		 * no need for setting for writing
		 * Limit the number of packets queued by this session
		 * to 4.  Note that even though we try and limit this
		 * to 4 packets, the session could have more queued
		 * if the packets needed to be fragmented
		 * (XXX <= 4 ?)
		 */
		if ((so->so_state & SS_ISFCONNECTED) && so->so_queued <= 4) {
			FD_SET(so->s, rfds);
			UPD_NFDS(so->s);
		}
	}
    }
	
    /* Setup timeout to use minimum CPU usage, especially when idle. */
    tmo = -1;

    /*
     * If a slowtimo is needed, set timeout to 5ms from the last
     * slow timeout. If a fast timeout is needed, set timeout within
     * 2ms of when it was requested.
     */
#define SLOW_TIMO 5
#define FAST_TIMO 2
    if (slirp->do_slowtimo) {
	tmo = (SLOW_TIMO - (curtime - slirp->last_slowtimo)) * 1000;
	if (tmo < 0)
		tmo = 0;
	else if (tmo > (SLOW_TIMO * 1000))
		tmo = SLOW_TIMO * 1000;

	/* Can only fasttimo if we also slowtimo */
	if (slirp->time_fasttimo) {
		tmp_time = (FAST_TIMO - (curtime - slirp->time_fasttimo)) * 1000;
		if (tmp_time < 0)
			tmp_time = 0;

		/* Choose the smallest of the 2 */
		if (tmp_time < tmo)
			tmo = tmp_time;
	}
    }
    *pnfds = nfds;

    /*
     * Adjust the timeout to make the minimum timeout
     * 2ms (XXX?) to lessen the CPU load
     */
    if (tmo < (FAST_TIMO * 1000))
	tmo = FAST_TIMO * 1000;

    return tmo;
}	


static void
poll_select(slirp_t *slirp, fd_set *rfds, fd_set *wfds, fd_set *xfds)
{
    struct SLIRPsocket *so, *so_next;
    int ret;

    global_readfds = rfds;
    global_writefds = wfds;
    global_xfds = xfds;

    /* Update time */
    updtime();

    /* See if anything has timed out. */
    if (slirp->link_up) {
	if (slirp->time_fasttimo && ((curtime - slirp->time_fasttimo) >= FAST_TIMO)) {
		tcp_fasttimo();
		slirp->time_fasttimo = 0;
	}

	if (slirp->do_slowtimo && ((curtime - slirp->last_slowtimo) >= SLOW_TIMO)) {
		ip_slowtimo();
		tcp_slowtimo();
		slirp->last_slowtimo = curtime;
	}
    }

    /* Check sockets. */
    if (slirp->link_up) {
	/* Check TCP sockets. */
	for (so = tcb.so_next; so != &tcb; so = so_next) {
		so_next = so->so_next;

		/*
		 * FD_ISSET is meaningless on these sockets
		 * (and they can crash the program)
		 */
		if (so->so_state & SS_NOFDREF || so->s == -1)
			   continue;

		/*
		 * Check for URG data
		 * This will soread as well, so no need to
		 * test for readfds below if this succeeds
		 */
		if (FD_ISSET(so->s, xfds))
			sorecvoob(so);

		/* Check sockets for reading. */
		else if (FD_ISSET(so->s, rfds)) {
			/* Check for incoming connections. */
			if (so->so_state & SS_FACCEPTCONN) {
				tcp_connect(so);
				continue;
			} /* else */
			ret = soread(so);

			/* Output it if we read something */
			if (ret > 0)
				tcp_output(sototcpcb(so));
		}

		/* Check sockets for writing. */
		if (FD_ISSET(so->s, wfds)) {
			/* Check for non-blocking, still-connecting sockets. */
			if (so->so_state & SS_ISFCONNECTING) {
				/* Connected */
				so->so_state &= ~SS_ISFCONNECTING;
			}
		}
		
		/*
		 * Now UDP sockets.
		 * Incoming packets are sent straight away, they're not
		 * buffered. Incoming UDP data isn't buffered either.
		 */
		for (so = udb.so_next; so != &udb; so = so_next) {
			so_next = so->so_next;
			
			if (so->s != -1 && FD_ISSET(so->s, rfds)) {
                            sorecvfrom(so);
                        }
		}
	}
    }
	
    /* See if we can start outputting. */
    if (if_queued && slirp->link_up)
	if_start();

    /* Clear global file descriptor sets. */
    global_readfds = NULL;
    global_writefds = NULL;
    global_xfds = NULL;
}


/* API: poll an instance for any work. */
int
slirp_poll(slirp_t *slirp)
{
    fd_set rfds, wfds, xfds;
    struct timeval tv;
    int ret, nfds, tmo;

    /* Create a list of all open sockets. */
    nfds = -1;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);
    tmo = poll_fill(slirp, &nfds, &rfds, &wfds, &xfds);
    if (tmo < 0)
	tmo = 500;

    tv.tv_sec = 0;
    tv.tv_usec = tmo;

    /* Now wait for something to happen, or at most 'tmo' usec. */
    ret = select(nfds+1, &rfds, &wfds, &xfds, &tv);
    if (ret < 0)
	return -1;

    /* If something happened, let SLiRP handle it. */
    if (ret >= 0)
	poll_select(slirp, &rfds, &wfds, &xfds);

    return ret;
}
