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
 *	@(#)udp_usrreq.c	8.4 (Berkeley) 1/21/94
 * udp_usrreq.c,v 1.4 1994/10/02 17:48:45 phk Exp
 */
#ifdef _WIN32
# include <windows.h>
# undef errno
# define errno (WSAGetLastError())
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <errno.h>
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
#include "ip_icmp.h"
#include "udp.h"
#include "bootp.h"


/*
 * Changes and additions relating to SLiRP
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */


struct udpstat udpstat;
struct SLIRPsocket *udp_last_so = &udb;
struct SLIRPsocket udb;

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */
#ifndef	COMPAT_42
int	udpcksum = 1;
#else
int	udpcksum = 0;		/* XXX */
#endif


static const struct tos_t udptos[] = {
  { 0,		53,	IPTOS_LOWDELAY,	0		},	/* DNS */
  { 517,	517,	IPTOS_LOWDELAY,	EMU_TALK	},	/* talk */
  { 518,	518,	IPTOS_LOWDELAY,	EMU_NTALK	},	/* ntalk */
  { 0,		7648,	IPTOS_LOWDELAY,	EMU_CUSEEME	},	/* Cu-Seeme */
  { 0,		0,	0,		0		}
};


uint8_t
udp_tos(struct SLIRPsocket *so)
{
    int i = 0;
	
    while (udptos[i].tos) {
	if ((udptos[i].fport && ntohs(so->so_fport) == udptos[i].fport) ||
	    (udptos[i].lport && ntohs(so->so_lport) == udptos[i].lport)) {
	    	so->so_emu = udptos[i].emu;
		return udptos[i].tos;
	}
	i++;
    }
	
    return 0;
}


void
udp_init(void)
{
    udb.so_next = udb.so_prev = &udb;
}


/* m->m_data  points at ip packet header 
 * m->m_len   length ip packet 
 * ip->ip_len length data (IPDU)
 */
void
udp_input(struct SLIRPmbuf *m, int iphlen)
{
    struct SLIRPsocket *so, *tmp;
#if 0
    struct SLIRPmbuf *opts = 0;
#endif
    struct ip save_ip; 
    struct udphdr *uh;
    struct ip *ip;
    int len;

    udpstat.udps_ipackets++;

    /*
     * Strip IP options, if any; should skip this,
     * make available to user, and use on returned packets,
     * but we don't yet have a way to check the checksum
     * with options still present.
     */
    if (iphlen > sizeof(struct ip)) {
	ip_stripoptions(m, (struct SLIRPmbuf *)0);
	iphlen = sizeof(struct ip);
    }

    /* Get IP and UDP header together in first SLIRPmbuf. */
    ip = mtod(m, struct ip *);
    uh = (struct udphdr *)((SLIRPcaddr_t)ip + iphlen);

    /*
     * Make SLIRPmbuf data length reflect UDP length.
     * If not enough data to reflect UDP length, drop.
     */
    len = ntohs((uint16_t)uh->uh_ulen);
    if (ip->ip_len != len) {
	if (len > ip->ip_len) {
		udpstat.udps_badlen++;
		goto bad;
	}
	m_adj(m, len - ip->ip_len);
	ip->ip_len = len;
    }
	
    /*
     * Save a copy of the IP header in case we want restore it
     * for sending an ICMP error message in response.
     */
    save_ip = *ip; 
    save_ip.ip_len+= iphlen;         /* tcp_input subtracts this */

    /* Checksum extended UDP header and data. */
    if (udpcksum && uh->uh_sum) {
	((struct ipovly *)ip)->ih_next = 0;
	((struct ipovly *)ip)->ih_prev = 0;
	((struct ipovly *)ip)->ih_x1 = 0;
	((struct ipovly *)ip)->ih_len = uh->uh_ulen;

	/* keep uh_sum for ICMP reply
	 * uh->uh_sum = cksum(m, len + sizeof (struct ip)); 
 	 * if (uh->uh_sum) { 
 	 */
	if (cksum(m, len + sizeof(struct ip))) {
		udpstat.udps_badsum++;
		goto bad;
	}
    }

    /* Handle DHCP/BOOTP. */
    if (ntohs(uh->uh_dport) == BOOTP_SERVER) {
	bootp_input(m);
	goto bad;
    }

#ifdef NEED_TFTP
    /* Handle TFTP. */
    if (ntohs(uh->uh_dport) == TFTP_SERVER) {
	tftp_input(m);
	goto bad;
    }
#endif

    /* Locate pcb for datagram. */
    so = udp_last_so;
    if (so->so_lport != uh->uh_sport ||
	so->so_laddr.s_addr != ip->ip_src.s_addr) {
	for (tmp = udb.so_next; tmp != &udb; tmp = tmp->so_next) {
		if (tmp->so_lport == uh->uh_sport &&
		    tmp->so_laddr.s_addr == ip->ip_src.s_addr) {
			tmp->so_faddr.s_addr = ip->ip_dst.s_addr;
			tmp->so_fport = uh->uh_dport;
			so = tmp;
			break;
		}
	}

	if (tmp != &udb) {
	  udpstat.udpps_pcbcachemiss++;
	  udp_last_so = so;
	} else
	  so = NULL;
    }

    if (so == NULL) {
	/* If there's no socket for this packet, create one. */
	if ((so = socreate()) == NULL) goto bad;

	if (udp_attach(so) == -1) {
		DEBUG_MISC((dfd," udp_attach errno = %d-%s\n", 
			    errno,strerror(errno)));
		sofree(so);
		goto bad;
	}

	/* Set up fields. */
#if 0
	udp_last_so = so;
#endif
	so->so_laddr = ip->ip_src;
	so->so_lport = uh->uh_sport;

	if ((so->so_iptos = udp_tos(so)) == 0)
		so->so_iptos = ip->ip_tos;

	/*
 	 * XXXXX Here, check if it's in udpexec_list,
	 * and if it is, do the fork_exec() etc.
	 */
    }

    so->so_faddr = ip->ip_dst; /* XXX */
    so->so_fport = uh->uh_dport; /* XXX */

    iphlen += sizeof(struct udphdr);
    m->m_len -= iphlen;
    m->m_data += iphlen;

#ifdef NEED_EMU
    /* Now we sendto() the packet. */
    if (so->so_emu)
	udp_emu(so, m);
#endif

    if (sosendto(so,m) == -1) {
	m->m_len += iphlen;
	m->m_data -= iphlen;
	*ip = save_ip;
	DEBUG_MISC((dfd,"udp tx errno = %d-%s\n",errno,strerror(errno)));
	icmp_error(m, ICMP_UNREACH,ICMP_UNREACH_NET, 0,strerror(errno));  
    }

    m_free(so->so_m);		/* used for ICMP if error on sorecvfrom */

    /* restore the orig SLIRPmbuf packet */
    m->m_len += iphlen;
    m->m_data -= iphlen;
    *ip = save_ip;
    so->so_m = m;		/* ICMP backup */

    return;
bad:
    m_freem(m);
#if 0
    if (opts) m_freem(opts);
#endif
}


int
udp_output2(struct SLIRPsocket *so, struct SLIRPmbuf *m, 
            struct sockaddr_in *saddr, struct sockaddr_in *daddr, int iptos)
{
    struct udpiphdr *ui;
    int error = 0;

    /* Adjust for header. */
    m->m_data -= sizeof(struct udpiphdr);
    m->m_len += sizeof(struct udpiphdr);
	
    /*
     * Fill in SLIRPmbuf with extended UDP header
     * and addresses and length put into network format.
     */
    ui = mtod(m, struct udpiphdr *);
    ui->ui_next = ui->ui_prev = 0;
    ui->ui_x1 = 0;
    ui->ui_pr = IPPROTO_UDP;
    ui->ui_len = htons(m->m_len - sizeof(struct ip)); /* + sizeof (struct udphdr)); */
    /* XXXXX Check for from-one-location sockets, or from-any-location sockets */
    ui->ui_src = saddr->sin_addr;
    ui->ui_dst = daddr->sin_addr;
    ui->ui_sport = saddr->sin_port;
    ui->ui_dport = daddr->sin_port;
    ui->ui_ulen = ui->ui_len;

    /* Stuff checksum and output datagram. */
    ui->ui_sum = 0;
    if (udpcksum) {
	if ((ui->ui_sum = cksum(m, /* sizeof (struct udpiphdr) + */ m->m_len)) == 0)
		ui->ui_sum = 0xffff;
    }
    ((struct ip *)ui)->ip_len = m->m_len;

    ((struct ip *)ui)->ip_ttl = ip_defttl;
    ((struct ip *)ui)->ip_tos = iptos;
	
    udpstat.udps_opackets++;
	
    error = ip_output(so, m);
	
    return(error);
}


int
udp_output(struct SLIRPsocket *so, struct SLIRPmbuf *m, 
           struct sockaddr_in *addr)
{
    struct sockaddr_in saddr, daddr;

    saddr = *addr;
    if ((so->so_faddr.s_addr & htonl(0xffffff00)) == special_addr.s_addr) {
        saddr.sin_addr.s_addr = so->so_faddr.s_addr;
        if ((so->so_faddr.s_addr & htonl(0x000000ff)) == htonl(0xff))
            saddr.sin_addr.s_addr = router_addr.s_addr;
    }
    daddr.sin_addr = so->so_laddr;
    daddr.sin_port = so->so_lport;
    
    return udp_output2(so, m, &saddr, &daddr, so->so_iptos);
}


int
udp_attach(struct SLIRPsocket *so)
{
    struct sockaddr_in addr;
	
    if ((so->s = socket(AF_INET,SOCK_DGRAM,0)) != -1) {
	/*
	 * Here, we bind() the socket.  Although not really needed
	 * (sendto() on an unbound socket will bind it), it's done
	 * here so that emulation of ytalk etc. don't have to do it
	 */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(so->s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int lasterrno = errno;
		closesocket(so->s);
		so->s = -1;
#ifdef _WIN32
		WSASetLastError(lasterrno);
#else
		errno = lasterrno;
#endif
	} else {
		/* success, insert in queue */
		so->so_expire = curtime + SO_EXPIRE;
		insque(so,&udb);
	}
    }

    return(so->s);
}


void
udp_detach(struct SLIRPsocket *so)
{
    closesocket(so->s);

#if 0
    if (so->so_m)
	/* done by sofree */
	m_free(so->so_m);
#endif

    sofree(so);
}


#ifdef USE_REDIR
struct SLIRPsocket *
udp_listen(u_int port, uint32_t laddr, u_int lport, int flags)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    struct SLIRPsocket *so;
    int opt = 1;

    if ((so = socreate()) == NULL) {
	free(so);
	return NULL;
    }
    so->s = socket(AF_INET,SOCK_DGRAM,0);
    so->so_expire = curtime + SO_EXPIRE;
    insque(so,&udb);

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = port;

    if (bind(so->s, (struct sockaddr *)&addr, addrlen) < 0) {
	udp_detach(so);
	return NULL;
    }
    setsockopt(so->s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(int));
#if 0
    setsockopt(so->s, SOL_SOCKET, SO_OOBINLINE, (char *)&opt, sizeof(int));
#endif

    getsockname(so->s,(struct sockaddr *)&addr,&addrlen);
    so->so_fport = addr.sin_port;
    if (addr.sin_addr.s_addr == 0 || addr.sin_addr.s_addr == loopback_addr.s_addr)
	so->so_faddr = alias_addr;
    else
	so->so_faddr = addr.sin_addr;

    so->so_lport = lport;
    so->so_laddr.s_addr = laddr;
    if (flags != SS_FACCEPTONCE)
	so->so_expire = 0;

    so->so_state = SS_ISFCONNECTED;

    return so;
}
#endif	/*USE_REDIR*/
