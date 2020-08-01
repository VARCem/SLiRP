/*
 * QEMU BOOTP/DHCP server
 * 
 * Copyright (c) 2004 Fabrice Bellard
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifdef _WIN32
# include <windows.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define HAVE_INADDR_H
#include "private.h"
#include "slirp.h"
#include "mbuf.h"
#include "if.h"
#include "arp.h"
#include "ip.h"
#include "udp.h"
#include "bootp.h"


#define NB_ADDR		16
#define START_ADDR	100
#define LEASE_TIME	(24 * 3600)


typedef struct {
    uint8_t	allocated;
    uint8_t	macaddr[ETH_ALEN];
} BOOTPClient;


static BOOTPClient	clients[NB_ADDR];
static const uint8_t	rfc1533_cookie[] = { RFC1533_COOKIE };


static char *
pr_mac(const uint8_t *mac)
{
    static char buff[20];

    sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return(buff);
}


static BOOTPClient *
get_new_addr(const struct in_addr *ciaddr, struct in_addr *paddr)
{
    BOOTPClient *bc;
    int i;

    for (i = 0; i < NB_ADDR; i++) {
	bc = &clients[i];
        if (! bc->allocated) {
		bc->allocated = 1;
		paddr->s_addr = htonl(ntohl(special_addr.s_addr) | (i + START_ADDR));
		return bc;
	}
    }

    return NULL;
}


static BOOTPClient *
find_addr(struct in_addr *paddr, const uint8_t *macaddr)
{
    BOOTPClient *bc;
    int i;

    for (i = 0; i < NB_ADDR; i++) {
	bc = &clients[i];

        if (! memcmp(macaddr, bc->macaddr, 6)) {
		bc = &clients[i];
		bc->allocated = 1;
		paddr->s_addr = htonl(ntohl(special_addr.s_addr) | (i + START_ADDR));
		return bc;
	}
    }

    return NULL;
}


static int
dhcp_decode(const uint8_t *buf, int size)
{
    const uint8_t *p, *p_end;
    int msg_type, len, tag;

    msg_type = 0;    

    p = buf;
    p_end = buf + size;
    if (size < 5)
        return(msg_type);

    if (memcmp(p, rfc1533_cookie, 4) != 0)
        return(msg_type);

    p += 4;
    while (p < p_end) {
	tag = p[0];

	if (tag == RFC1533_PAD) {
		p++; 
	} else if (tag == RFC1533_END) {
		break;
	} else {
		p++;
		if (p >= p_end)
			break;
		len = *p++;

		switch(tag) {
			case RFC2132_MSG_TYPE:
				if (len >= 1)
					msg_type = p[0];
				break;

			default:
				break;
		}
		p += len;
	}
    }

    return msg_type;
}


static void
bootp_reply(struct bootp_t *bp)
{
    BOOTPClient *bc;
    struct SLIRPmbuf *m;
    struct bootp_t *rbp;
    struct sockaddr_in addr, saddr, daddr;
    struct in_addr xaddr;
    int msg_type, val;
    uint8_t *q;

    /* Decode the Vendor area to guesstimate the protocol and message type. */
    msg_type = dhcp_decode(bp->bp_vend, DHCP_OPT_LEN);
    
    if (msg_type == 0) {
	/* Force reply for old BOOTP clients */
	msg_type = BOOTPREQUEST;
	lprint("BOOTP: BOOTP REQUEST from %s\n", pr_mac(bp->bp_hwaddr));
    } else if (msg_type == DHCPDISCOVER) {
	lprint("BOOTP: DHCP DISCOVER from %s\n", pr_mac(bp->bp_hwaddr));
    } else if (msg_type == DHCPREQUEST) {
	lprint("BOOTP: DHCP REQUEST from %s\n", pr_mac(bp->bp_hwaddr));
    } else {
	lprint("BOOTP: invalid message %d from %s\n", pr_mac(bp->bp_hwaddr));
	return;
    }

    /* Make sure we support this topology. */
    if (bp->bp_htype != 1 || bp->bp_hlen != ETH_ALEN) {
	lprint("BOOTP: unsupported topology %d or hlen %d from %s\n",
			bp->bp_htype, bp->bp_hlen, pr_mac(bp->bp_hwaddr));
	return;
    }

    /* Save the client MAC address. */
    memcpy(client_macaddr, bp->bp_hwaddr, bp->bp_hlen);

    /* Reset client IP address. */
    memset(&addr, 0x00, sizeof(addr));
    addr.sin_port = htons(BOOTP_CLIENT);

    /* Create return packet. */
    if ((m = m_get()) == NULL) {
	lprint("BOOTP: out of memory for reply to %s\n",
		 pr_mac(bp->bp_hwaddr));
	return;
    }
    m->m_data += if_maxlinkhdr;
    rbp = (struct bootp_t *)m->m_data;
    m->m_data += sizeof(struct udpiphdr);
    memset(rbp, 0x00, sizeof(struct bootp_t));

    switch(msg_type) {
	case BOOTPREQUEST:
		/*
		 * If client already has an address, see if we can
		 * re-assign that to it. Otherwise, allocate a new
		 * address for the client.
		 */
		bc = find_addr(&daddr.sin_addr, bp->bp_hwaddr);
		if (! bc)
			bc = get_new_addr(&bp->bp_ciaddr, &daddr.sin_addr);
		if (! bc) {
			lprint("BOOTP: out of slots for %s\n",
				 pr_mac(bp->bp_hwaddr));
			return;
		}
		memcpy(bc->macaddr, bp->bp_hwaddr, bp->bp_hlen);
		addr.sin_addr.s_addr = 0xffffffff;
		break;

	case DHCPDISCOVER:
new_addr:
		bc = get_new_addr(&bp->bp_ciaddr, &daddr.sin_addr);
		if (! bc) {
			lprint("DHCP: out of slots for %s\n",
				 pr_mac(bp->bp_hwaddr));
			return;
		}
		memcpy(bc->macaddr, bp->bp_hwaddr, bp->bp_hlen);
		break;

	default:
		/* Find the client's MAC address. */
		bc = find_addr(&daddr.sin_addr, bp->bp_hwaddr);
		if (! bc) {
			/*
			 * If client not found, could be a Windows
			 * machine trying to keep its current (but
			 * expired) address. FIXME: wrong!!  --FvK
			 */
			goto new_addr;
		}
		break;
    }

    /* Set up my IP address. */
    saddr.sin_addr.s_addr = htonl(ntohl(special_addr.s_addr) | CTL_SERVER);
    saddr.sin_port = htons(BOOTP_SERVER);

    /* Target address is either broadcast, or the client IP address. */
    if (addr.sin_addr.s_addr == 0)
	addr.sin_addr.s_addr = daddr.sin_addr.s_addr;

    /* Set up the reply packet. */
    rbp->bp_op = BOOTP_REPLY;
    rbp->bp_xid = bp->bp_xid;
    rbp->bp_htype = bp->bp_htype;
    rbp->bp_hlen = bp->bp_hlen;
    memcpy(rbp->bp_hwaddr, bp->bp_hwaddr, bp->bp_hlen);

    rbp->bp_ciaddr = bp->bp_ciaddr;	/* client current IP address */
    rbp->bp_yiaddr = daddr.sin_addr;	/* client new IP address */
    rbp->bp_siaddr = saddr.sin_addr;	/* server IP address */

    /* Set up the RFC1533 cookie to indicate standard Vendor Extensions. */
    q = rbp->bp_vend;
    memcpy(q, rfc1533_cookie, 4);
    q += 4;

    if (msg_type == DHCPDISCOVER) {
	*q++ = RFC2132_MSG_TYPE;
	*q++ = 1;
	*q++ = DHCPOFFER;
    }

    if (msg_type == DHCPREQUEST) {
	*q++ = RFC2132_MSG_TYPE;
	*q++ = 1;
	*q++ = DHCPACK;
    }

    if (msg_type == DHCPDISCOVER || msg_type == DHCPREQUEST) {
        *q++ = RFC2132_SRV_ID;
        *q++ = 4;
        memcpy(q, &saddr.sin_addr, 4);
        q += 4;

        *q++ = RFC2132_LEASE_TIME;
        *q++ = 4;
        val = htonl(LEASE_TIME);
        memcpy(q, &val, 4);
        q += 4;
    }

    if (msg_type == BOOTPREQUEST || msg_type == DHCPDISCOVER || msg_type == DHCPREQUEST) {
        *q++ = RFC1533_NETMASK;
        *q++ = 4;
        *q++ = 0xff;	/* FIXME: wrong, but works for now --FvK */
        *q++ = 0xff;
        *q++ = 0xff;
        *q++ = 0x00;
        
        *q++ = RFC1533_GATEWAY;
        *q++ = 4;
        xaddr.s_addr = htonl(ntohl(special_addr.s_addr) | CTL_ROUTER);
        memcpy(q, &xaddr, 4);
        q += 4;
        
        *q++ = RFC1533_DNS;
        *q++ = 4;
        xaddr.s_addr = htonl(ntohl(special_addr.s_addr) | CTL_SERVER);
        memcpy(q, &xaddr, 4);
        q += 4;

        if (slirp_hostname[0]) {
            val = strlen(slirp_hostname);
            *q++ = RFC1533_HOSTNAME;
            *q++ = val;
            memcpy(q, slirp_hostname, val);
            q += val;
        }

	/* End of option list. */
	*q++ = RFC1533_END;
    }
    
    m->m_len = sizeof(struct bootp_t) - 
        sizeof(struct ip) - sizeof(struct udphdr);
lprint("BOOTP: sending reply=%d to %s\n", m->m_len, inet_ntoa(addr.sin_addr));
    udp_output2(NULL, m, &saddr, &addr, IPTOS_LOWDELAY);
}


void
bootp_input(struct SLIRPmbuf *m)
{
    struct bootp_t *bp = mtod(m, struct bootp_t *);

    switch(bp->bp_op) {
	case BOOTP_REQUEST:
		bootp_reply(bp);
		break;

	default:
		lprint("BOOTP: invalid opcode %d (ignored)\n", bp->bp_op);
		break;
    }
}
