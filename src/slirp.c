#ifdef _WIN32
# include <winsock2.h>        /* on top otherwise, it'll pull in winsock1 */
#else
# include <netinet/in.h>
# include <arpa/inet.h>
# include <unistd.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "private.h"
#include "slirp.h"
#include "host.h"
#include "mbuf.h"
#include "if.h"
#include "socket.h"
#include "arp.h"
#include "ip.h"
#ifdef USE_REDIR
# include "redir.h"
#endif
#include "version.h"


/* Our actual addresses. */
char		slirp_hostname[32];
char		slirp_domainname[128];
struct in_addr	our_addr;		/* host IP address */
struct in_addr	dns_addr;		/* host DNS server */
struct in_addr	loopback_addr;		/* host loopback address */

/* Our virtual addresses. */
const uint8_t	special_macaddr[ETH_ALEN] = { 
    0x52, 0x54, 0x00, 0x12, 0x35, 0x00	/* virtual MAC address. */
};
struct in_addr	special_addr;		/* virtual IP address */
struct in_addr	router_addr;		/* virtual address alias for router */
struct in_addr	server_addr;		/* virtual address alias for server */
//struct in_addr alias_addr;		/* virtual address alias for host */
//struct in_addr myaddr;


uint8_t		client_macaddr[ETH_ALEN];	/* guest's MAC address */
int		link_up;
u_int		detach_time;
u_int		detach_wait = 600000;	/* 10 minutes */


/* API: return the library version. */
_SLIRP_API int
slirp_version(char *bufp, int max_len)
{
    char temp[128];

    sprintf(temp, "%s", LIB_VERSION_4);

    strncpy(bufp, temp, max_len);

    return(strlen(temp));
}


/* API: initialize an instance for use. */
_SLIRP_API slirp_t *
slirp_init(void)
{
    slirp_t *slirp;
#if 0
    char *sp;
#endif

    /* First of all, initialize any host stuff. */
    if (host_init() != 0) return(NULL);

    /* Allocate an instance, and initialize it. */
    slirp = (slirp_t *)malloc(sizeof(slirp_t));
    if (slirp == NULL)
	return(NULL);
    memset(slirp, 0x00, sizeof(slirp_t));
    slirp->instance = 1;
    slirp->link_up = 1;

    if_init(slirp);
    ip_init();

    /* Initialize mbufs *after* setting the MTU. */
    m_init();

    /* Set default addresses. */
    memset(&our_addr, 0x00, sizeof(our_addr));
    memset(&dns_addr, 0x00, sizeof(dns_addr));
    inet_aton("127.0.0.1", &loopback_addr);

    /* Get local hostname and domainname. */
    memset(slirp_hostname, 0, sizeof(slirp_hostname));
    memset(slirp_domainname, 0, sizeof(slirp_domainname));
#if 0
    if (! gethostname(temp, sizeof(temp) - 1)) {
	/* We got the hostname. Do an IP lookup on it. */
	hp = gethostbyname(temp);
	if (hp != NULL)
		strncpy(temp, hp->h_name, sizeof(temp));

	sp = strchr(temp, '.');
	if (sp != NULL)
		*sp++ = '\0';

	strncpy(slirp_hostname, temp, sizeof(slirp_hostname));
	strcat(slirp_hostname, "_slirp");

	if (sp != NULL) {
		strncpy(slirp_domainname, sp, sizeof(slirp_domainname));
		strcat(slirp_hostname, ".");
		strcat(slirp_hostname, slirp_domainname);
	}
    }
#endif

    /* Get the host's network information. */
    if (host_get_info(&dns_addr, slirp_hostname, slirp_domainname) < 0) {
	free(slirp);
	return NULL;
    }

    /*
     * Initialize the virtual network.
     *
     * The default network configuration is:
     *
     * Network:		10.0.2.0/24 (255.255.255.0)
     * Router:		10.0.2.1
     * DHCP/DNS:	10.0.2.2
     * Local:		10.0.2.15	(this may be removed later)
     */
    inet_aton(CTL_SPECIAL, &special_addr);
    router_addr.s_addr = special_addr.s_addr | htonl(CTL_ROUTER);
    server_addr.s_addr = special_addr.s_addr | htonl(CTL_SERVER);
#ifdef CTL_LOCAL
    myaddr.s_addr = special_addr.s_addr | htonl(CTL_LOCAL);
#endif

#ifdef USE_REDIR
    redir_init();
#endif

    return slirp;
}


/* API: close an instance, and release all resources. */
_SLIRP_API void
slirp_close(slirp_t *slirp)
{
    if (slirp != NULL)
	free(slirp);

    /* Close down any host stuff. */
    host_close();
}


/* API: receive a packet from the inbound queue. */
_SLIRP_API int
slirp_recv(slirp_t *slirp, uint8_t *bufp)
{
    return 0;
}


/* API: send a packet to the outbound interface. */
_SLIRP_API int
slirp_send(slirp_t *slirp, uint8_t *bufp, int pkt_len)
{
    return 0;
}


_SLIRP_API void
slirp_input(const uint8_t *pkt, int pkt_len)
{
    struct SLIRPmbuf *m;
    int proto;

    if (pkt_len < ETH_HLEN)
	return;
    
    proto = (pkt[12] << 8) | pkt[13];
    switch(proto) {
	case ETH_P_ARP:
		arp_input(pkt, pkt_len);
		break;

	case ETH_P_IP:
		m = m_get();
		if (!m)
			return;
		/* Note: we add to align the IP header */
		m->m_len = pkt_len + 2;
		memcpy(m->m_data + 2, pkt, pkt_len);

		m->m_data += 2 + ETH_HLEN;
		m->m_len -= 2 + ETH_HLEN;

		ip_input(m);
		break;

	default:
		break;
    }
}


/* Output the IP packet to the client device. */
void
if_encap(const uint8_t *ip_data, int ip_data_len)
{
    uint8_t buff[1600];
    struct ethhdr *eh = (struct ethhdr *)buff;

    if (ip_data_len + ETH_HLEN > sizeof(buff))
	return;

    /* Set the client device's MAC address. */
    memcpy(eh->h_dest, client_macaddr, ETH_ALEN);

    /* Set our MAC address. */
    memcpy(eh->h_source, special_macaddr, ETH_ALEN - 1);
    eh->h_source[5] = CTL_SERVER;

    /* This works for IP, but not NetWare and such. */
    eh->h_proto = htons(ETH_P_IP);

    /* Now copy in the data to be sent. */
    memcpy(buff + ETH_HLEN, ip_data, ip_data_len);
    ip_data_len += ETH_HLEN;

    slirp_output(buff, ip_data_len);
}


static void
purgesocks(void)
{
    struct SLIRPsocket *so;

    for (so = tcb.so_next; so != &tcb; so = so->so_next)
	closesocket(so->s);	//close the socket
}


void
slirp_exit(int exit_status)
{
    DEBUG_CALL("slirp_exit");
    DEBUG_ARG("exit_status = %d", exit_status);

    if (dostats) {
	ipstats();
	tcpstats();
	udpstats();
	icmpstats();
	mbufstats();
	sockstats();
	fclose(dfd);
    }
	
    purgesocks();
}


/* Needed by SLiRP library. */
_SLIRP_API void
slirp_output(const uint8_t *pkt, int pkt_len)
{
#if 0
    struct queuepacket *qp;

    if (slirpq != NULL) {
	qp = (struct queuepacket *)mem_alloc(sizeof(struct queuepacket));
	qp->len = pkt_len;
	memcpy(qp->data, pkt, pkt_len);
	QueueEnter(slirpq, qp);
    }
#endif
}


/* Needed by SLiRP library. */
_SLIRP_API int
slirp_can_output(void)
{
//    return((slirp != NULL)?1:0);
    return 0;
}
