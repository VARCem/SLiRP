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


void
arp_input(const uint8_t *pkt, int pkt_len)
{
    uint8_t arp_reply[ETH_HLEN + sizeof(struct arphdr)];
    struct ethhdr *eh = (struct ethhdr *)pkt;
    struct arphdr *ah = (struct arphdr *)(pkt + ETH_HLEN);
    struct ethhdr *reh = (struct ethhdr *)arp_reply;
    struct arphdr *rah = (struct arphdr *)(arp_reply + ETH_HLEN);
#ifdef USE_REDIR
    struct ex_list *ex_ptr;
#endif
    int ar_op;

    ar_op = ntohs(ah->ar_op);
    switch (ar_op) {
	case ARPOP_REQUEST:
		if (! memcmp(ah->ar_tip, &special_addr, 3)) {
			if (ah->ar_tip[3] == CTL_ROUTER ||
			    ah->ar_tip[3] == CTL_SERVER)
				goto arp_ok;
#ifdef USE_REDIR
			for (ex_ptr = exec_list; ex_ptr; ex_ptr = ex_ptr->ex_next) {
				if (ex_ptr->ex_addr == ah->ar_tip[3])
					goto arp_ok;
			}
#endif
			return;

arp_ok:
			/* XXX: make an ARP request for the client address */
			memcpy(client_macaddr, eh->h_source, ETH_ALEN);

			/* ARP request for alias/dns mac address */
			memcpy(reh->h_dest, pkt + ETH_ALEN, ETH_ALEN);
			memcpy(reh->h_source, special_macaddr, ETH_ALEN - 1);
			reh->h_source[5] = ah->ar_tip[3];
			reh->h_proto = htons(ETH_P_ARP);

			rah->ar_hrd = htons(1);
			rah->ar_pro = htons(ETH_P_IP);
			rah->ar_hln = ETH_ALEN;
			rah->ar_pln = 4;
			rah->ar_op = htons(ARPOP_REPLY);
			memcpy(rah->ar_sha, reh->h_source, ETH_ALEN);
			memcpy(rah->ar_sip, ah->ar_tip, 4);
			memcpy(rah->ar_tha, ah->ar_sha, ETH_ALEN);
			memcpy(rah->ar_tip, ah->ar_sip, 4);
			slirp_output(arp_reply, sizeof(arp_reply));
		}
		break;

	default:
		break;
    }
}
