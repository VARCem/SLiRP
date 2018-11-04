/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */
#ifndef SLIRP_IF_H
# define SLIRP_IF_H


/* Needed for FreeBSD */
#undef if_mtu
extern int	if_mtu;
extern int	if_mru;	/* MTU and MRU */
extern int	if_maxlinkhdr;
extern int	if_queued;	/* Number of packets queued so far */


/* Interface statistics */
struct slirp_ifstats {
    u_int out_pkts;		/* Output packets */
    u_int out_bytes;		/* Output bytes */
    u_int out_errpkts;		/* Output Error Packets */
    u_int out_errbytes;		/* Output Error Bytes */
    u_int in_pkts;		/* Input packets */
    u_int in_bytes;		/* Input bytes */
    u_int in_errpkts;		/* Input Error Packets */
    u_int in_errbytes;		/* Input Error Bytes */

    u_int bytes_saved;		/* Number of bytes that compression "saved" */
				/* ie: #bytes not sent over the link
				 * because of compression */

    u_int in_mbad;		/* Bad incoming packets */
};


extern void	if_init(slirp_t *);
extern void	if_start(void);
extern void	if_output(struct SLIRPsocket *, struct SLIRPmbuf *);
extern void	if_encap(const uint8_t *ip_data, int ip_data_len);


#endif	/*SLIRP_IF_H*/
