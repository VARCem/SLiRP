#ifndef SLIRP_REDIR_H
# define SLIRP_REDIR_H


extern int	redir_init(void);
extern int	slirp_redir(int is_udp, int host_port,
			    struct in_addr guest_addr, int guest_port);
extern int	slirp_add_exec(int do_pty, const char *args,
			       int addr_low_byte, int guest_port);


#endif	/*SLIRP_REDIR_H*/
