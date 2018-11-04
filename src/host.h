#ifndef SLIRP_HOST_H
# define SLIRP_HOST_H


extern int	host_get_info(struct in_addr *, char *, char *);
extern int	host_init(void);
extern void	host_close(void);

#ifdef _WIN32
extern int	inet_aton(const char *, struct in_addr *);
#endif


#endif	/*SLIRP_HOST_H*/
