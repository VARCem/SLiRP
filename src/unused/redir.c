#include "slirp.h"
#ifdef USE_REDIR
#include "redir.h"


struct ex_list	*exec_list = NULL;


int
redir_init(void)
{
    const char *cat = "SLiRP Port Forwarding";
    char temp[256];
    int rc, udp, from, to;
    int i = 0;

    for (;;) {
	sprintf(temp, "%d_udp", i);
	udp = config_get_int(cat, temp, 0);
	sprintf(temp, "%d_from", i);
	from = config_get_int(cat, temp, 0);

	if (from < 1)
		break;
	sprintf(temp, "%d_to", i);
	to = config_get_int(cat, temp, from);

	rc = slirp_redir(udp, from, myaddr, to);
	if (rc == 0)
		pclog(1, "slirp redir %d -> %d successful\n", from, to);
	else
		pclog(1, "slirp redir %d -> %d failed (%d)\n", from, to, rc);

	i++;
    }
}


int
slirp_redir(int is_udp, int host_port, 
            struct in_addr guest_addr, int guest_port)
{
    if (is_udp) {
        if (! udp_listen(htons(host_port), guest_addr.s_addr, 
                        htons(guest_port), 0))
            return -1;
    } else {
        if (! solisten(htons(host_port), guest_addr.s_addr, 
                      htons(guest_port), 0))
            return -1;
    }

    return 0;
}


int
slirp_add_exec(int do_pty, const char *args, int addr_low_byte, int guest_port)
{
    return add_exec(&exec_list, do_pty, (char *)args, 
                    addr_low_byte, htons(guest_port));
}


#endif	/*USE_REDIR*/
