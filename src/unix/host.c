#ifdef _WIN32
# include <windows.h>
#else
# include <unistd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define HAVE_INADDR_H
#include "../private.h" 
#include "../slirp.h"


int
host_get_info(struct in_addr *dns, char *hostname, char *domainname)
{
    char buff[512], buff2[256];
    struct in_addr addr;
    struct hostent *he;
    int found = 0;
    FILE *f;

    f = fopen("/etc/resolv.conf", "r");
    if (!f)
        return -1;

    /* Set up hostname, domainname and IP address. */
    if (! gethostname(buff, sizeof(buff))) {
	he = gethostbyname(buff);
	if (he)
		our_addr = *(struct in_addr *)he->h_addr;
	strcpy(hostname, buff);
	strcpy(domainname, "");
    }
strcpy(domainname, "homenet.lan");
    lprint("My name: %s.%s\n", hostname, domainname);
    lprint("My IP address: %s\n", inet_ntoa(our_addr));

    lprint(" DNS Servers:\n" );
    while (fgets(buff, 512, f) != NULL) {
        if (sscanf(buff, "nameserver%*[ \t]%256s", buff2) == 1) {
            if (! inet_aton(buff2, &addr))
                continue;
            if (addr.s_addr == loopback_addr.s_addr)
                addr = our_addr;

            /* If it's the first one, set it to dns_addr */
            if (! found++)
                *dns = addr;

            lprint("  Address: %s\n", inet_ntoa(addr));
        }
    }
    fclose(f);

    if (! found)
        return -1;

    return 0;
}


int
host_init(void)
{
    /* Nothing to do, usually. */

    return 0;
}


void
host_close(void)
{
    /* Nothing to do. */
}
