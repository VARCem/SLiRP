#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../host.h"
#include "../debug.h"


#ifndef AI_FQDN
# define AI_FQDN	0x00020000
#endif


extern struct in_addr  our_addr;               /* host IP address */
extern struct in_addr  dns_addr;               /* host DNS server */
extern struct in_addr  loopback_addr;          /* host loopback address */


int
inet_aton(const char *cp, struct in_addr *ia)
{
    uint32_t addr = inet_addr(cp);

    if (addr == 0xffffffff)
	return 0;
    ia->s_addr = addr;

    return 1;
}


int
host_get_info(struct in_addr *dns, char *hostname, char *domainname)
{
    struct addrinfo hints, *ai;
    IP_ADDR_STRING *pIPAddr;
    FIXED_INFO *FixedInfo;
    struct in_addr addr;
    ULONG BufLen;
    DWORD ret;
    
    FixedInfo = (FIXED_INFO *)GlobalAlloc(GPTR, sizeof(FIXED_INFO));
    BufLen = sizeof(FIXED_INFO);
   
    if (ERROR_BUFFER_OVERFLOW == GetNetworkParams(FixedInfo, &BufLen)) {
        if (FixedInfo) {
            GlobalFree(FixedInfo);
            FixedInfo = NULL;
        }
        FixedInfo = (FIXED_INFO *)GlobalAlloc(GPTR, BufLen);
    }
	
    if ((ret = GetNetworkParams(FixedInfo, &BufLen)) != ERROR_SUCCESS) {
        lprint("GetNetworkParams failed. ret = %08x\n", (u_int)ret);
        if (FixedInfo) {
            GlobalFree(FixedInfo);
            FixedInfo = NULL;
        }
        return -1;
    }

    /* Set up hostname, domainname and IP address. */
    strcpy(hostname, FixedInfo->HostName);
    strcpy(domainname, FixedInfo->DomainName);
strcpy(domainname, "homenet.lan");
    memset(&hints, 0x00, sizeof(hints));
    ai = NULL;
#ifdef AI_FQDN
    hints.ai_flags = AI_FQDN;
#else
    hints.ai_flags = AI_CANONNAME;
#endif
    hints.ai_family = AF_INET;
    if (! getaddrinfo(hostname, NULL, &hints, &ai)) {
	our_addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr;
	strcpy(hostname, ai->ai_canonname);
	freeaddrinfo(ai);
    }
    if (our_addr.s_addr == 0)
        our_addr.s_addr = loopback_addr.s_addr;

    lprint(" Hostname: %s.%s\n", hostname, domainname);
    lprint(" IP address: %s\n", inet_ntoa(our_addr));

    memset(&addr, 0x00, sizeof(addr));
    pIPAddr = &FixedInfo->DnsServerList;
    inet_aton(pIPAddr->IpAddress.String, &addr);
    *dns = addr;

    lprint(" DNS Servers:\n" );
    while (pIPAddr) {
	lprint("  Address: %s\n", pIPAddr->IpAddress.String);
	pIPAddr = pIPAddr->Next;
    }

    if (FixedInfo)
        GlobalFree(FixedInfo);

    return 0;
}


int
host_init(void)
{
    WSADATA Data;

    WSAStartup(MAKEWORD(2,0), &Data);

    return 0;
}


void
host_close(void)
{
    WSACleanup();
}
