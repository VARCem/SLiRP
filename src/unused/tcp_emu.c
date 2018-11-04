/*
 * Changes and additions relating to SLiRP
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */

#define WANT_SYS_IOCTL_H
#include <stdlib.h>
#ifndef _WIN32
# include <unistd.h>
#endif
#include "slirp.h"


#ifdef USE_REDIR
struct emu_t *tcpemu = 0;
int do_echo = -1;


/*
 * Emulate programs that try and connect to us
 * This includes ftp (the data connection is
 * initiated by the server) and IRC (DCC CHAT and
 * DCC SEND) for now
 * 
 * NOTE: It's possible to crash SLiRP by sending it
 * unstandard strings to emulate... if this is a problem,
 * more checks are needed here
 *
 * XXX Assumes the whole command came in one packet
 *					    
 * XXX Some ftp clients will have their TOS set to
 * LOWDELAY and so Nagel will kick in.  Because of this,
 * we'll get the first letter, followed by the rest, so
 * we simply scan for ORT instead of PORT...
 * DCC doesn't have this problem because there's other stuff
 * in the packet before the DCC command.
 * 
 * Return 1 if the SLIRPmbuf m is still valid and should be 
 * sbappend()ed
 * 
 * NOTE: if you return 0 you MUST m_free() the SLIRPmbuf!
 */
int
tcp_emu(struct SLIRPsocket *so, struct SLIRPmbuf *m)
{
	u_int n1, n2, n3, n4, n5, n6;
	char buff[256];
	u_int32_t laddr;
	u_int lport;
	char *bptr;
	
	DEBUG_CALL("tcp_emu");
	DEBUG_ARG("so = %lx", (long)so);
	DEBUG_ARG("m = %lx", (long)m);
	
	switch(so->so_emu) {
		int x, i;
		
	 case EMU_IDENT:
		/*
		 * Identification protocol as per rfc-1413
		 */
		
		{
			struct SLIRPsocket *tmpso;
			struct sockaddr_in addr;
			socklen_t addrlen = sizeof(struct sockaddr_in);
			struct sbuf *so_rcv = &so->so_rcv;
			
			memcpy(so_rcv->sb_wptr, m->m_data, m->m_len);
			so_rcv->sb_wptr += m->m_len;
			so_rcv->sb_rptr += m->m_len;
			m->m_data[m->m_len] = 0; /* NULL terminate */
			if (strchr(m->m_data, '\r') || strchr(m->m_data, '\n')) {
				if (sscanf(so_rcv->sb_data, "%d%*[ ,]%d", &n1, &n2) == 2) {
					HTONS(n1);
					HTONS(n2);
					/* n2 is the one on our host */
					for (tmpso = tcb.so_next; tmpso != &tcb; tmpso = tmpso->so_next) {
						if (tmpso->so_laddr.s_addr == so->so_laddr.s_addr &&
						    tmpso->so_lport == n2 &&
						    tmpso->so_faddr.s_addr == so->so_faddr.s_addr &&
						    tmpso->so_fport == n1) {
							if (getsockname(tmpso->s,
								(struct sockaddr *)&addr, &addrlen) == 0)
							   n2 = ntohs(addr.sin_port);
							break;
						}
					}
				}
				so_rcv->sb_cc = sprintf(so_rcv->sb_data, "%d,%d\r\n", n1, n2);
				so_rcv->sb_rptr = so_rcv->sb_data;
				so_rcv->sb_wptr = so_rcv->sb_data + so_rcv->sb_cc;
			}
			m_free(m);
			return 0;
		}
		
#if 0
	 case EMU_RLOGIN:
		/*
		 * Rlogin emulation
		 * First we accumulate all the initial option negotiation,
		 * then fork_exec() rlogin according to the  options
		 */
		{
			int i, i2, n;
			char *ptr;
			char args[100];
			char term[100];
			struct sbuf *so_snd = &so->so_snd;
			struct sbuf *so_rcv = &so->so_rcv;
			
			/* First check if they have a priveladged port, or too much data has arrived */
			if (ntohs(so->so_lport) > 1023 || ntohs(so->so_lport) < 512 ||
			    (m->m_len + so_rcv->sb_wptr) > (so_rcv->sb_data + so_rcv->sb_datalen)) {
				memcpy(so_snd->sb_wptr, "Permission denied\n", 18);
				so_snd->sb_wptr += 18;
				so_snd->sb_cc += 18;
				tcp_sockclosed(sototcpcb(so));
				m_free(m);
				return 0;
			}
			
			/* Append the current data */
			memcpy(so_rcv->sb_wptr, m->m_data, m->m_len);
			so_rcv->sb_wptr += m->m_len;
			so_rcv->sb_rptr += m->m_len;
			m_free(m);
			
			/*
			 * Check if we have all the initial options,
			 * and build argument list to rlogin while we're here
			 */
			n = 0;
			ptr = so_rcv->sb_data;
			args[0] = 0;
			term[0] = 0;
			while (ptr < so_rcv->sb_wptr) {
				if (*ptr++ == 0) {
					n++;
					if (n == 2) {
						sprintf(args, "rlogin -l %s %s",
							ptr, inet_ntoa(so->so_faddr));
					} else if (n == 3) {
						i2 = so_rcv->sb_wptr - ptr;
						for (i = 0; i < i2; i++) {
							if (ptr[i] == '/') {
								ptr[i] = 0;
#ifdef HAVE_SETENV
								sprintf(term, "%s", ptr);
#else
								sprintf(term, "TERM=%s", ptr);
#endif
								ptr[i] = '/';
								break;
							}
						}
					}
				}
			}
			
			if (n != 4)
			   return 0;
			
			/* We have it, set our term variable and fork_exec() */
#ifdef HAVE_SETENV
			setenv("TERM", term, 1);
#else
			putenv(term);
#endif
			fork_exec(so, args, 2);
			term[0] = 0;
			so->so_emu = 0;
			
			/* And finally, send the client a 0 character */
			so_snd->sb_wptr[0] = 0;
			so_snd->sb_wptr++;
			so_snd->sb_cc++;
			
			return 0;
		}
		
	 case EMU_RSH:
		/*
		 * rsh emulation
		 * First we accumulate all the initial option negotiation,
		 * then rsh_exec() rsh according to the  options
		 */
		{
			int  n;
			char *ptr;
			char *user;
			char *args;
			struct sbuf *so_snd = &so->so_snd;
			struct sbuf *so_rcv = &so->so_rcv;
			
			/* First check if they have a priveladged port, or too much data has arrived */
			if (ntohs(so->so_lport) > 1023 || ntohs(so->so_lport) < 512 ||
			    (m->m_len + so_rcv->sb_wptr) > (so_rcv->sb_data + so_rcv->sb_datalen)) {
				memcpy(so_snd->sb_wptr, "Permission denied\n", 18);
				so_snd->sb_wptr += 18;
				so_snd->sb_cc += 18;
				tcp_sockclosed(sototcpcb(so));
				m_free(m);
				return 0;
			}
			
			/* Append the current data */
			memcpy(so_rcv->sb_wptr, m->m_data, m->m_len);
			so_rcv->sb_wptr += m->m_len;
			so_rcv->sb_rptr += m->m_len;
			m_free(m);
			
			/*
			 * Check if we have all the initial options,
			 * and build argument list to rlogin while we're here
			 */
			n = 0;
			ptr = so_rcv->sb_data;
			user="";
			args="";
			if (so->extra==NULL) {
				struct SLIRPsocket *ns;
				struct tcpcb* tp;
				int port=atoi(ptr);
				if (port <= 0) return 0;
                if (port > 1023 || port < 512) {
                  memcpy(so_snd->sb_wptr, "Permission denied\n", 18);
                  so_snd->sb_wptr += 18;
                  so_snd->sb_cc += 18;
                  tcp_sockclosed(sototcpcb(so));
                  return 0;
                }
				if ((ns=socreate()) == NULL)
                  return 0;
				if (tcp_attach(ns)<0) {
                  free(ns);
                  return 0;
				}

				ns->so_laddr=so->so_laddr;
				ns->so_lport=htons(port);

				(void) tcp_mss(sototcpcb(ns), 0);

				ns->so_faddr=so->so_faddr;
				ns->so_fport=htons(IPPORT_RESERVED-1); /* Use a fake port. */

				if (ns->so_faddr.s_addr == 0 || 
					ns->so_faddr.s_addr == loopback_addr.s_addr)
                  ns->so_faddr = alias_addr;

				ns->so_iptos = tcp_tos(ns);
				tp = sototcpcb(ns);
                
				tcp_template(tp);
                
				/* Compute window scaling to request.  */
				/*	while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
				 *		(TCP_MAXWIN << tp->request_r_scale) < so->so_rcv.sb_hiwat)
				 *		tp->request_r_scale++;
				 */

                /*soisfconnecting(ns);*/

				tcpstat.tcps_connattempt++;
					
				tp->t_state = TCPS_SYN_SENT;
				tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
				tp->iss = tcp_iss; 
				tcp_iss += TCP_ISSINCR/2;
				tcp_sendseqinit(tp);
				tcp_output(tp);
				so->extra=ns;
			}
			while (ptr < so_rcv->sb_wptr) {
              if (*ptr++ == 0) {
                n++;
                if (n == 2) {
                  user=ptr;
                } else if (n == 3) {
                  args=ptr;
                }
              }
			}
			
			if (n != 4)
              return 0;
			
			rsh_exec(so,so->extra, user, inet_ntoa(so->so_faddr), args);
			so->so_emu = 0;
			so->extra=NULL;
			
			/* And finally, send the client a 0 character */
			so_snd->sb_wptr[0] = 0;
			so_snd->sb_wptr++;
			so_snd->sb_cc++;
			
			return 0;
		}

	 case EMU_CTL:
		{
			int num;
			struct sbuf *so_snd = &so->so_snd;
			struct sbuf *so_rcv = &so->so_rcv;
			
			/*
			 * If there is binary data here, we save it in so->so_m
			 */
			if (!so->so_m) {
			  int rxlen;
			  char *rxdata;
			  rxdata=mtod(m, char *);
			  for (rxlen=m->m_len; rxlen; rxlen--) {
			    if (*rxdata++ & 0x80) {
			      so->so_m = m;
			      return 0;
			    }
			  }
			} /* if(so->so_m==NULL) */
			
			/*
			 * Append the line
			 */
			sbappendsb(so_rcv, m);
			
			/* To avoid going over the edge of the buffer, we reset it */
			if (so_snd->sb_cc == 0)
			   so_snd->sb_wptr = so_snd->sb_rptr = so_snd->sb_data;
			
			/*
			 * A bit of a hack:
			 * If the first packet we get here is 1 byte long, then it
			 * was done in telnet character mode, therefore we must echo
			 * the characters as they come.  Otherwise, we echo nothing,
			 * because in linemode, the line is already echoed
			 * XXX two or more control connections won't work
			 */
			if (do_echo == -1) {
				if (m->m_len == 1) do_echo = 1;
				else do_echo = 0;
			}
			if (do_echo) {
			  sbappendsb(so_snd, m);
			  m_free(m);
			  tcp_output(sototcpcb(so)); /* XXX */
			} else
			  m_free(m);
			
			num = 0;
			while (num < so->so_rcv.sb_cc) {
				if (*(so->so_rcv.sb_rptr + num) == '\n' ||
				    *(so->so_rcv.sb_rptr + num) == '\r') {
					int n;
					
					*(so_rcv->sb_rptr + num) = 0;
					if (ctl_password && !ctl_password_ok) {
						/* Need a password */
						if (sscanf(so_rcv->sb_rptr, "pass %256s", buff) == 1) {
							if (strcmp(buff, ctl_password) == 0) {
								ctl_password_ok = 1;
								n = sprintf(so_snd->sb_wptr,
									    "Password OK.\r\n");
								goto do_prompt;
							}
						}
						n = sprintf(so_snd->sb_wptr,
					 "Error: Password required, log on with \"pass PASSWORD\"\r\n");
						goto do_prompt;
					}
					cfg_quitting = 0;
					n = do_config(so_rcv->sb_rptr, so, PRN_SPRINTF);
					if (!cfg_quitting) {
						/* Register the printed data */
do_prompt:
						so_snd->sb_cc += n;
						so_snd->sb_wptr += n;
						/* Add prompt */
						n = sprintf(so_snd->sb_wptr, "Slirp> ");
						so_snd->sb_cc += n;
						so_snd->sb_wptr += n;
					}
					/* Drop so_rcv data */
					so_rcv->sb_cc = 0;
					so_rcv->sb_wptr = so_rcv->sb_rptr = so_rcv->sb_data;
					tcp_output(sototcpcb(so)); /* Send the reply */
				}
				num++;
			}
			return 0;
		}
#endif		
        case EMU_FTP: /* ftp */
		*(m->m_data+m->m_len) = 0; /* NULL terminate for strstr */
		if ((bptr = (char *)strstr(m->m_data, "ORT")) != NULL) {
			/*
			 * Need to emulate the PORT command
			 */			
			x = sscanf(bptr, "ORT %d,%d,%d,%d,%d,%d\r\n%256[^\177]", 
				   &n1, &n2, &n3, &n4, &n5, &n6, buff);
			if (x < 6)
			   return 1;
			
			laddr = htonl((n1 << 24) | (n2 << 16) | (n3 << 8) | (n4));
			lport = htons((n5 << 8) | (n6));
			
			if ((so = solisten(0, laddr, lport, SS_FACCEPTONCE)) == NULL)
			   return 1;
			
			n6 = ntohs(so->so_fport);
			
			n5 = (n6 >> 8) & 0xff;
			n6 &= 0xff;
			
			laddr = ntohl(so->so_faddr.s_addr);
			
			n1 = ((laddr >> 24) & 0xff);
			n2 = ((laddr >> 16) & 0xff);
			n3 = ((laddr >> 8)  & 0xff);
			n4 =  (laddr & 0xff);
			
			m->m_len = bptr - m->m_data; /* Adjust length */
			m->m_len += sprintf(bptr,"ORT %d,%d,%d,%d,%d,%d\r\n%s", 
					    n1, n2, n3, n4, n5, n6, x==7?buff:"");
			return 1;
		} else if ((bptr = (char *)strstr(m->m_data, "27 Entering")) != NULL) {
			/*
			 * Need to emulate the PASV response
			 */
			x = sscanf(bptr, "27 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n%256[^\177]",
				   &n1, &n2, &n3, &n4, &n5, &n6, buff);
			if (x < 6)
			   return 1;
			
			laddr = htonl((n1 << 24) | (n2 << 16) | (n3 << 8) | (n4));
			lport = htons((n5 << 8) | (n6));
			
			if ((so = solisten(0, laddr, lport, SS_FACCEPTONCE)) == NULL)
			   return 1;
			
			n6 = ntohs(so->so_fport);
			
			n5 = (n6 >> 8) & 0xff;
			n6 &= 0xff;
			
			laddr = ntohl(so->so_faddr.s_addr);
			
			n1 = ((laddr >> 24) & 0xff);
			n2 = ((laddr >> 16) & 0xff);
			n3 = ((laddr >> 8)  & 0xff);
			n4 =  (laddr & 0xff);
			
			m->m_len = bptr - m->m_data; /* Adjust length */
			m->m_len += sprintf(bptr,"27 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n%s",
					    n1, n2, n3, n4, n5, n6, x==7?buff:"");
			
			return 1;
		}
		
		return 1;
				   
	 case EMU_KSH:
		/*
		 * The kshell (Kerberos rsh) and shell services both pass
		 * a local port port number to carry signals to the server
		 * and stderr to the client.  It is passed at the beginning
		 * of the connection as a NUL-terminated decimal ASCII string.
		 */
		so->so_emu = 0;
		for (lport = 0, i = 0; i < m->m_len-1; ++i) {
			if (m->m_data[i] < '0' || m->m_data[i] > '9')
				return 1;       /* invalid number */
			lport *= 10;
			lport += m->m_data[i] - '0';
		}
		if (m->m_data[m->m_len-1] == '\0' && lport != 0 &&
		    (so = solisten(0, so->so_laddr.s_addr, htons(lport), SS_FACCEPTONCE)) != NULL)
			m->m_len = sprintf(m->m_data, "%d", ntohs(so->so_fport))+1;
		return 1;
		
	 case EMU_IRC:
		/*
		 * Need to emulate DCC CHAT, DCC SEND and DCC MOVE
		 */
		*(m->m_data+m->m_len) = 0; /* NULL terminate the string for strstr */
		if ((bptr = (char *)strstr(m->m_data, "DCC")) == NULL)
			 return 1;
		
		/* The %256s is for the broken mIRC */
		if (sscanf(bptr, "DCC CHAT %256s %u %u", buff, &laddr, &lport) == 3) {
			if ((so = solisten(0, htonl(laddr), htons(lport), SS_FACCEPTONCE)) == NULL)
				return 1;
			
			m->m_len = bptr - m->m_data; /* Adjust length */
			m->m_len += sprintf(bptr, "DCC CHAT chat %lu %u%c\n",
			     (unsigned long)ntohl(so->so_faddr.s_addr),
			     ntohs(so->so_fport), 1);
		} else if (sscanf(bptr, "DCC SEND %256s %u %u %u", buff, &laddr, &lport, &n1) == 4) {
			if ((so = solisten(0, htonl(laddr), htons(lport), SS_FACCEPTONCE)) == NULL)
				return 1;
			
			m->m_len = bptr - m->m_data; /* Adjust length */
			m->m_len += sprintf(bptr, "DCC SEND %s %lu %u %u%c\n", 
			      buff, (unsigned long)ntohl(so->so_faddr.s_addr),
			      ntohs(so->so_fport), n1, 1);
		} else if (sscanf(bptr, "DCC MOVE %256s %u %u %u", buff, &laddr, &lport, &n1) == 4) {
			if ((so = solisten(0, htonl(laddr), htons(lport), SS_FACCEPTONCE)) == NULL)
				return 1;
			
			m->m_len = bptr - m->m_data; /* Adjust length */
			m->m_len += sprintf(bptr, "DCC MOVE %s %lu %u %u%c\n",
			      buff, (unsigned long)ntohl(so->so_faddr.s_addr),
			      ntohs(so->so_fport), n1, 1);
		}
		return 1;

	 case EMU_REALAUDIO:
                /* 
		 * RealAudio emulation - JP. We must try to parse the incoming
		 * data and try to find the two characters that contain the
		 * port number. Then we redirect an udp port and replace the
		 * number with the real port we got.
		 *
		 * The 1.0 beta versions of the player are not supported
		 * any more.
		 * 
		 * A typical packet for player version 1.0 (release version):
		 *        
		 * 0000:50 4E 41 00 05 
		 * 0000:00 01 00 02 1B D7 00 00 67 E6 6C DC 63 00 12 50 .....×..gælÜc..P
		 * 0010:4E 43 4C 49 45 4E 54 20 31 30 31 20 41 4C 50 48 NCLIENT 101 ALPH
		 * 0020:41 6C 00 00 52 00 17 72 61 66 69 6C 65 73 2F 76 Al..R..rafiles/v
		 * 0030:6F 61 2F 65 6E 67 6C 69 73 68 5F 2E 72 61 79 42 oa/english_.rayB
		 *         
		 * Now the port number 0x1BD7 is found at offset 0x04 of the
		 * Now the port number 0x1BD7 is found at offset 0x04 of the
		 * second packet. This time we received five bytes first and
		 * then the rest. You never know how many bytes you get.
		 *
		 * A typical packet for player version 2.0 (beta):
		 *        
		 * 0000:50 4E 41 00 06 00 02 00 00 00 01 00 02 1B C1 00 PNA...........Á.
		 * 0010:00 67 75 78 F5 63 00 0A 57 69 6E 32 2E 30 2E 30 .guxõc..Win2.0.0
		 * 0020:2E 35 6C 00 00 52 00 1C 72 61 66 69 6C 65 73 2F .5l..R..rafiles/
		 * 0030:77 65 62 73 69 74 65 2F 32 30 72 65 6C 65 61 73 website/20releas
		 * 0040:65 2E 72 61 79 53 00 00 06 36 42                e.rayS...6B
		 *        
		 * Port number 0x1BC1 is found at offset 0x0d.
		 *      
		 * This is just a horrible switch statement. Variable ra tells
		 * us where we're going.
		 */
		
		bptr = m->m_data;
		while (bptr < m->m_data + m->m_len) {
			u_short p;
			static int ra = 0;
			char ra_tbl[4]; 
			
			ra_tbl[0] = 0x50;
			ra_tbl[1] = 0x4e;
			ra_tbl[2] = 0x41;
			ra_tbl[3] = 0;
			
			switch (ra) {
			 case 0:
			 case 2:
			 case 3:
				if (*bptr++ != ra_tbl[ra]) {
					ra = 0;
					continue;
				}
				break;
				
			 case 1:
				/*
				 * We may get 0x50 several times, ignore them
				 */
				if (*bptr == 0x50) {
					ra = 1;
					bptr++;
					continue;
				} else if (*bptr++ != ra_tbl[ra]) {
					ra = 0;
					continue;
				}
				break;
				
			 case 4: 
				/* 
				 * skip version number
				 */
				bptr++;
				break;
				
			 case 5: 
				/*
				 * The difference between versions 1.0 and
				 * 2.0 is here. For future versions of
				 * the player this may need to be modified.
				 */
				if (*(bptr + 1) == 0x02)
				   bptr += 8;
				else
				   bptr += 4;
				break;                          
				
			 case 6:
				/* This is the field containing the port
				 * number that RA-player is listening to.
				 */
				lport = (((u_char*)bptr)[0] << 8) 
				+ ((u_char *)bptr)[1];
				if (lport < 6970)      
				   lport += 256;   /* don't know why */
				if (lport < 6970 || lport > 7170)
				   return 1;       /* failed */
				
				/* try to get udp port between 6970 - 7170 */
				for (p = 6970; p < 7071; p++) {
					if (udp_listen( htons(p),
						       so->so_laddr.s_addr,
						       htons(lport),
						       SS_FACCEPTONCE)) {
						break;
					}
				}
				if (p == 7071)
				   p = 0;
				*(u_char *)bptr++ = (p >> 8) & 0xff;
				*(u_char *)bptr++ = p & 0xff;
				ra = 0; 
				return 1;   /* port redirected, we're done */
				break;  
				
			 default:
				ra = 0;                         
			}
			ra++;
		}
		return 1;                                
		
	 default:
		/* Ooops, not emulated, won't call tcp_emu again */
		so->so_emu = 0;
		return 1;
	}
}
#endif	/*USE_REDIR*/
