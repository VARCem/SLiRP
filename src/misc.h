/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */
#ifndef SLIRP_MISC_H
# define SLIRP_MISC_H


#ifdef USE_REDIR
struct ex_list {
    int		ex_pty;			/* Do we want a pty? */
    int		ex_addr;		/* The last byte of the address */
    int		ex_fport;		/* Port to telnet to */
    char	*ex_exec;		/* Command line of what to exec */

    struct ex_list *ex_next;
};

struct emu_t {
    uint16_t	lport;
    uint16_t	fport;
    uint8_t	tos;
    uint8_t	emu;

    struct emu_t *next;
};


extern struct emu_t *tcpemu;
extern int x_port, x_server, x_display;
extern struct ex_list *exec_list;
#endif


#define EMU_NONE	0x0

/* TCP emulations */
#define EMU_CTL		0x1
#define EMU_FTP		0x2
#define EMU_KSH		0x3
#define EMU_IRC		0x4
#define EMU_REALAUDIO	0x5
#define EMU_RLOGIN	0x6
#define EMU_IDENT	0x7
#define EMU_RSH		0x8

#define EMU_NOCONNECT	0x10	/* Don't connect */

/* UDP emulations */
#define EMU_TALK	0x1
#define EMU_NTALK	0x2
#define EMU_CUSEEME	0x3


struct tos_t {
    uint16_t	lport;
    uint16_t	fport;
    uint8_t	tos;
    uint8_t	emu;
};


extern u_int curtime, detach_time, detach_wait;


extern void	slirp_insque(void *, void *);
extern void	slirp_remque(void *);
extern void	fd_nonblock(int);
extern void	fd_block(int);


#endif	/*SLIRP_MISC_H*/
