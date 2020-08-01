/*
 * VARCem	Virtual ARchaeological Computer EMulator.
 *		An emulator of (mostly) x86-based PC systems and devices,
 *		using the ISA,EISA,VLB,MCA  and PCI system buses, roughly
 *		spanning the era between 1981 and 1995.
 *
 *		This file is part of the VARCem Project.
 *
 *		Define the API for libSLiRP.
 *
 * Version:	@(#)slirp.h	1.0.2	2020/07/29
 *
 * Author:	Fred N. van Kempen, <decwiz@yahoo.com>
 *
 *		Copyright 2020 Fred N. van Kempen.
 *
 *		Redistribution and  use  in source  and binary forms, with
 *		or  without modification, are permitted  provided that the
 *		following conditions are met:
 *
 *		1. Redistributions of  source  code must retain the entire
 *		   above notice, this list of conditions and the following
 *		   disclaimer.
 *
 *		2. Redistributions in binary form must reproduce the above
 *		   copyright  notice,  this list  of  conditions  and  the
 *		   following disclaimer in  the documentation and/or other
 *		   materials provided with the distribution.
 *
 *		3. Neither the  name of the copyright holder nor the names
 *		   of  its  contributors may be used to endorse or promote
 *		   products  derived from  this  software without specific
 *		   prior written permission.
 *
 * THIS SOFTWARE  IS  PROVIDED BY THE  COPYRIGHT  HOLDERS AND CONTRIBUTORS
 * "AS IS" AND  ANY EXPRESS  OR  IMPLIED  WARRANTIES,  INCLUDING, BUT  NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE  ARE  DISCLAIMED. IN  NO  EVENT  SHALL THE COPYRIGHT
 * HOLDER OR  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL,  EXEMPLARY,  OR  CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE  GOODS OR SERVICES;  LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED  AND ON  ANY
 * THEORY OF  LIABILITY, WHETHER IN  CONTRACT, STRICT  LIABILITY, OR  TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING  IN ANY  WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef LIB_SLIRP_H
# define LIB_SLIRP_H


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int		instance;
    int		link_up;

    int		do_slowtimo;

    uint32_t	time_fasttimo,
		last_slowtimo;
} slirp_t;


#ifdef HAVE_STDARG_H
typedef void (*log_func_t)(slirp_t *, const char *, va_list);
#endif


/* Functions. */
#ifndef _SLIRP_API
# define _SLIRP_API	/*nothing*/
#endif
extern _SLIRP_API int		slirp_version(char *bufp, int max_len);
extern _SLIRP_API void		debug_init(const char *filename, int level);
#ifdef HAVE_STDARG_H
extern _SLIRP_API void		slirp_debug(int level, log_func_t);
#endif

extern _SLIRP_API slirp_t	*slirp_init(void);
extern _SLIRP_API void		slirp_close(slirp_t *);

extern _SLIRP_API int		slirp_poll(slirp_t *slirp);

#ifdef USE_REDIR
extern _SLIRP_API int		slirp_redir(int is_udp, int host_port, 
					    struct in_addr guest_addr, int guest_port);
extern _SLIRP_API int		slirp_add_exec(int do_pty, const char *args,
					       int addr_low_byte, int guest_port);
#endif

extern _SLIRP_API int		slirp_can_output(void);
extern _SLIRP_API void		slirp_output(const uint8_t *pkt, int pkt_len);
extern _SLIRP_API void		slirp_input(const uint8_t *pkt, int pkt_len);

#ifdef __cplusplus
}
#endif


#endif	/*LIB_SLIRP_H*/
