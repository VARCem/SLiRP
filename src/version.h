/*
 * VARCem	Virtual ARchaeological Computer EMulator.
 *		An emulator of (mostly) x86-based PC systems and devices,
 *		using the ISA,EISA,VLB,MCA  and PCI system buses, roughly
 *		spanning the era between 1981 and 1995.
 *
 *		This file is part of the VARCem Project.
 *
 *		Define support library version and build info.
 *
 * Version:	@(#)version.h	1.0.2	2020/07/29
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
#ifndef LIB_VERSION_H
# define LIB_VERSION_H


/* Library name. */
#define LIB_NAME	"LibSLiRP"

/* Version info. */
#define LIB_VER_MAJOR	1
#define LIB_VER_MINOR	0
#define LIB_VER_REV	9
#define LIB_VER_PATCH	2


/* Standard C preprocessor macros. */
#define STR_STRING(x)	#x
#define STR(x)		STR_STRING(x)
#define STR_RC(a,e)	a ## , ## e


/* These are used in the application. */
#define LIB_VER_NUM	LIB_VER_MAJOR.LIB_VER_MINOR.LIB_VER_REV
#if defined(LIB_VER_PATCH) && LIB_VER_PATCH > 0
# define LIB_VER_NUM_4	LIB_VER_MAJOR.LIB_VER_MINOR.LIB_VER_REV.LIB_VER_PATCH
#else
# define LIB_VER_NUM_4	LIB_VER_MAJOR.LIB_VER_MINOR.LIB_VER_REV.0
#endif
#define LIB_VERSION	STR(LIB_VER_NUM)
#define LIB_VERSION_4	STR(LIB_VER_NUM_4)


#endif	/*LIB_VERSION_H*/
