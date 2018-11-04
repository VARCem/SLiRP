/*
 * Copyright (c) 1995 Danny Gasparovski.
 * 
 * Please read the file COPYRIGHT for the 
 * terms and conditions of the copyright.
 */
#ifndef DEBUG_H
# define DEBUG_H


#define DBG_CALL	0x01
#define DBG_MISC	0x02
#define DBG_ERROR	0x04
#define DEBUG_DEFAULT	DBG_CALL|DBG_MISC|DBG_ERROR


#ifdef _DEBUG
# define DEBUG_CALL(x) \
	if (dbglvl & DBG_CALL) { \
		fprintf(dfd, "%s...\n", x); \
		fflush(dfd); \
	}
# define DEBUG_ARG(x, y) \
	if (dbglvl & DBG_CALL) { \
		fputc(' ', dfd); \
		fprintf(dfd, x, y); \
		fputc('\n', dfd); \
		fflush(dfd); \
	}
# define DEBUG_ARGS(x) \
	if (dbglvl & DBG_CALL) { \
		fprintf x ; \
		fflush(dfd); \
	}
# define DEBUG_MISC(x) \
	if (dbglvl & DBG_MISC) { \
		fprintf x ; \
		fflush(dfd); \
	}
# define DEBUG_ERROR(x) \
	if (dbglvl & DBG_ERROR) { \
		fprintf x ; \
		fflush(dfd); \
	}
#else
# define DEBUG_CALL(x)
# define DEBUG_ARG(x, y)
# define DEBUG_ARGS(x)
# define DEBUG_MISC(x)
# define DEBUG_ERROR(x)
#endif


extern FILE	*dfd;
extern int	dostats;
extern int	dbglvl;


extern void	debug_init(char *, int);
extern void	lprint(const char *fmt, ...);
#ifdef _DEBUG
extern void	dump_packet(void *dat, int n);
#endif

#ifndef _MSC_VER
extern char	*strerror(int);
#endif


#endif	/*DEBUG_H*/
