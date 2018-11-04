/* Define to sizeof(char *) */
#ifdef SIZEOF_VOID_P
# define SIZEOF_CHAR_P SIZEOF_VOID_P
#else
# define SIZEOF_CHAR_P	8	/*FIXME: sizeof() does not work in cpp!*/
#endif

#define HAVE_MEMMOVE		/* Define if you have memmove() */
#define HAVE_STRERROR		/* Define if you have strerror() */


#ifdef _WIN32
# define DECLARE_IOVEC
typedef unsigned int	u_int;
typedef char		*SLIRPcaddr_t;
typedef int		socklen_t;
typedef unsigned long	ioctlsockopt_t;

# define USE_FIONBIO	1
# ifndef EWOULDBLOCK
#  define EWOULDBLOCK	WSAEWOULDBLOCK
# endif
# ifndef EINPROGRESS
#  define EINPROGRESS	WSAEINPROGRESS
# endif
# ifndef ENOTCONN
#  define ENOTCONN	WSAENOTCONN
# endif
# ifndef EHOSTUNREACH
#  define EHOSTUNREACH	WSAEHOSTUNREACH
# endif
# ifndef ENETUNREACH
#  define ENETUNREACH	WSAENETUNREACH
# endif
# ifndef ECONNREFUSED
#  define ECONNREFUSED	WSAECONNREFUSED
# endif

# define udp_read_completion slirp_udp_read_completion
# define write_udp	slirp_write_udp
# define init_udp	slirp_init_udp
# define final_udp	slirp_final_udp
#else
# define HAVE_INET_ATON
typedef char		*SLIRPcaddr_t;
typedef int		ioctlsockopt_t;
# define ioctlsocket	ioctl
# define closesocket(s)	close(s)
# define O_BINARY	0
#endif

#ifndef HAVE_MEMMOVE
# define memmove(x, y, z) bcopy(y, x, z)
#endif

#ifdef GETTIMEOFDAY_ONE_ARG
# define gettimeofday(x, y) gettimeofday(x)
#endif


#if defined(__GNUC__)
#define PACKED__ __attribute__ ((packed))
#elif defined(__sgi)
#define PRAGMA_PACK_SUPPORTED 1
#define PACK_END 0
#define PACKED__
#elif defined(_MSC_VER)
#define PACKED__
#else
#error "Packed attribute or pragma shall be supported"
#endif
