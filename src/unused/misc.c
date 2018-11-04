void
snooze(void)
{
	sigset_t s;
	int i;
	
	/* Don't need our data anymore */
	/* XXX This makes SunOS barf */
/*	brk(0); */
	
	/* Close all fd's */
	for (i = 255; i >= 0; i--)
	   close(i);
	
	signal(SIGQUIT, slirp_exit);
	signal(SIGHUP, snooze_hup);
	sigemptyset(&s);
	
	/* Wait for any signal */
	sigsuspend(&s);
	
	/* Just in case ... */
	exit(255);
}


void
relay(int s)
{
	char buf[8192];
	int n;
	fd_set readfds;
	struct ttys *ttyp;
	
	/* Don't need our data anymore */
	/* XXX This makes SunOS barf */
/*	brk(0); */
	
	signal(SIGQUIT, slirp_exit);
	signal(SIGHUP, slirp_exit);
        signal(SIGINT, slirp_exit);
	signal(SIGTERM, slirp_exit);
	
	/* Fudge to get term_raw and term_restore to work */
	if (NULL == (ttyp = tty_attach (0, slirp_tty))) {
         lprint ("Error: tty_attach failed in misc.c:relay()\r\n");
         slirp_exit (1);
    }
	ttyp->fd = 0;
	ttyp->flags |= TTY_CTTY;
	term_raw(ttyp);
	
	while (1) {
		FD_ZERO(&readfds);
		
		FD_SET(0, &readfds);
		FD_SET(s, &readfds);
		
		n = select(s+1, &readfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0);
		
		if (n <= 0)
		   slirp_exit(0);
		
		if (FD_ISSET(0, &readfds)) {
			n = read(0, buf, 8192);
			if (n <= 0)
			   slirp_exit(0);
			n = writen(s, buf, n);
			if (n <= 0)
			   slirp_exit(0);
		}
		
		if (FD_ISSET(s, &readfds)) {
			n = read(s, buf, 8192);
			if (n <= 0)
			   slirp_exit(0);
			n = writen(0, buf, n);
			if (n <= 0)
			   slirp_exit(0);
		}
	}
	
	/* Just in case.... */
	exit(1);
}


#ifdef BAD_SPRINTF
# undef vsprintf
# undef sprintf

/* Some BSD-derived systems have a sprintf which returns char *. */
int
vsprintf_len(char *string, const char *format, va_list args)
{
    vsprintf(string, format, args);

    return strlen(string);
}


int
sprintf_len(char *string, const char *format, ...)
{
    va_list args;

    va_start(args, format);

    vsprintf(string, format, args);

    return strlen(string);
}
#endif


void
u_sleep(int usec)
{
    struct timeval t;
    fd_set fdset;
	
    FD_ZERO(&fdset);
	
    t.tv_sec = 0;
    t.tv_usec = usec * 1000;
	
    select(0, &fdset, &fdset, &fdset, &t);
}
