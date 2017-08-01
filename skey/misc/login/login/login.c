/*
 * Copyright (c) 1980, 1987, 1988 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1980, 1987, 1988 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)login.c	5.32.1.1 (Berkeley) 1/28/89";
#endif /* not lint */

/*
 * login [ name ]
 * login -h hostname	(for telnetd, etc.)
 * login -f name	(for pre-authenticated login: datakit, xterm, etc.)
#ifdef OLD_RLOGIN
 * login -r hostname	(for old-style rlogind)
#endif
 */

#include <sys/param.h>
#ifdef QUOTA
#include <sys/quota.h>
#endif
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#ifdef USE_TERMIO_H
#include <termio.h>
#else /* TERMIO_H */
#include <sys/ioctl.h>
#endif /* TERMIO_H */

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <ident.h>

#ifdef __svr4__
#include <utmpx.h>
#define UT_NAMESIZE	sizeof(((struct utmpx *)0)->ut_name)
#else /* __svr4__ */
#include <utmp.h>
#ifndef	UT_NAMESIZE
#define UT_NAMESIZE	sizeof(((struct utmp *)0)->ut_name)
#endif /* UT_NAMESIZE */
#endif /* __svr4__ */
#include <signal.h>
#include <lastlog.h>
#include <errno.h>
#ifndef __svr4__
#include <ttyent.h>
#endif /* __svr4__ */
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdio.h>
#ifdef USE_STRING_H
#include <string.h>
#define index	strchr
#define rindex	strrchr
#define bzero(s,l) memset(s,0,l)
#else /* STRING_H */
#include <strings.h>
#endif /* STRING_H */

#ifdef __svr4__
#include <unistd.h>
#define getdtablesize() sysconf(_SC_OPEN_MAX)
#include <sys/fcntl.h>
#include <shadow.h>
#include "sysv_shadow.h"
#include "sysv_default.h"
#endif /* __svr4__ */

#define	TTYGRPNAME	"tty"		/* name of group to own ttys */

#define	MOTDFILE	"/etc/motd"
#ifdef __svr4__
#define	MAILDIR		"/var/mail"
#else /* __svr4__ */
#define	MAILDIR		"/usr/spool/mail"
#endif /* __svr4__ */
#define	NOLOGIN		"/etc/nologin"
#define	HUSHLOGIN	".hushlogin"
#define	LASTLOG		"/usr/adm/lastlog"
#define	BSHELL		"/bin/sh"
#define _PATH_LOGIN_LOG "/var/log/login"

/* Ultrix syslog(3) has no facility stuff. */
#ifndef LOG_AUTH
#define LOG_AUTH	0
#define LOG_ODELAY	0
#endif

#ifdef OLD_RLOGIN
static	char rusername[UT_NAMESIZE+1], lusername[UT_NAMESIZE+1];
#endif /* OLD_RLOGIN */

/*
 * This bounds the time given to login.  Not a define so it can
 * be patched on machines where it's too small.
 */
int	timeout = 300;

struct	passwd *pwd;
int	failures;
char	term[64], *hostname, *username, *tty;

#ifdef NONICE
#define	setpriority(x,y,z)	z
#endif

#ifdef USE_TERMIO_H
struct	termio termio;
#else /* USE_TERMIO_H */
struct	sgttyb sgttyb;
struct	tchars tc = {
	CINTR, CQUIT, CSTART, CSTOP, CEOT, CBRK
};
struct	ltchars ltc = {
	CSUSP, CDSUSP, CRPRNT, CFLUSH, CWERASE, CLNEXT
};
#endif /* USE_TERMIO_H */

main(argc, argv)
	int argc;
	char **argv;
{
	extern int errno, optind;
	extern char *optarg, **environ;
	struct group *gr;
	register int ch;
	register char *p;
	int ask, fflag, hflag, pflag, cnt;
#ifdef OLD_RLOGIN
	int rflag;
#endif /* OLD_RLOGIN */
	int quietlog, passwd_req, ioctlval;
        void timedout();
#ifdef DETECT_HANGUP
	void hungup();
#endif
	char *domain, *salt, *envinit[1], *ttyn, *pp;
	char tbuf[MAXPATHLEN + 2];
	char *ttyname(), *stypeof(), *crypt(), *getpass();
	time_t time();
	off_t lseek();
	char *getenv();

#ifdef LOGGING
        FILE *fp;
#endif /* LOGGING */

#ifdef __svr4__
	/* Read defaults file and set the login timeout period. */
	sysv_defaults();
	timeout = atoi(default_timeout);
#endif /* __svr4__ */

	(void)signal(SIGALRM, timedout);
	(void)alarm((u_int)timeout);
#ifdef DETECT_HANGUP
	(void)signal(SIGHUP, hungup);
#endif
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	(void)setpriority(PRIO_PROCESS, 0, 0);
#ifdef QUOTA
	(void)quota(Q_SETUID, 0, 0, 0);
#endif

	/*
	 * -p is used by getty to tell login not to destroy the environment
 	 * -f is used to skip a second login authentication 
	 * -h is used by other servers to pass the name of the remote
	 *    host to login so that it may be placed in utmp and wtmp
#ifdef OLD_RLOGIN
	 * -r is used by old-style rlogind to execute the autologin protocol
#endif
	 */
	(void)gethostname(tbuf, sizeof(tbuf));
	domain = index(tbuf, '.');

	fflag = hflag = pflag = 0;
#ifdef OLD_RLOGIN
	rflag = 0;
#endif /* OLD_RLOGIN */
	passwd_req = 1;
#if defined(__svr4__) || defined(OLD_RLOGIN)
	while ((ch = getopt(argc, argv, "d:fh:pr:")) != EOF)
#else
	while ((ch = getopt(argc, argv, "fh:p")) != EOF)
#endif
		switch (ch) {
#ifdef __svr4__ /* Allow but always ignore the -d option. */
			case 'd':
				break;
#endif /* __svr4__ */
		case 'f':
			fflag = 1;
			break;
		case 'h':
#ifdef OLD_RLOGIN
			if (rflag || hflag) {
				printf("Only one of -r and -h allowed\n");
				exit(1);
			}
#endif /* OLD_RLOGIN */
			if (getuid()) {
				fprintf(stderr,
				    "login: -h for super-user only.\n");
				exit(1);
			}
			hflag = 1;
#if 0			/* No local domain stripping */
			if (domain && (p = index(optarg, '.')) &&
			    strcasecmp(p, domain) == 0)
				*p = 0;
#endif
			hostname = optarg;
			break;
#ifndef __svr4__ /* System V login never preserves the environment. */
		case 'p':
			pflag = 1;
			break;
#endif /* __svr4__ */
#ifdef __svr4__ 
                case 'p':
                        break;
#endif 
#ifdef OLD_RLOGIN
		case 'r':
			if (rflag || hflag) {
				printf("Only one of -r and -h allowed\n");
				exit(1);
			}
			if (getuid()) {
				fprintf(stderr,
				    "login: -r for super-user only.\n");
				exit(1);
			}
			rflag = 1;
#if 0			/* No local domain stripping */
			if (domain && (p = index(optarg, '.')) &&
			    strcasecmp(p, domain) == 0)
				*p = 0;
#endif
			hostname = optarg;
			fflag = (doremotelogin(hostname) == 0);
			break;
#endif /* OLD_RLOGIN */
		case '?':
		default:
#if defined(__svr4__) || defined(OLD_RLOGIN)
			fprintf(stderr, "usage: login [-h | -r] [username]\n");
#else
			fprintf(stderr, "usage: login [-fp] [username]\n");
#endif
			exit(1);
		}
	argc -= optind;
	argv += optind;
#ifdef OLD_RLOGIN
	if (rflag) {
		username = lusername;
		ask = 0;
	} else
#endif /* OLD_RLOGIN */
#ifdef __svr4__ /* Pick up environment stuff after logging in. */
	if (*argv && strchr(*argv, '=')) {
		ask = 1;
	} else
#endif /* __svr4__ */
	if (*argv) {
		username = *argv;
		ask = 0;
#ifdef __svr4__ /* Pick up additional environment stuff after logging in. */
		argc--;
		argv++;
#endif /* __svr4__ */
#ifdef ultrix /* dlogind passes host via cmd line but user via environment */
	} else if (username = getenv("USERNAME")) {
		ask = 0;
#endif
#ifdef __svr4__ /* Perhaps the prompt was already printed. */
	} else if (getenv("TTYPROMPT")) {
		getloginname(0);
		ask = 0;
#endif /* __svr4__ */
	} else
		ask = 1;

#ifdef USE_TERMIO_H
	(void)ioctl(0, TCGETA, &termio);
#ifdef OLD_RLOGIN
	doremoteterm(term, &termio);
#endif /* OLD_RLOGIN */
	termio.c_lflag |= (ECHOE|ECHOCTL|ECHO|ECHOKE|IEXTEN);
	(void)ioctl(0, TCSETAF, &termio);
#else /* USE_TERMIO_H */
#ifdef ultrix
	ioctlval = LCRTBS | LCRTERA | LPRTERA;
#else
	ioctlval = 0;
#endif
	(void)ioctl(0, TIOCLSET, &ioctlval);
	(void)ioctl(0, TIOCNXCL, 0);
	(void)fcntl(0, F_SETFL, ioctlval);
	(void)ioctl(0, TIOCGETP, &sgttyb);
#ifdef OLD_RLOGIN
	doremoteterm(term, &sgttyb);
#endif /* OLD_RLOGIN */
	sgttyb.sg_erase = CERASE;
	sgttyb.sg_kill = CKILL;
	(void)ioctl(0, TIOCSLTC, &ltc);
	(void)ioctl(0, TIOCSETC, &tc);
	(void)ioctl(0, TIOCSETP, &sgttyb);
#endif /* USE_TERMIO_H */

	for (cnt = getdtablesize(); cnt > 2; cnt--)
		close(cnt);

	ttyn = ttyname(0);
	if (ttyn == NULL || *ttyn == '\0')
		ttyn = "/dev/tty??";
#ifdef __svr4__
	/* Use pts/XXX instead of basename. */
	if (tty = strchr(ttyn + 1, '/'))
#else /* __svr4__ */
	if (tty = rindex(ttyn, '/'))
#endif /* __svr4__ */
		++tty;
	else
		tty = ttyn;

	openlog("login", LOG_ODELAY, LOG_AUTH);

	for (cnt = 0;; ask = 1) {
#ifndef USE_TERMIO_H
		ioctlval = 0;
		(void)ioctl(0, TIOCSETD, &ioctlval);
#endif

		if (ask) {
			fflag = 0;
			getloginname(1);
		}
		/*
		 * Note if trying multiple user names;
		 * log failures for previous user name,
		 * but don't bother logging one failure
		 * for nonexistent name (mistyped username).
		 */
		if (failures && strcmp(tbuf, username)) {
			if (failures > (pwd ? 0 : 1))
				badlogin(tbuf);
			failures = 0;
		}
		(void)strcpy(tbuf, username);
		if (pwd = getpwnam(username))
			salt = pwd->pw_passwd;
		else
			salt = "xx";

		/* if user not super-user, check for disabled logins */
		if (pwd == NULL || pwd->pw_uid)
			checknologin();

		/*
		 * Disallow automatic login to root; if not invoked by
		 * root, disallow if the uid's differ.
		 */
		if (fflag && pwd) {
			int uid = getuid();

			passwd_req = pwd->pw_uid == 0 ||
			    (uid && uid != pwd->pw_uid);
		}

		/*
		 * If no pre-authentication and a password exists
		 * for this user, prompt for one and verify it.
		 */
		if (!passwd_req || (pwd && !*pwd->pw_passwd))
			break;

		setpriority(PRIO_PROCESS, 0, -4);

#ifdef SKEY_ONLY
                if (!skey_haskey (username)) { 
                   if (skey_authenticate (username) == 0)
                      break;
                   else 
                      goto BADSKEY;
                }
#endif
		pp = getpass("Password:");
		p = crypt(pp, salt);
		setpriority(PRIO_PROCESS, 0, 0);

		(void) bzero(pp, strlen(pp));
		if (pwd && !strcmp(p, pwd->pw_passwd))
			break;
#ifdef SKEY_ONLY
BADSKEY:
#endif
		printf("Login incorrect\n");
		failures++;
		badlogin(username);
#ifdef USE_TERMIO_H
		termio.c_cflag |= HUPCL;
		(void)ioctl(0, TCSETA, &termio);
#else /* USE_TERMIO_H */
		(void)ioctl(0, TIOCHPCL, (struct sgttyb *)NULL);
#endif /* USE_TERMIO_H */
#ifdef FINGERBACK
                if (hostname)
                    fingerback (hostname);
#endif /* FINGERBACK */

		sleepexit(1);
		sleep((u_int)((cnt - 3) * 5));

	}

       /* committed to login -- turn off timeout */
        (void)alarm((u_int)0);

#if defined (SKEY) && !defined (SKEY_ONLY)
        if (skey_authenticate (username) < 0) {
           if (hostname)
              syslog(LOG_NOTICE, "SKEY LOGIN FAILURE FROM %s, %s",
                     hostname, username);
           else
              syslog(LOG_NOTICE, "SKEY FAILURE ON %s, %s",
                     tty, username);
#ifdef LOGGING
           if ((fp = fopen(_PATH_LOGIN_LOG, "a")) != NULL) {
                struct timeval tp;

                (void) gettimeofday(&tp, (struct timezone *)0);
                (void) fprintf(fp, "%.15s %s: ", ctime(&tp.tv_sec)+4,
                                hostname ? hostname : "(local)");
                (void) fprintf (fp, "Skey login failure for %s\n", username);
                (void) fclose(fp);
           }
#endif /* LOGGING */
           printf ("Invalid response.\n");
           fflush (stdout);
           sleepexit(1);
           sleep((u_int)((cnt - 3) * 5));
        }
#endif /* SKEY */

#ifdef WATCHDOG

        if (w_authenticate (username) < 0) {
             sleepexit(1);
             sleep((u_int)((cnt - 3) * 5));
        }

#endif /* WATCHDOG */

	/*
	 * If valid so far and root is logging in, see if root logins on
	 * this terminal are permitted.
	 */
	if (pwd->pw_uid == 0 && !rootterm(tty)) {
		if (hostname)
			syslog(LOG_NOTICE, "ROOT LOGIN REFUSED FROM %s",
			    hostname);
		else
			syslog(LOG_NOTICE, "ROOT LOGIN REFUSED ON %s", tty);
		printf("Login incorrect\n");
		sleepexit(1);
	}

#ifdef QUOTA
	if (quota(Q_SETUID, pwd->pw_uid, 0, 0) < 0 && errno != EINVAL) {
		switch(errno) {
		case EUSERS:
			fprintf(stderr,
		"Too many users logged on already.\nTry again later.\n");
			break;
		case EPROCLIM:
			fprintf(stderr,
			    "You have too many processes running.\n");
			break;
		default:
			perror("quota (Q_SETUID)");
		}
		sleepexit(0);
	}
#endif

#ifdef __svr4__ /* Update SYSV-style utmp and wtmp files. */
	if (utmpx_login(tty, username, hostname ? hostname : "") != 0) {
		printf("No utmpx entry.  You must exec \"login\" from the lowest level \"sh\".\n");
		sleepexit(0);
	}
#endif /* __svr4__ */

	if (chdir(pwd->pw_dir) < 0) {
		printf("No directory %s!\n", pwd->pw_dir);
		if (chdir("/"))
			exit(0);
		pwd->pw_dir = "/";
		printf("Logging in with home = \"/\".\n");
	}

	/* nothing else left to fail -- really log in */
#ifndef __svr4__ /* Update BSD-style utmp and wtmp files. */
	{
		struct utmp utmp;

		bzero((char *)&utmp, sizeof(utmp));
		(void)time(&utmp.ut_time);
		strncpy(utmp.ut_name, username, sizeof(utmp.ut_name));
		if (hostname)
			strncpy(utmp.ut_host, hostname, sizeof(utmp.ut_host));
		strncpy(utmp.ut_line, tty, sizeof(utmp.ut_line));
		login(&utmp);
	}
#endif /* __svr4__ */

	quietlog = access(HUSHLOGIN, F_OK) == 0;
	dolastlog(quietlog);

#ifdef OLD_RLOGIN
	if (!rflag)
#endif /* OLD_RLOGIN */
	if (!hflag) {					/* XXX */
		static struct winsize win = { 0, 0, 0, 0 };

		(void)ioctl(0, TIOCSWINSZ, &win);
	}

#ifdef USE_FBTAB
	login_fbtab(tty, pwd->pw_uid, pwd->pw_gid);
#endif /* USE_FBTAB */

	(void)chown(ttyn, pwd->pw_uid,
	    (gr = getgrnam(TTYGRPNAME)) ? gr->gr_gid : pwd->pw_gid);
	(void)chmod(ttyn, 0620);
	(void)setgid(pwd->pw_gid);

	initgroups(username, pwd->pw_gid);

#ifdef QUOTA
	quota(Q_DOWARN, pwd->pw_uid, (dev_t)-1, 0);
#endif
#ifndef SHADOW_PASSWD /* No problem if we are signalled to drop core */
	(void)setuid(pwd->pw_uid);
#endif

	if (*pwd->pw_shell == '\0')
		pwd->pw_shell = BSHELL;
#ifndef USE_TERMIO_H
	/* turn on new line discipline for the csh */
	else if (!strcmp(pwd->pw_shell, "/bin/csh")) {
		ioctlval = NTTYDISC;
		(void)ioctl(0, TIOCSETD, &ioctlval);
	}
#endif /* USE_TERMIO_H */

#ifdef __svr4__
	/* set up a somewhat censored environment. */
	sysv_newenv(argc, argv, pwd, term);
#else /* __svr4__ */
	/* destroy environment unless user has requested preservation */
	if (!pflag)
		environ = envinit;
#ifdef sun
	else
		fixenv(environ);
#endif
	(void)setenv("HOME", pwd->pw_dir, 1);
	(void)setenv("SHELL", pwd->pw_shell, 1);
	if (!pflag || !getenv("TERM")) {
		if (term[0] == 0)
			strncpy(term, stypeof(tty), sizeof(term));
		(void)setenv("TERM", term, 0);
	}
	(void)setenv("USER", pwd->pw_name, 1);
	(void)setenv("PATH", "/usr/ucb:/bin:/usr/bin:", 0);

	if (tty[sizeof("tty")-1] == 'd')
		syslog(LOG_INFO, "DIALUP %s, %s", tty, pwd->pw_name);
#endif /* __svr4__ */
	if (pwd->pw_uid == 0)
		if (hostname)
			syslog(LOG_NOTICE, "ROOT LOGIN ON %s FROM %s",
			    tty, hostname);
		else
			syslog(LOG_NOTICE, "ROOT LOGIN ON %s", tty);

#ifndef __svr4__ /* Optionally show the message of the day. */
	if (!quietlog) {
		struct stat st;

		motd();
		(void)sprintf(tbuf, "%s/%s", MAILDIR, pwd->pw_name);
		if (stat(tbuf, &st) == 0 && st.st_size != 0)
			printf("You have %smail.\n",
			    (st.st_mtime > st.st_atime) ? "new " : "");
	}
#endif /* __svr4__ */

#ifdef LOGIN_ACCESS
	if (login_access(pwd->pw_name, hostname ? hostname : tty) == 0) {
		printf("Permission denied\n");
		if (hostname)
			syslog(LOG_NOTICE, "%s LOGIN REFUSED FROM %s",
			    pwd->pw_name, hostname);
		else
			syslog(LOG_NOTICE, "%s LOGIN REFUSED ON %s", 
			    pwd->pw_name, tty);
#ifdef LOGGING
                if ((fp = fopen(_PATH_LOGIN_LOG, "a")) != NULL) {
                    struct timeval tp;
 
                   (void) gettimeofday(&tp, (struct timezone *)0);
                   (void) fprintf(fp, "%.15s %s: ", ctime(&tp.tv_sec)+4,
                                  hostname ? hostname : "(local)");
                   (void) fprintf (fp, "Login refused for %s\n", pwd->pw_name);
                   (void) fclose(fp);
                }
#endif /* LOGGING */

		sleepexit(1);
	}
#endif /* LOGIN_ACCESS */

#ifdef __svr4__
	/*
	 * After cleaning up the environment, but before giving away privs,
	 * optionally run, as the user, /bin/passwd.
	 */

	if (sysv_expire(spwd))
		if (change_passwd(pwd))
			sleepexit(0);

	if (pwd->pw_passwd[0] == 0 && strcasecmp(default_passreq, "YES") == 0) {
		printf("You don't have a password.  Choose one.\n");
		if (change_passwd(pwd))
			sleepexit(0);
	}
#endif /* __svr4__ */

	(void)signal(SIGALRM, SIG_DFL);
#ifdef DETECT_HANGUP
	(void)signal(SIGHUP, SIG_DFL);
#endif /* DETECT_HANGUP */
	(void)signal(SIGQUIT, SIG_DFL);
	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGTSTP, SIG_IGN);

	tbuf[0] = '-';
	strcpy(tbuf + 1, (p = rindex(pwd->pw_shell, '/')) ?
	    p + 1 : pwd->pw_shell);
#ifdef SHADOW_PASSWD
	/* discard permissions last so can't get signalled to drop core */
	if (setuid(pwd->pw_uid)) {
		fprintf(stderr, "login: bad uid: %d\n", pwd->pw_uid);
		exit(0);
	}
#endif
	execlp(pwd->pw_shell, tbuf, 0);
	fprintf(stderr, "login: no shell: ");
	perror(pwd->pw_shell);
	exit(0);
}

getloginname(prompt)
	int	prompt;
{
	register int ch;
	register char *p;
	static char nbuf[UT_NAMESIZE + 1];

	for (;;) {
		if (prompt)
		printf("login: ");
		prompt = 1;
		for (p = nbuf; (ch = getchar()) != '\n'; ) {
			if (ch == EOF) {
				badlogin(username);
				exit(0);
			}
			if (p < nbuf + UT_NAMESIZE)
				*p++ = ch;
		}
		if (p > nbuf)
			if (nbuf[0] == '-')
				fprintf(stderr,
				    "login names may not start with '-'.\n");
			else {
				*p = '\0';
				username = nbuf;
				break;
			}
	}
}

void timedout()
{
	fprintf(stderr, "Login timed out after %d seconds\n", timeout);
	exit(0);
}

#ifdef DETECT_HANGUP

void hungup()
{
	close(0);	/* force EOF */
}

#endif

rootterm(ttyn)
	char *ttyn;
{
#ifdef __svr4__
	return (strcmp(default_console, ttyname(0)) == 0);
#else
	struct ttyent *t;

	return((t = getttynam(ttyn)) && t->ty_status&TTY_SECURE);
#endif
}

#ifndef __svr4__ /* message of the day stuff */

jmp_buf motdinterrupt;

motd()
{
	register int fd, nchars;
	int (*oldint)(), sigint();
	char tbuf[8192];

	if ((fd = open(MOTDFILE, O_RDONLY, 0)) < 0)
		return;
#if 1
	oldint = (int (*)()) signal(SIGINT, sigint);
#else
	oldint = signal(SIGINT, sigint);
#endif
	if (setjmp(motdinterrupt) == 0)
		while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
			(void)write(fileno(stdout), tbuf, nchars);
	(void)signal(SIGINT, oldint);
	(void)close(fd);
}

sigint()
{
	longjmp(motdinterrupt, 1);
}

#endif /* !__svr4__ */

checknologin()
{
	register int fd, nchars;
	char tbuf[8192];

	if ((fd = open(NOLOGIN, O_RDONLY, 0)) >= 0) {
		while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
			(void)write(fileno(stdout), tbuf, nchars);
		sleepexit(0);
	}
}

dolastlog(quiet)
	int quiet;
{
	struct lastlog ll;
	int fd;

	if ((fd = open(LASTLOG, O_RDWR, 0)) >= 0) {
		(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), L_SET);
		if (!quiet) {
			if (read(fd, (char *)&ll, sizeof(ll)) == sizeof(ll) &&
			    ll.ll_time != 0) {
#ifdef __svr4__			/* Last login too long ago? */
				if (pwd->pw_uid && spwd->sp_inact > 0 
				    && ll.ll_time / DAY
				    + spwd->sp_inact < DAY_NOW) {
					printf("Your account has been inactive to long.\n");
					sleepexit(1);
				}
#endif /* __svr4__ */
				printf("Last login: %.*s ",
				    24-5, (char *)ctime(&ll.ll_time));
				if (*ll.ll_host != '\0')
					printf("from %.*s\n",
					    sizeof(ll.ll_host), ll.ll_host);
				else
					printf("on %.*s\n",
					    sizeof(ll.ll_line), ll.ll_line);
			}
			(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), L_SET);
		}
		bzero((char *)&ll, sizeof(ll));
		(void)time(&ll.ll_time);
		strncpy(ll.ll_line, tty, sizeof(ll.ll_line));
		if (hostname)
			/* strncpy(ll.ll_host, hostname, 16); */
                        strcpy(ll.ll_host, hostname); 
		(void)write(fd, (char *)&ll, sizeof(ll));
		(void)close(fd);
	}
}

badlogin(name)
	char *name;
{
        register FILE *fp;
        register int ch;
        register char *lp;

#ifdef LOGGING
        if ((fp = fopen(_PATH_LOGIN_LOG, "a")) != NULL) {
                struct timeval tp;
 
                (void) gettimeofday(&tp, (struct timezone *)0);
                (void) fprintf(fp, "%.15s %s: ", ctime(&tp.tv_sec)+4,
                               hostname ? hostname : "(local)");
                fprintf (fp, "Login failure for %s\n", name);
                (void) fclose(fp);
        }
#endif /* LOGGING */

	if (hostname)
		syslog(LOG_NOTICE, "LOGIN FAILURE FROM %s, %s",
		       hostname, name);
	else
		syslog(LOG_NOTICE, "LOGIN FAILURE ON %s, %s",
		       tty, name);
}

#ifndef __svr4__ /* get terminal type from ttytab file */

#undef	UNKNOWN
#define	UNKNOWN	"su"

char *
stypeof(ttyid)
	char *ttyid;
{
	struct ttyent *t;

	return(ttyid && (t = getttynam(ttyid)) ? t->ty_type : UNKNOWN);
}

#endif /* !__svr4__ */

#ifdef OLD_RLOGIN

doremotelogin(host)
	char *host;
{
	getstr(rusername, sizeof (rusername), "remuser");
	getstr(lusername, sizeof (lusername), "locuser");
	getstr(term, sizeof(term), "Terminal type");
	pwd = getpwnam(lusername);
	if (pwd == NULL)
		return(-1);
	return(ruserok(host, (pwd->pw_uid == 0), rusername, lusername));
}

getstr(buf, cnt, err)
	char *buf, *err;
	int cnt;
{
	char ch;

	do {
		if (read(0, &ch, sizeof(ch)) != sizeof(ch))
			exit(1);
		if (--cnt < 0) {
			fprintf(stderr, "%s too long\r\n", err);
			sleepexit(1);
		}
		*buf++ = ch;
	} while (ch);
}

char    *speeds[] =
    { "0", "50", "75", "110", "134", "150", "200", "300",
      "600", "1200", "1800", "2400", "4800", "9600", "19200", "38400" };
#define NSPEEDS (sizeof (speeds) / sizeof (speeds[0]))

doremoteterm(term, tp)
	char *term;
#ifdef USE_TERMIO_H
	struct termio *tp;
#else /* USE_TERMIO_H */
	struct sgttyb *tp;
#endif /* USE_TERMIO_H */
{
	register char *cp = index(term, '/'), **cpp;
	char *speed;

	if (cp) {
		*cp++ = '\0';
		speed = cp;
		cp = index(speed, '/');
		if (cp)
			*cp++ = '\0';
		for (cpp = speeds; cpp < &speeds[NSPEEDS]; cpp++)
			if (strcmp(*cpp, speed) == 0) {
#ifdef USE_TERMIO_H
				tp->c_cflag &= ~CBAUD;
				tp->c_cflag |= cpp-speeds;
#else /* USE_TERMIO_H */
				tp->sg_ispeed = tp->sg_ospeed = cpp-speeds;
#endif /* USE_TERMIO_H */
				break;
			}
	}
#ifdef USE_TERMIO_H
#ifdef __svr4__
	tp->c_lflag |= (ICANON|ECHO);
	tp->c_iflag |= (IGNPAR|ICRNL);
	tp->c_cc[VEOF] = 4;	/* XXX */
#else /* __svr4__ */
	/* Boy, SunOS 4.x rlogind really messes things up... */
	tp->c_cflag &= ~CSIZE;
	tp->c_cflag |= (PARENB|CS7);
	tp->c_iflag |= (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON|IMAXBEL);
	tp->c_iflag &= ~IXANY;
	tp->c_lflag |= (ISIG|IEXTEN|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE);
	tp->c_oflag |= (OPOST|ONLCR|XTABS);
	tp->c_cc[VEOF] = 4;	/* XXX */
#endif /* __svr4__ */
#else /* USE_TERMIO_H */
	tp->sg_flags = ECHO|CRMOD|ANYP|XTABS;
#endif /* USE_TERMIO_H */
}

#endif /* OLD_RLOGIN */

sleepexit(eval)
	int eval;
{
	sleep((u_int)5);
	exit(eval);
}

#ifdef	NO_SETENV

setenv(name, value, overwrite)
char   *name;
char   *value;
int     overwrite;
{
	char   *malloc();
	char   *getenv();
	char   *p;

	if (overwrite == 0 && getenv(name) != 0)
		return (0);
	if ((p = malloc(strlen(name) + strlen(value) + 2)) == 0) {
		fprintf(stderr, "out of memory\n");
		sleepexit(1);
	}
	sprintf(p, "%s=%s", name, value);
	return (putenv(p));
}

#endif /* NO_SETENV */

#ifdef sun

fixenv(cpp)
char  **cpp;
{
	register char **xpp;
	register char *cp;

	while (cp = *cpp) {
		if (strncmp(cp, "LD_", 3) == 0 || strncmp(cp, "IFS=", 4) == 0) {
			for (xpp = cpp; xpp[0] = xpp[1]; xpp++);
			 /* void */ ;
		} else {
			cpp++;
		}
	}
}

#endif

#ifdef __svr4__

change_passwd(who)
	struct passwd  *who;
{
	int             status;
	int             pid;
	int             wpid;

	/*
	 * Running a command from a privileged program such as login is
	 * fraught with peril. Unless we are very careful, nasty games can be
	 * played with environment variables, in particular when the shell is
	 * used.
	 * 
	 * Running a command after giving up privileges has its problems too:
	 * the I/O buffers that were used for reading the shadow password
	 * file are still around, making us an attractive target for signals
	 * that force core dumps.
	 * 
	 * We therefore keep privileges (so that unprivileged users cannot
	 * signal us to dump core), sanitize the environment, and then run
	 * the child process as the user. And keep our fingers crossed.
	 */

	switch (pid = fork()) {
	case -1:
		perror("Cannot execute /bin/passwd");
		sleepexit(1);
	case 0:
		setgid(who->pw_gid);
		setuid(who->pw_uid);
		execlp("/bin/passwd", "passwd", who->pw_name, (char *) 0);
		_exit(1);
	default:
		while ((wpid = wait(&status)) != -1 && wpid != pid)
			 /* void */ ;
		return (status);
	}
}

#endif /* __svr4__ */

#ifdef FINGERBACK

int readline(s, buf)
     int s;
     char *buf;
{
    int to = 0, ret;
    char c;
 
    do {
        if ((ret = read(s, &c, 1)) < 0)
                return (-1);
        if (!ret)
            return (-2);
 
 
        if ((c >= ' ') || (c <= 126))
            if (to < 85 - 1)
                buf[to++] = c;
    } while (c != '\n');
 
    buf[to] = '\0';
 
    return (1);
}

int fingerback (host)
char *host;
{
    FILE *fp;
    int s;
    char buf[85];
    struct timeval tp;

    if ((fp = fopen(_PATH_LOGIN_LOG, "a")) != NULL) {
         (void) gettimeofday(&tp, (struct timezone *)0);

         s = connect_to_service (host, "finger", 0);

         if (s < 0) {
            (void) fprintf(fp, "%.15s Error connection to %s (port 79)\n",
                           ctime(&tp.tv_sec)+4, host);
            fclose (fp);
            return -1;
         }

         write(s, "\r\n", 2);

         (void) fprintf(fp, "%.15s Connected to %s (port 79)\n", 
                        ctime(&tp.tv_sec)+4, host);

         while (readline (s, buf) > 0)
               (void) fprintf (fp, "%s", buf);
          
         (void) fprintf(fp, "%.15s End of connection to %s (port 79)\n",
                           ctime(&tp.tv_sec)+4, host);

         fclose (fp);
         return (0);
     }

} 
  

int connect_to_service(hostname, service, port)
char    *hostname;
char    *service;
u_int   port;
{
    struct sockaddr_in  remote_addr;    /* remote inet socket address   */
    struct servent      *serv;          /* returned by getservbyname()  */
    struct hostent      *host;          /* returned by gethostbyname()  */
    int                 sock;
 
    if (strlen(service) <= 0)
        service = NULL;
    if ((host = gethostbyname(hostname)) == NULL) {
        perror("connect");
        return (-1);
    }
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return (-1);
    }
    if (service != NULL) {
        if ((serv = getservbyname(service, "tcp")) == NULL) {
            if (port <= 0) {
                fprintf(
                    stderr,
                    "Unknown serv %s/tcp. No default port given\n",
                    service);
                return(-1);
            }
            remote_addr.sin_port = htons((u_short) port);
        }
        else
            remote_addr.sin_port = serv->s_port;
    }
    else
        remote_addr.sin_port = htons((u_short) port);
    remote_addr.sin_family = host->h_addrtype;
    memcpy((char *) &remote_addr.sin_addr, host->h_addr,
           (unsigned int) host->h_length);
 
    if (connect(sock, (struct sockaddr *) &remote_addr,
        sizeof(remote_addr)) < 0)  {
        perror("connect");
        exit (-1);
    }
    return(sock);
}

#endif /* FINGERBACK */
