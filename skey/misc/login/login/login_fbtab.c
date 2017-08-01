#ifdef USE_FBTAB

/*
    SYNOPSIS
	login_fbtab(tty, uid, gid)
	char *tty;
	int uid;
	int gid;

    DESCRIPTION
	This module implements device security as described in the
	SunOS 4.1.1 fbtab(5) manual page. We expect an /etc/fbtab file
	with the following format:

	    Comments start with a # and extend to the end of the line.

	    Blank lines or lines with only a comment are ignored.

	    All other lines consist of three fields delimited by
	    whitespace: a login device (/dev/console), an octal
	    permission number (0600), and a ":"-delimited list of
	    devices (/dev/kbd:/dev/mouse). All device names are
	    absolute paths.

	    If the tty argument (relative path) matches a login device
	    name (absolute path), the permissions of the devices in the
	    ":"-delimited list are set as specified in the second
	    field, and their ownership is changed to that of the uid
	    and gid arguments.

    DIAGNOSTICS
	Problems are reported via the syslog daemon with severity
	LOG_ERR.

    BUGS
	This module uses strtok(3), which may cause conflicts with other
	uses of that same routine.

    AUTHOR
	Wietse Venema (wietse@wzv.win.tue.nl)
	Eindhoven University of Technology
	The Netherlands
 */

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#define	FBTAB	"/etc/fbtab"
#define	WSPACE	" \t\n"

/* login_fbtab - apply protections as specified in /etc/fbtab */

login_fbtab(tty, uid, gid)
char   *tty;
int     uid;
int     gid;
{
    FILE   *fp;
    char    buf[BUFSIZ];
    char   *devname;
    char   *cp;
    int     prot;

    if ((fp = fopen(FBTAB, "r")) == 0)
	return;

    while (fgets(buf, sizeof(buf), fp)) {
	if (cp = strchr(buf, '#'))
	    *cp = 0;				/* strip comment */
	if ((cp = devname = strtok(buf, WSPACE)) == 0) {
	    continue;				/* empty or comment */
	} else if (strncmp(devname, "/dev/", 5) != 0
	       || (cp = strtok((char *) 0, WSPACE)) == 0
	       || *cp != '0'
	       || sscanf(cp, "%o", &prot) == 0
	       || prot == 0
	       || prot > 0777
	       || (cp = strtok((char *) 0, WSPACE)) == 0) {
	    syslog(LOG_ERR, "%s: bad entry: %s", FBTAB, cp ? cp : "(null)");
	    continue;
	} else if (strcmp(devname + 5, tty) == 0) {
	    for (cp = strtok(cp, ":"); cp; cp = strtok((char *) 0, ":")) {
		if (chmod(cp, prot) && errno != ENOENT)
		    syslog(LOG_ERR, "%s: chmod(%s): %m", FBTAB, cp);
		if (chown(cp, uid, gid) && errno != ENOENT)
		    syslog(LOG_ERR, "%s: chown(%s): %m", FBTAB, cp);
	    }
	}
    }
    fclose(fp);
}

#endif
