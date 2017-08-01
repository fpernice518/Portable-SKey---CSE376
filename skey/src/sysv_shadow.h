
#include "config.h"

#ifdef HAVE_SHADOW_H
#  include <shadow.h>
#else
#  error Must have shadow.h
#endif

struct spwd *spwd;

static struct passwd *fix_getpwnam(u)
char   *u;
{
    struct passwd *pwd = 0;

    if ((spwd = getspnam(u)) && (pwd = getpwnam(u)))
	pwd->pw_passwd = spwd->sp_pwdp;
    return pwd;
}

#define getpwnam fix_getpwnam

// extern sysv_expire(struct spwd *);
