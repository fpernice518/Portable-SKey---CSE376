/* S/KEY v1.1b (skeysh.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *          Scott Chasin <chasin@crimelab.com>
 *
 * S/Key authentication shell
 */
#include "config.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#else
#  error Must have stdio.h
#endif

#ifdef HAVE_STRING_H
#  include <string.h>
#else
#  error Must have string.h
#endif

#ifdef HAVE_PWD_H
#  include <pwd.h>
#else
#  error Must have pwd.h
#endif

#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#elif defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#else
#  error Must have stdlib.h or sys/types.h
#endif /* HAVE_STDLIB_H || HAVE_SYS_TYPES_H */

#ifdef HAVE_GRP_H
#  include <grp.h>
#else
#  error Must have grp.h
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#else
#  error Must have unistd.h
#endif

#include "skey.h"

char userbuf[16] = "USER=";
char homebuf[128] = "HOME=";
char shellbuf[128] = "SHELL=";
char pathbuf[128] = "PATH=:/usr/ucb:/bin:/usr/bin";
char *cleanenv[] = { userbuf, homebuf, shellbuf, pathbuf, 0, 0 };
char *shell = "/bin/csh";

char *getenvf(char *ename);
void setenvf(char *ename, char *eval, char *buf);


extern char **environ;
struct passwd *pwd;

int main(int argc, char *argv[])
{
  int stat;
  char user [8];
 
  if ((pwd = getpwuid(getuid())) == NULL) {
      fprintf(stderr, "Who are you?\n");
      exit(1);
  }

  strcpy(user, pwd->pw_name);

  if ((pwd = getpwnam(user)) == NULL) {
      fprintf(stderr, "Unknown login: %s\n", user);
      exit(1);
  }
 
  stat = skey_haskey (user);
 
  if (stat == 1) {
     fprintf(stderr,"keysh: no entry for user %s.\n", user);
     exit (-1);
  }

  if (stat == -1) {
     fprintf(stderr, "keysh: could not open key file.\n");
     exit (-1);
  }
 
  if (skey_authenticate (user) == -1) {
      printf ("Invalid response.\n");
      exit (-1);
  } 

  if (setgid(pwd->pw_gid) < 0) {
      perror("keysh: setgid");
      exit(3);
  }

  if (initgroups(user, pwd->pw_gid)) {
      fprintf(stderr, "keysh: initgroups failed\n");
      exit(4);
  }

  if (setuid(pwd->pw_uid) < 0) {
      perror("keysh: setuid");
      exit(5);
  }

  cleanenv[4] = getenvf("TERM");
  environ = cleanenv;

  setenvf("USER", pwd->pw_name, userbuf);
  setenvf("SHELL", shell, shellbuf);
  setenvf("HOME", pwd->pw_dir, homebuf);

  if (chdir(pwd->pw_dir) < 0) {
      fprintf(stderr, "No directory\n");
      exit(6);
  }

  execv (shell, argv);
  fprintf(stderr, "No shell\n");
  exit(7);
}
 
void setenvf(char *ename, char *eval, char *buf)
{
  register char *cp, *dp;
  register char **ep = environ;
 
  /*
   * this assumes an environment variable "ename" already exists
   */
   while (1) 
   {
       dp = *ep++;
       for (cp = ename; *cp == *dp && *cp; cp++, dp++)
            continue;
       if (*cp == 0 && (*dp == '=' || *dp == 0)) {
            strcat(buf, eval);
            *--ep = buf;
            return;
       }
   }
}

char *getenvf(char *ename)
{
  register char *cp, *dp;
  register char **ep = environ;
 
  while (1) 
  {
     dp = *ep++;
     for (cp = ename; *cp == *dp && *cp; cp++, dp++)
          continue;
     if (*cp == 0 && (*dp == '=' || *dp == 0))
          return (*--ep);
  }
  return ((char *)0);
}
