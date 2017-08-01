/*
 * S/KEY v1.1b (skey.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *          Scott Chasin <chasin@crimelab.com>
 *
 *
 * Stand-alone program for computing responses to S/Key challenges.
 * Takes the iteration count and seed as command line args, prompts
 * for the user's key, and produces both word and hex format responses.
 *
 * Usage example:
 *	>skey 88 ka9q2
 *	Enter password:
 *	OMEN US HORN OMIT BACK AHOY
 *	>
 */
#include "config.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#else
#  error Must have stdio.h
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#elif defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#else
#  error Must have stdlib.h or sys/types.h
#endif /* HAVE_STDLIB_H || HAVE_SYS_TYPES_H*/

#ifdef HAVE_STRING_H
#  include <string.h>
#else
#  error Must have string.h
#endif /* HAVE_STRING_H */

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#else
#  error Must have fcntl.h
#endif /* HAVE_FCNTL_H */

#ifdef HAVE_ERRNO_H
#  include <errno.h>
#else
#  error Must have errno.h
#endif

// #include <sgtty.h>

#include "md4.h"
#include "skey.h"

char *readpass ();
void usage ();
int getopt ();
void printHelpMenu(void);
void terminate();

extern int optind;
extern char *optarg;
char *lastOptArg;

// FILE* logger;
// unsigned debugLvl;

int main(int argc, char *argv[])
{
  int n, cnt, i, pass = 0, debugCtr;
  char passwd[256], key[8], buf[33], *seed, *slash;

  char lvlThree[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlOne[MAX_DEBUG_BUFF] = "";

  /* My variables for option parsing */
  unsigned hCount = 0, vCount = 0, lCount = 0;
  // dCount is declared as debugLevel in skey.h

  cnt = 1;
  logger = stderr;
  debugLvl = 0;

  atexit(terminate);

  while ((i = getopt (argc, argv, "l:n:p:hvd")) != EOF)
  {
    switch (i)
    {
  
    case 'd':
      ++debugLvl;
      break;

    case 'h':
      ++hCount;
      break;

    case 'l':
      ++lCount;
      lastOptArg = optarg;
      break;

    case 'p':
      strcpy (passwd, optarg);
      pass = 1;
      break;

   case 'n':
      cnt = atoi (optarg);
      break;

    case 'v':
      ++vCount;
      break;

    }
  }


  if(lCount > 0)
  {
    FILE* log;
    log = fopen(lastOptArg, "w");

    if(log == NULL)
    {
      fprintf(stderr, "Cannot append to file %s: %s", lastOptArg, strerror(errno));
      exit(-1);
    }

    logger = log;
  }


  //debug stuff
  char* cur = lvlThree; 
  char* const end = lvlThree + sizeof lvlThree;

  cur += snprintf(cur, (end-cur), "Passing args [");
  for(debugCtr = 0; debugCtr < argc; ++debugCtr)
  {
    if(cur < end)
      cur += snprintf(cur, (end-cur), " %s ", argv[debugCtr]);
    else
      break;
  }
  snprintf(cur, (end-cur), "] into main()\n");

  snprintf(lvlOne, MAX_DEBUG_BUFF,"Entering main() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, lvlTwo, lvlThree);
  //end debug stuff

  if(hCount > 0)
  {
    printHelpMenu();
    exit(0);
  }

  if(lCount > 0)
  {

  }

  if(vCount > 0)
  {
    printf("Version Number = %0.2lf\n", VERSION_NUMBER);
  }

  /* could be in the form <number>/<seed> */

  if (argc <= optind + 1)
  {
    /* look for / in it */
    if (argc <= optind)
    {
      usage (argv[0]);
      exit (1); 
    }

    slash = strchr (argv[optind], '/');
    if (slash == NULL)
    {
      usage (argv[0]);
      exit (1);
    }
    *slash++ = '\0';
    seed = slash;

    if ((n = atoi (argv[optind])) < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
  }
  else
  {

    if ((n = atoi (argv[optind])) < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
    seed = argv[++optind];
  }

  /* Get user's secret password */
  if (!pass)
  {
    printf ("Enter secret password: ");
    readpass (passwd, sizeof (passwd));
  }

  rip (passwd);

  /* Crunch seed and password into starting key */
  if (keycrunch (key, seed, passwd) != 0)
  {
    fprintf (stderr, "%s: key crunch failed\n", argv[0]);
    exit (1);
  }
  if (cnt == 1)
  {
    while (n-- != 0)
      f (key);
    printf ("%s\n", btoe (buf, key));
#ifdef	HEXIN
    printf ("%s\n", put8 (buf, key));
#endif
   }
  else
  {
    for (i = 0; i <= n - cnt; i++)
      f (key);
    for (; i <= n; i++)
    {
#ifdef	HEXIN
      printf ("%d: %-29s  %s\n", i, btoe (buf, key), put8 (buf, key));
#else
      printf ("%d: %-29s\n", i, btoe (buf, key));
#endif
      f (key);
    }
  }
  exit (0);
}

void usage(char *s)
{
  printf ("Usage: %s [-n count] [-p password ] <sequence #>[/] <key> \n", s);
}

void printHelpMenu(void)
{
  printf("This is not a very helpful help menu");
}

void terminate()
{
  char lvlOne[MAX_DEBUG_BUFF] = "";

  snprintf(lvlOne, MAX_DEBUG_BUFF, "Leaving main() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne,"","");

  fclose(logger);
}
