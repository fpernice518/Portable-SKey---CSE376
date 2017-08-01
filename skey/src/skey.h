/*
 * S/KEY v1.1b (skey.h)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications:
 *          Scott Chasin <chasin@crimelab.com>
 *
 * Main client header
 */

/* Server-side data structure for reading keys file during login */


#ifndef SKEY_H 
#define SKEY_H

#include "config.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#else
#  error Must have stdio.h
#endif

#define MAX_DEBUG_BUFF 500

struct skey
{
  FILE *keyfile;
  char buf[256];
  char *logname;  
  int n;
  char *seed;
  char *val;
  long recstart;		/* needed so reread of buffer is efficient */
};

/* Client-side structure for scanning data stream for challenge */
struct mc
{
  char buf[256];
  int skip;
  int cnt;
};

FILE* logger;
unsigned debugLvl;

extern void f(char *x);
extern int keycrunch(char *result, char *seed, char *passwd);
extern char *btoe(char *engout, char *c);
extern char *put8(char *out, char *s);
extern int etob(char *out, char *e);
extern void rip(char *buf);
extern int skeychallenge(struct skey * mp, char *name, char *ss);
extern int skeylookup(struct skey * mp, char *name);
extern int skeyverify(struct skey * mp, char *response);

/* my added prototypes */
extern void sevenbit(char *s);
extern int atob8(register char *out, register char *in);
extern int btoa8(register char *out, register char *in);
extern int skey_haskey(char *username);
extern int skey_authenticate(char *username);
extern void backspace(char *buf);
extern char *readpass(char *buf, int n);
extern int htoi(int c);
extern void debuginfo(char* lvlOne, char* lvlTwo, char* lvlThree);


#endif /* SKEY_H */

