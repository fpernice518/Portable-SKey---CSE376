/* S/KEY v1.1b (skeysubr.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications: 
 *          Scott Chasin <chasin@crimelab.com>
 *
 * S/KEY misc routines.
 */
#include "config.h"


#ifdef HAVE_STDIO_H
#  include <stdio.h>
#else
#  error Must have stdio.h
#endif

#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#else
#  error Must have stdlib.h
#endif

#ifdef HAVE_STRING_H
#  include <string.h>
#else
#  error Must have string.h
#endif

#ifdef HAVE_SIGNAL_H
#  include <signal.h>
#else
#  error Must have signal.h
#endif

#ifdef HAVE_TERMIOS_H
#  include <termios.h>
#else
#  error Must have termios.h
#endif



#ifdef stty
# undef stty
#endif
 
#ifdef gtty
# undef gtty
#endif

# define TTYSTRUCT termios
# define stty(fd,buf) ioctl((fd),TCSETA,(buf))
# define gtty(fd,buf) ioctl((fd),TCGETA,(buf))


struct termios newtty;
struct termios oldtty;


void trapped(int stats);

#include "md4.h"
#include "skey.h"

void sevenbit(char *s);

/* Crunch a key:
 * concatenate the seed and the password, run through MD4 and
 * collapse to 64 bits. This is defined as the user's starting key.
 */
int keycrunch(char *result, char *seed, char *passwd)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing charater pointers %p %p %p (val1 = %s, val2 = %s, val3 = %s) into keycrunch()\n",
           result, seed, passwd, result, seed, passwd);
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function keycrunch() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);


	char *buf;
	MDstruct md;
	unsigned int buflen;
#ifndef	MY_LITTLE_ENDIAN
	int i;
	register long tmp;
#endif
	
	buflen = strlen(seed) + strlen(passwd);
	if ((buf = (char *)malloc(buflen+1)) == NULL)
  {
    snprintf(lvlTwo, MAX_DEBUG_BUFF, "returning %d from function keycrunch()\n", -1);
    debuginfo("", lvlTwo, "");
		return -1;
  }
	strcpy(buf,seed);
	strcat(buf,passwd);

	/* Crunch the key through MD4 */
	sevenbit(buf);
	MDbegin(&md);
	MDupdate(&md,(unsigned char *)buf,8*buflen);

	free(buf);

	/* Fold result from 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifdef	MY_LITTLE_ENDIAN
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(result,(char *)md.buffer,8);
#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */
	for (i=0; i<2; i++) {
		tmp = md.buffer[i];
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
	}
#endif

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "returning %d from function keycrunch()\n", 0);
  debuginfo("", lvlTwo, "");
	return 0;
}

/* The one-way function f(). Takes 8 bytes and returns 8 bytes in place */
void f(char *x)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing charater pointer %p ( value = %s )into f()\n", x, x);
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function f() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);



	MDstruct md;
#ifndef	MY_LITTLE_ENDIAN
	register long tmp;
#endif

	MDbegin(&md);
	MDupdate(&md,(unsigned char *)x,64);

	/* Fold 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifdef	MY_LITTLE_ENDIAN
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(x,(char *)md.buffer,8);

#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */
	tmp = md.buffer[0];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;

	tmp = md.buffer[1];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x = tmp;
#endif

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function f()\n");
  debuginfo("", lvlTwo, "");
}

/* Strip trailing cr/lf from a line of text */
void rip(char *buf)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing charater pointer %p ( value = %s ) into rip()\n", buf, buf);
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function rip() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);

	char *cp;

	if((cp = strchr(buf,'\r')) != NULL)
		*cp = '\0';

	if((cp = strchr(buf,'\n')) != NULL)
		*cp = '\0';

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function rip()\n");
  debuginfo("", lvlTwo, "");
}

char *readpass (char *buf, int n)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing charater pointer %p ( value = %s ) and integer %d readpass()\n", buf, buf, n);
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function readpass() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);


#ifndef USE_ECHO
    set_term ();
    echo_off ();
#endif

    fgets (buf, n, stdin);

    rip (buf);

    printf ("\n\n");
    sevenbit (buf);

#ifndef USE_ECHO
    unset_term ();
#endif


    snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning character pointer %p ( value = %s )from function readpass()\n", buf, buf);
    debuginfo("", lvlTwo, "");

    return buf;
}

void set_term(void)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing void into function set_term()\n");
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function set_term() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);

  tcgetattr(fileno(stdin), &newtty);
  tcgetattr(fileno(stdin), &oldtty);
    // gtty (fileno(stdin), &newtty);
    // gtty (fileno(stdin), &oldtty);
 
  signal (SIGINT, trapped);

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function set_term()\n");
  debuginfo("", lvlTwo, "");
}

void echo_off(void)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing void into function echo_off()\n");
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function echo_off() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);

  newtty.c_lflag &= ~(ICANON | ECHO | ECHONL);

  newtty.c_cc[VMIN] = 1;
  newtty.c_cc[VTIME] = 0;
  newtty.c_cc[VINTR] = 3;

  tcsetattr(fileno (stdin), TCSANOW, &newtty);

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function echo_off()\n");
  debuginfo("", lvlTwo, "");
}

void unset_term(void)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing void into function unset_term()\n");
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function unset_term() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);

  tcsetattr(fileno (stdin), TCSANOW, &oldtty);

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function unset_term()\n");
  debuginfo("", lvlTwo, "");
}

void trapped(int stats)
 {
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing integer %d into function trapped()\n", stats);
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function trapped() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);

  signal (SIGINT, trapped);
  printf ("^C\n");
  unset_term ();

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function trapped(), exiting with status %d\n", stats);
  debuginfo("", lvlTwo, "");

  exit(stats);
 }

/* removebackspaced over charaters from the string */
void backspace(char *buf)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing character pointer %p ( value = %s ) into function backspace()\n", buf, buf);
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function backspace() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);

	char bs = 0x8;
	char *cp = buf;
	char *out = buf;

	while(*cp){
		if( *cp == bs ) {
			if(out == buf){
				cp++;
				continue;
			}
			else {
			  cp++;
			  out--;
			}
		}
		else {
			*out++ = *cp++;
		}

	}
	*out = '\0';

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function backspace()\n");
  debuginfo("", lvlTwo, "");	
}

/* sevenbit ()
 *
 * Make sure line is all seven bits.
 */
 
void sevenbit(char *s)
{
  char lvlOne[MAX_DEBUG_BUFF] = "";
  char lvlTwo[MAX_DEBUG_BUFF] = "";
  char lvlThree[MAX_DEBUG_BUFF] = "";

  snprintf(lvlThree, MAX_DEBUG_BUFF, "Passing character pointer %p ( value = %s ) into function sevenbit()\n", s, s);
  snprintf(lvlOne, MAX_DEBUG_BUFF, "Entering function sevenbit() in %s at line %d\n", __FILE__, __LINE__);
  debuginfo(lvlOne, "", lvlThree);

   while (*s) {
     *s = 0x7f & ( *s);
     s++;
   }

  snprintf(lvlTwo, MAX_DEBUG_BUFF, "Returning void from function sevenbit()\n");
  debuginfo("", lvlTwo, "");  
}
