#
# Copyright (c) 1988 Regents of the University of California.
# All rights reserved.
#
# Redistribution and use in source and binary forms are permitted
# provided that the above copyright notice and this paragraph are
# duplicated in all such forms and that any documentation, advertising
# materials, and other materials related to such redistribution and
# use acknowledge that the software was developed by the University
# of California, Berkeley.  The name of the University may not be
# used to endorse or promote products derived from this software
# without specific prior written permission.  THIS SOFTWARE IS PROVIDED
# ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND
# FITNESS FOR A PARTICULAR PURPOSE.
#
# @(#)Makefile	5.2 (Berkeley) 9/20/88
#

CFLAGS	= -O
SYSVOBJ	= stream_pty.o utmpx_init.o utmpx_login.o utmpx_logout.o
BSD4OBJ	= login.o logout.o logwtmp.o
RANLIB	= ranlib
EXTRA	=

what:
	@echo This Makefile is not to be invoked directly 1>&2; exit 1

43bsd ultrix4 sunos4:
	make OBJS="$(BSD4OBJ) $(EXTRA)" CFLAGS="$(CFLAGS)" \
	    RANLIB=$(RANLIB) libutil.a

sysv4 sunos5:
	make OBJS="$(SYSVOBJ) $(EXTRA)" CFLAGS="$(CFLAGS) -DUSE_TERMIOS_H" \
	    RANLIB=echo libutil.a

libutil.a: ${OBJS}
	ar rv $@ $?
	$(RANLIB) $@

clean:
	rm -f *.o libutil.a

stream_pty: tiocpkt.h
