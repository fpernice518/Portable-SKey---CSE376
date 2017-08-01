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
# @(#)Makefile	5.1 (Berkeley) 10/18/88
#

CFLAGS=	-O -DNONICE -DLOGIN_ACCESS -DUSE_FBTAB -DDETECT_HANGUP -DOLD_RLOGIN -DLOGGING -DSKEY_ONLY
LIBS=	../lib/libutil.a libskey.a
SRCS=	login.c
OBJS=	login.o login_access.o login_fbtab.o
SYSLIBS=

what:
	@echo make sunos5 or sunos4 or ultrix4 1>&2; exit 1

all: lib login try

ultrix4:
	make all SYS=$@ CFLAGS="$(CFLAGS)"

sunos4:
	make all SYS=$@ CFLAGS="$(CFLAGS) -DNO_SETENV -DUSE_TERMIO_H"

sunos5:
	make all SYS=$@ CFLAGS="$(CFLAGS) -DNO_SETENV -DUSE_TERMIO_H \
	    -DUSE_STRING_H -DSHADOW_PASSWD -D__svr4__" \
	    OBJS="$(OBJS) sysv_shadow.o sysv_environ.o sysv_default.o" \
	    RANLIB=echo SYSLIBS="-lsocket -lnsl"

lib:
	cd ../lib; make CFLAGS="$(CFLAGS)" $(SYS)

login: ${LIBS} ${OBJS}
	${CC} -o $@ ${CFLAGS} ${OBJS} ${LIBS} ${SYSLIBS}

try:	try.c login_access.o
	${CC} -o $@ ${CFLAGS} try.c login_access.o

clean:
	rm -f *.o core login try
	cd ../lib; make $@

$(OBJS): Makefile
login.o sysv_default.o sysv_environ.o: sysv_default.h
login.o sysv_shadow.o: sysv_shadow.h
