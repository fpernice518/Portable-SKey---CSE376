BIN=/usr/local/bin
CFLAGS = -DSKEY -DSOLARIS
LIB = ../../src/libskey.a

all: su

su: su.c
	$(CC) -o $@ $(CFLAGS) su.c $(LIB)

install: 
	$(INSTALL) -c -s -m 4555 -o root su $(BIN)

clean:
	-rm su *.o *~ core
